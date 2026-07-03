package service

// srtp_tunnel.go — سرویس تونل RTP/SRTP over TCP (Anti-DPI Mechanism #1)
//
// این سرویس یک تونل هوشمند و مطمئن بر پایه پروتکل RTP روی TCP (بر اساس استاندارد RFC 4571)
// راه‌اندازی می‌کند تا ترافیک معمولی را به شکل بسته‌های صوتی/تصویری VoIP شبیه‌سازی کند.
//
// ویژگی‌ها:
//   ۱. استفاده از ساختار استاندارد RTP Header (۱۲ بایت)
//   ۲. رمزگذاری جریان داده با الگوی فوق سریع RC4 (بدون وابستگی به پکیج‌های خارجی)
//   ۳. پشتیبانی کامل از انتقال بدون اتلاف (Reliable) به دلیل اجرا روی TCP
//   ۴. فرستادن بسته‌های فیک Keep-Alive صوتی در صورت عدم وجود ترافیک فعال

import (
	"bufio"
	"crypto/hmac"
	"crypto/rc4"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

const (
	rtpHeaderSize  = 12
	maxPayloadSize = 1400
)

// SrtpTunnelService سرویس مدیریت تونل RTP سرور
type SrtpTunnelService struct {
	mu        sync.RWMutex
	isRunning bool
	listener  net.Listener
	stopChan  chan struct{}

	// تنظیمات
	listenPort int    // پورت بیرونی که سرور روی آن منتظر کلاینت است (مثلاً 3478)
	targetPort int    // پورت محلی xray-core (مثلاً پورت VLESS/VMess)
	pskKey     string // کلید پیش‌فرض برای رمزگذاری RC4
}

// NewSrtpTunnelService یک نمونه جدید از سرویس تونل می‌سازد
func NewSrtpTunnelService() *SrtpTunnelService {
	return &SrtpTunnelService{
		stopChan: make(chan struct{}),
	}
}

// Configure اعمال تنظیمات تونل
func (s *SrtpTunnelService) Configure(listenPort, targetPort int, pskKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listenPort = listenPort
	s.targetPort = targetPort
	s.pskKey = pskKey
}

// Start راه‌اندازی سرور تونل
func (s *SrtpTunnelService) Start() error {
	s.mu.Lock()
	if s.isRunning {
		s.mu.Unlock()
		return fmt.Errorf("SRTP Tunnel is already running")
	}
	s.mu.Unlock()

	addr := fmt.Sprintf("0.0.0.0:%d", s.listenPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("SRTP Tunnel: failed to listen on %s: %w", addr, err)
	}

	s.mu.Lock()
	s.listener = listener
	s.isRunning = true
	s.stopChan = make(chan struct{})
	s.mu.Unlock()

	go s.acceptLoop()

	log.Printf("[SRTP Tunnel] Service started on TCP port %d -> forwarding to xray on port %d\n", s.listenPort, s.targetPort)
	return nil
}

// Stop متوقف کردن سرویس تونل
func (s *SrtpTunnelService) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isRunning {
		return
	}

	close(s.stopChan)
	if s.listener != nil {
		s.listener.Close()
	}
	s.isRunning = false
	log.Println("[SRTP Tunnel] Service stopped")
}

func (s *SrtpTunnelService) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.stopChan:
				return
			default:
				log.Println("[SRTP Tunnel] Accept error:", err)
				continue
			}
		}

		go s.handleConnection(conn)
	}
}

func (s *SrtpTunnelService) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	clientReader := bufio.NewReaderSize(clientConn, 32768)

	// اتصال به پورت محلی xray-core
	targetAddr := fmt.Sprintf("127.0.0.1:%d", s.targetPort)
	xrayConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("[SRTP Tunnel] Failed to connect to local xray at %s: %v\n", targetAddr, err)
		return
	}
	defer xrayConn.Close()

	// ایجاد کلید رمزنگاری RC4 پس از دریافت نخستین پکت
	s.mu.RLock()
	key := []byte(s.pskKey)
	s.mu.RUnlock()

	// استفاده از کلید پیش‌فرض در صورت خالی بودن
	if len(key) == 0 {
		key = []byte("antigravity-default-srtp-key")
	}

	var clientCipherReader *rc4.Cipher
	var clientCipherWriter *rc4.Cipher
	ciphersReady := make(chan struct{})
	var ssrc uint32
	var ciphersInitialized bool
	var ciphersMu sync.Mutex

	var wg sync.WaitGroup
	wg.Add(2)

	// کلاینت به سرور: خواندن فریم‌های RTP، رمزگشایی و تحویل به xray-core
	go func() {
		defer wg.Done()
		defer xrayConn.Close()

		lenBuf := make([]byte, 2)
		headerBuf := make([]byte, rtpHeaderSize)

		for {
			// ۱. خواندن طول فریم (۲ بایت)
			_, err := io.ReadFull(clientReader, lenBuf)
			if err != nil {
				return
			}
			frameLen := binary.BigEndian.Uint16(lenBuf)

			if frameLen < rtpHeaderSize {
				return // فریم نامعتبر
			}

			// ۲. خواندن هدر RTP
			_, err = io.ReadFull(clientReader, headerBuf)
			if err != nil {
				return
			}

			payloadType := headerBuf[1]

			// استخراج SSRC برای شروع رمزنگاری اختصاصی این اتصال
			if !ciphersInitialized {
				ciphersMu.Lock()
				ssrc = binary.BigEndian.Uint32(headerBuf[8:12])
				cKey, sKey := deriveRC4Keys(key, ssrc)
				clientCipherReader, err = rc4.NewCipher(cKey)
				if err != nil {
					log.Println("[SRTP Tunnel] Cipher creation error:", err)
					ciphersMu.Unlock()
					return
				}
				clientCipherWriter, err = rc4.NewCipher(sKey)
				if err != nil {
					log.Println("[SRTP Tunnel] Cipher creation error:", err)
					ciphersMu.Unlock()
					return
				}
				ciphersInitialized = true
				close(ciphersReady)
				ciphersMu.Unlock()
			}

			// ۳. خواندن پی‌لود رمزگذاری‌شده
			payloadLen := frameLen - rtpHeaderSize
			payload := make([]byte, payloadLen)
			_, err = io.ReadFull(clientReader, payload)
			if err != nil {
				return
			}

			// اگر بسته Comfort Noise (Keep-Alive) باشد، آن را نادیده می‌گیریم
			if payloadType == 13 {
				continue
			}

			// ۴. رمزگشایی پی‌لود با RC4
			decrypted := make([]byte, payloadLen)
			clientCipherReader.XORKeyStream(decrypted, payload)

			// ۵. نوشتن به xray-core
			_, err = xrayConn.Write(decrypted)
			if err != nil {
				return
			}
		}
	}()

	// سرور به کلاینت: خواندن از xray-core، رمزگذاری و قالب‌بندی به شکل RTP
	go func() {
		defer wg.Done()
		defer clientConn.Close()

		// منتظر بمان تا کلیدها از اولین بسته کلاینت استخراج شوند
		select {
		case <-ciphersReady:
		case <-time.After(10 * time.Second):
			return // زمان انتظار به سر رسید
		}

		rawBuf := make([]byte, maxPayloadSize)
		var seqNum uint16 = 0
		var timestamp uint32 = 0

		idleDuration := 5 * time.Second
		lastActive := time.Now()

		for {
			xrayConn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, err := xrayConn.Read(rawBuf)

			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// بررسی زمان آخرین فعالیت برای ارسال Keep-Alive
					if time.Since(lastActive) >= idleDuration {
						// ساخت بسته Comfort Noise (Payload Type = 13)
						header := make([]byte, rtpHeaderSize)
						header[0] = 0x80
						header[1] = 13 // Payload Type: CN
						binary.BigEndian.PutUint16(header[2:4], seqNum)
						binary.BigEndian.PutUint32(header[4:8], timestamp)
						binary.BigEndian.PutUint32(header[8:12], ssrc)

						seqNum++

						fakePayload := []byte{0x00, 0x00, 0x00, 0x00}
						frameLen := uint16(rtpHeaderSize + len(fakePayload))
						frameLenBuf := make([]byte, 2)
						binary.BigEndian.PutUint16(frameLenBuf, frameLen)

						// ادغام فریم طول، هدر و داده فیک جهت بهینه‌سازی سرعت
						frameBytes := make([]byte, 2+rtpHeaderSize+len(fakePayload))
						copy(frameBytes[0:2], frameLenBuf)
						copy(frameBytes[2:14], header)
						copy(frameBytes[14:], fakePayload)

						clientConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
						if _, err := clientConn.Write(frameBytes); err != nil {
							return
						}
						lastActive = time.Now()
					}
					continue
				}
				return
			}

			payload := rawBuf[:n]
			lastActive = time.Now()

			// ۱. رمزگذاری پی‌لود
			encrypted := make([]byte, n)
			clientCipherWriter.XORKeyStream(encrypted, payload)

			// ۲. ساخت هدر RTP (۱۲ بایت)
			header := make([]byte, rtpHeaderSize)
			header[0] = 0x80 // Version 2
			header[1] = 96   // Payload Type: 96 (Dynamic Video)
			binary.BigEndian.PutUint16(header[2:4], seqNum)
			binary.BigEndian.PutUint32(header[4:8], timestamp)
			binary.BigEndian.PutUint32(header[8:12], ssrc)

			seqNum++
			timestamp += uint32(n)

			// ۳. ارسال فریم: [طول کل فریم (۲ بایت) | هدر (۱۲ بایت) | پی‌لود رمزگذاری‌شده (N بایت)]
			frameLen := uint16(rtpHeaderSize + n)
			frameLenBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(frameLenBuf, frameLen)

			// ادغام فریم طول، هدر و داده جهت بهینه‌سازی سرعت (Write Coalescing)
			frameBytes := make([]byte, 2+rtpHeaderSize+n)
			copy(frameBytes[0:2], frameLenBuf)
			copy(frameBytes[2:14], header)
			copy(frameBytes[14:], encrypted)

			clientConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, err = clientConn.Write(frameBytes)
			if err != nil {
				return
			}
		}
	}()

	wg.Wait()
}

func deriveRC4Keys(psk []byte, ssrc uint32) (clientKey, serverKey []byte) {
	ssrcBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(ssrcBytes, ssrc)

	// Client Key
	h1 := hmac.New(sha256.New, psk)
	h1.Write(ssrcBytes)
	h1.Write([]byte("client"))
	clientKey = h1.Sum(nil)

	// Server Key
	h2 := hmac.New(sha256.New, psk)
	h2.Write(ssrcBytes)
	h2.Write([]byte("server"))
	serverKey = h2.Sum(nil)

	return
}
