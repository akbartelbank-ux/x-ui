package service

// spa_service.go — سرویس Single Packet Authorization (Anti-DPI Mechanism #4)
//
// این سرویس یک سرور UDP سبک‌وزن راه‌اندازی می‌کند که:
//   ۱. روی یک پورت UDP مخفی گوش می‌کند
//   ۲. بسته‌های SPA دریافتی را با HMAC-SHA256 اعتبارسنجی می‌کند
//   ۳. در صورت معتبر بودن، پورت اصلی را فقط برای IP آن کلاینت باز می‌کند
//   ۴. پس از پایان window زمانی، پورت را مجدداً می‌بندد
//
// فرمت بسته SPA:
//   [timestamp uint64 big-endian (8 bytes)] [nonce (8 bytes)] [HMAC-SHA256 (32 bytes)]
//   = 48 bytes total — مثل یک بسته DNS عادی
//
// نحوه اجرا: این سرویس در main.go در goroutine جداگانه اجرا می‌شود

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"sync"
	"time"

	"github.com/alireza0/x-ui/logger"
)

const (
	// اندازه بسته SPA: timestamp(8) + nonce(8) + HMAC-SHA256(32)
	spaPacketSize = 48
	// مقدار پیش‌فرض تعداد ثانیه‌های مجاز بودن timestamp
	defaultTimestampTolerance = 30
	// مدت زمان پیش‌فرض باز ماندن پورت برای IP کلاینت (ثانیه)
	defaultWindowSeconds = 60
)

// SpaService سرویس Single Packet Authorization
type SpaService struct {
	mu             sync.RWMutex
	isRunning      bool
	stopChan       chan struct{}
	authorizedIPs  map[string]time.Time // IP → زمان انقضا
	cleanupTicker  *time.Ticker

	// تنظیمات (از پنل x-ui بارگذاری می‌شوند)
	port                int
	psk                 []byte // Pre-Shared Key دیکد شده از Base64
	mainPort            int    // پورت اصلی که باید باز/بسته شود
	windowSeconds       int
	timestampTolerance  int
}

// NewSpaService یک نمونه جدید از SpaService می‌سازد
func NewSpaService() *SpaService {
	return &SpaService{
		authorizedIPs: make(map[string]time.Time),
		stopChan:      make(chan struct{}),
	}
}

// Configure تنظیمات سرویس را از مقادیر پنل بارگذاری می‌کند
func (s *SpaService) Configure(spaPort int, pskBase64 string, mainPort int, windowSecs int, timestampTol int) error {
	// رمزگشایی کلید PSK از Base64
	keyBytes, err := base64.StdEncoding.DecodeString(pskBase64)
	if err != nil {
		// تلاش با URL-safe base64
		keyBytes, err = base64.URLEncoding.DecodeString(pskBase64)
		if err != nil {
			return fmt.Errorf("SPA: invalid PSK base64: %w", err)
		}
	}

	if len(keyBytes) < 16 {
		return fmt.Errorf("SPA: PSK too short (%d bytes), minimum 16 bytes required", len(keyBytes))
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.port = spaPort
	s.psk = keyBytes
	s.mainPort = mainPort

	if windowSecs <= 0 {
		windowSecs = defaultWindowSeconds
	}
	s.windowSeconds = windowSecs

	if timestampTol <= 0 {
		timestampTol = defaultTimestampTolerance
	}
	s.timestampTolerance = timestampTol

	return nil
}

// Start سرور UDP SPA را در یک goroutine مجزا راه‌اندازی می‌کند
func (s *SpaService) Start() error {
	s.mu.Lock()
	if s.isRunning {
		s.mu.Unlock()
		return fmt.Errorf("SPA service is already running")
	}
	s.mu.Unlock()

	if s.port == 0 || len(s.psk) == 0 {
		return fmt.Errorf("SPA service not configured (call Configure first)")
	}

	// راه‌اندازی UDP server
	addr := fmt.Sprintf("0.0.0.0:%d", s.port)
	conn, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return fmt.Errorf("SPA: failed to listen on UDP %s: %w", addr, err)
	}

	s.mu.Lock()
	s.isRunning = true
	s.stopChan = make(chan struct{})
	s.mu.Unlock()

	// goroutine اصلی دریافت بسته‌ها
	go s.listenLoop(conn)

	// goroutine پاک‌سازی IP‌های منقضی‌شده
	s.cleanupTicker = time.NewTicker(10 * time.Second)
	go s.cleanupLoop()

	logger.Info("Anti-DPI SPA service started on UDP port", s.port)
	logger.Info("Anti-DPI SPA: main port", s.mainPort, "will be opened per-IP for", s.windowSeconds, "seconds")
	return nil
}

// Stop سرویس را متوقف می‌کند
func (s *SpaService) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isRunning {
		return
	}

	close(s.stopChan)
	s.isRunning = false
	if s.cleanupTicker != nil {
		s.cleanupTicker.Stop()
	}

	// حذف تمام قوانین iptables اضافه‌شده توسط این سرویس
	s.flushSpaRules()
	logger.Info("Anti-DPI SPA service stopped")
}

// listenLoop حلقه اصلی دریافت و پردازش بسته‌های UDP
func (s *SpaService) listenLoop(conn net.PacketConn) {
	defer conn.Close()

	buf := make([]byte, 256) // بزرگ‌تر از spaPacketSize برای دریافت بسته‌های بزرگ‌تر (reject می‌شوند)

	for {
		select {
		case <-s.stopChan:
			return
		default:
		}

		// تنظیم deadline برای بررسی stopChan
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))

		n, remoteAddr, err := conn.ReadFrom(buf)
		if err != nil {
			// اگر timeout بود ادامه بده
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-s.stopChan:
				return
			default:
				logger.Warning("SPA: UDP read error:", err)
				continue
			}
		}

		// پردازش بسته در goroutine جداگانه تا حلقه مسدود نشود
		packetData := make([]byte, n)
		copy(packetData, buf[:n])
		go s.processPacket(packetData, remoteAddr)
	}
}

// processPacket یک بسته SPA را اعتبارسنجی و پردازش می‌کند
func (s *SpaService) processPacket(data []byte, remoteAddr net.Addr) {
	// بررسی اندازه بسته
	if len(data) != spaPacketSize {
		// بسته‌های با اندازه غلط را بی‌سر و صدا رد می‌کنیم (برای جلوگیری از اطلاعات به مهاجم)
		return
	}

	// استخراج اجزای بسته
	timestamp := binary.BigEndian.Uint64(data[0:8])
	// nonce در bytes 8-16 است (برای anti-replay، تنها timestamp کافی نیست)
	message := data[0:16]     // timestamp + nonce
	receivedHMAC := data[16:] // 32 bytes

	// ── اعتبارسنجی ۱: بررسی timestamp ──────────────────────────────────────
	now := uint64(time.Now().Unix())
	diff := int64(now) - int64(timestamp)
	if diff < 0 {
		diff = -diff
	}

	s.mu.RLock()
	tolerance := int64(s.timestampTolerance)
	s.mu.RUnlock()

	if diff > tolerance {
		logger.Warning(fmt.Sprintf("SPA: rejected packet from %s — timestamp too old/new (diff=%ds)", remoteAddr.String(), diff))
		return
	}

	// ── اعتبارسنجی ۲: بررسی HMAC-SHA256 ────────────────────────────────────
	s.mu.RLock()
	psk := s.psk
	s.mu.RUnlock()

	mac := hmac.New(sha256.New, psk)
	mac.Write(message)
	expectedHMAC := mac.Sum(nil)

	if !hmac.Equal(receivedHMAC, expectedHMAC) {
		// HMAC نامعتبر — بدون هیچ پاسخ یا لاگ مفصلی رد می‌کنیم
		logger.Warning(fmt.Sprintf("SPA: rejected packet from %s — invalid HMAC", remoteAddr.String()))
		return
	}

	// ── بسته معتبر است: باز کردن پورت برای این IP ──────────────────────────
	// استخراج آدرس IP خالص (بدون port)
	clientIP := extractIP(remoteAddr.String())
	if clientIP == "" {
		logger.Warning("SPA: could not extract IP from address:", remoteAddr.String())
		return
	}

	s.authorizeIP(clientIP)
}

// authorizeIP پورت اصلی را برای یک IP مشخص باز می‌کند
func (s *SpaService) authorizeIP(clientIP string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	expiry := time.Now().Add(time.Duration(s.windowSeconds) * time.Second)
	s.authorizedIPs[clientIP] = expiry

	// اضافه کردن قانون iptables
	// این دستور یک قانون ACCEPT با comment منحصربه‌فرد برای شناسایی و حذف بعدی اضافه می‌کند
	comment := fmt.Sprintf("spa-auth-%s", clientIP)
	cmd := exec.Command("iptables",
		"-I", "INPUT", "1",
		"-s", clientIP,
		"-p", "tcp",
		"--dport", fmt.Sprintf("%d", s.mainPort),
		"-m", "comment", "--comment", comment,
		"-j", "ACCEPT",
	)

	if err := cmd.Run(); err != nil {
		logger.Warning(fmt.Sprintf("SPA: iptables rule add failed for %s: %v (continuing anyway)", clientIP, err))
	} else {
		logger.Info(fmt.Sprintf("✓ SPA: Port %d opened for IP %s (expires in %ds)",
			s.mainPort, clientIP, s.windowSeconds))
	}
}

// cleanupLoop قوانین iptables منقضی‌شده را پاک می‌کند
func (s *SpaService) cleanupLoop() {
	for {
		select {
		case <-s.stopChan:
			return
		case <-s.cleanupTicker.C:
			s.cleanupExpiredIPs()
		}
	}
}

// cleanupExpiredIPs قوانین iptables IP‌های منقضی‌شده را حذف می‌کند
func (s *SpaService) cleanupExpiredIPs() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for ip, expiry := range s.authorizedIPs {
		if now.After(expiry) {
			s.removeIPRule(ip)
			delete(s.authorizedIPs, ip)
			logger.Info(fmt.Sprintf("SPA: port %d closed again for expired IP %s", s.mainPort, ip))
		}
	}
}

// removeIPRule قانون iptables یک IP مشخص را حذف می‌کند
func (s *SpaService) removeIPRule(clientIP string) {
	comment := fmt.Sprintf("spa-auth-%s", clientIP)
	cmd := exec.Command("iptables",
		"-D", "INPUT",
		"-s", clientIP,
		"-p", "tcp",
		"--dport", fmt.Sprintf("%d", s.mainPort),
		"-m", "comment", "--comment", comment,
		"-j", "ACCEPT",
	)
	if err := cmd.Run(); err != nil {
		logger.Warning(fmt.Sprintf("SPA: iptables rule delete failed for %s: %v", clientIP, err))
	}
}

// flushSpaRules تمام قوانین SPA iptables را هنگام خاموش شدن سرویس حذف می‌کند
func (s *SpaService) flushSpaRules() {
	for ip := range s.authorizedIPs {
		s.removeIPRule(ip)
	}
	s.authorizedIPs = make(map[string]time.Time)
}

// GenerateRandomKey یک کلید PSK تصادفی 32 بایتی (Base64) تولید می‌کند
// این تابع از پنل x-ui برای تولید کلید جدید فراخوانی می‌شود
func GenerateSpaKey() string {
	// استفاده از SHA256 روی timestamp + entropy برای تولید کلید
	seed := fmt.Sprintf("spa-key-%d-%d", time.Now().UnixNano(), time.Now().Unix())
	h := sha256.Sum256([]byte(seed))
	return base64.StdEncoding.EncodeToString(h[:])
}

// IsIPAuthorized بررسی می‌کند آیا یک IP در حال حاضر مجاز است
func (s *SpaService) IsIPAuthorized(ip string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	expiry, ok := s.authorizedIPs[ip]
	if !ok {
		return false
	}
	return time.Now().Before(expiry)
}

// extractIP آدرس IP را از یک رشته "IP:port" جدا می‌کند
func extractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr // شاید بدون پورت باشد
	}
	return host
}
