package global

import (
	"context"
	_ "unsafe"

	"github.com/robfig/cron/v3"
)

// SpaServicer اینترفیس محلی برای سرویس SPA است.
// با تعریف اینترفیس اینجا، پکیج global هیچ وابستگی‌ای به پکیج service ندارد
// و مشکل circular dependency برطرف می‌شود.
// هر نوعی که متدهای زیر را پیاده‌سازی کند می‌تواند ثبت شود.
type SpaServicer interface {
	Configure(spaPort int, pskBase64 string, mainPort int, windowSecs int, timestampTol int) error
	Start() error
	Stop()
}

// SrtpTunnelServicer اینترفیس محلی برای سرویس تونل SRTP است.
type SrtpTunnelServicer interface {
	Configure(listenPort, targetPort int, pskKey string)
	Start() error
	Stop()
}

var (
	webServer        WebServer
	subServer        SubServer
	spaService       SpaServicer        // از interface استفاده می‌شود نه نوع مستقیم
	srtpTunnelService SrtpTunnelServicer // تونل صوتی/تصویری فیک
)

type WebServer interface {
	GetCron() *cron.Cron
	GetCtx() context.Context
}

type SubServer interface {
	GetCtx() context.Context
}

func SetWebServer(s WebServer) {
	webServer = s
}

func GetWebServer() WebServer {
	return webServer
}

func SetSubServer(s SubServer) {
	subServer = s
}

func GetSubServer() SubServer {
	return subServer
}

// SetSpaService سرویس SPA را در فضای سراسری ذخیره می‌کند
func SetSpaService(s SpaServicer) {
	spaService = s
}

// GetSpaService سرویس SPA را از فضای سراسری برمی‌گرداند
func GetSpaService() SpaServicer {
	return spaService
}

// SetSrtpTunnelService سرویس تونل SRTP را در فضای سراسری ذخیره می‌کند
func SetSrtpTunnelService(s SrtpTunnelServicer) {
	srtpTunnelService = s
}

// GetSrtpTunnelService سرویس تونل SRTP را از فضای سراسری برمی‌گرداند
func GetSrtpTunnelService() SrtpTunnelServicer {
	return srtpTunnelService
}

