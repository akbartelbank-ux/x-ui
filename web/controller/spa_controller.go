package controller

// spa_controller.go — کنترلر API برای مدیریت تنظیمات Anti-DPI SPA از پنل x-ui
//
// مسیرهای API:
//   GET  /xui/API/antiDpi/spaStatus    — وضعیت فعلی SPA
//   GET  /xui/API/antiDpi/generateKey  — تولید کلید PSK جدید
//   POST /xui/API/antiDpi/spaConfig    — ذخیره تنظیمات SPA
//   POST /xui/API/antiDpi/spaToggle    — فعال/غیرفعال کردن SPA
//   POST /xui/API/antiDpi/spaRestart   — راه‌اندازی مجدد سرویس SPA

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// SettingService اینترفیس محلی برای دسترسی به تنظیمات SPA
// این تعریف محلی وابستگی به پکیج‌های دیگر پروژه را برمی‌دارد تا در صورت تغییر
// نام ماژول/ریپازیتوری، این فایل نیازی به تغییر نداشته باشد.
type SettingService interface {
	GetSpaEnable() (bool, error)
	SetSpaEnable(value string) error
	GetSpaPort() (int, error)
	SetSpaPort(value string) error
	GetSpaKey() (string, error)
	SetSpaKey(value string) error
	GetSpaMainPort() (int, error)
	SetSpaMainPort(value string) error
	GetSpaWindowSeconds() (int, error)
	SetSpaWindowSeconds(value string) error
	GetSpaTimestampTolerance() (int, error)
	SetSpaTimestampTolerance(value string) error
}

// SpaService اینترفیس محلی برای کنترل سرور SPA
type SpaService interface {
	Configure(spaPort int, pskBase64 string, mainPort int, windowSecs int, timestampTol int) error
	Start() error
	Stop()
}

// SpaController کنترلر مدیریت Anti-DPI SPA
type SpaController struct {
	BaseController
	settingService SettingService
	spaService     SpaService
}

// NewSpaController یک نمونه جدید SpaController می‌سازد و مسیرها را ثبت می‌کند.
// این متد تمام وابستگی‌ها را به صورت تزریق وابستگی (Dependency Injection) دریافت می‌کند.
func NewSpaController(g *gin.RouterGroup, spaService SpaService, settingService SettingService) *SpaController {
	c := &SpaController{
		spaService:     spaService,
		settingService: settingService,
	}
	c.initRouter(g)
	return c
}

func (c *SpaController) initRouter(g *gin.RouterGroup) {
	antiDpi := g.Group("/antiDpi")
	antiDpi.Use(c.checkLogin)

	antiDpi.GET("/spaStatus", c.getSpaStatus)
	antiDpi.GET("/generateKey", c.generateNewKey)
	antiDpi.POST("/spaConfig", c.saveSpaConfig)
	antiDpi.POST("/spaToggle", c.toggleSpa)
	antiDpi.POST("/spaRestart", c.restartSpa)
}

// getSpaStatus وضعیت فعلی سرویس SPA را برمی‌گرداند
func (c *SpaController) getSpaStatus(ctx *gin.Context) {
	spaEnable, err := c.settingService.GetSpaEnable()
	if err != nil {
		jsonMsg(ctx, "Failed to get SPA status", err)
		return
	}

	spaPort, _ := c.settingService.GetSpaPort()
	spaKey, _ := c.settingService.GetSpaKey()
	spaMainPort, _ := c.settingService.GetSpaMainPort()
	spaWindow, _ := c.settingService.GetSpaWindowSeconds()
	spaTolerance, _ := c.settingService.GetSpaTimestampTolerance()

	// کلید را برای نمایش کوتاه می‌کنیم (امنیت)
	keyPreview := ""
	if len(spaKey) > 8 {
		keyPreview = spaKey[:8] + "..."
	} else if spaKey != "" {
		keyPreview = "****"
	}

	ctx.JSON(http.StatusOK, gin.H{
		"success": true,
		"obj": gin.H{
			"spaEnable":             spaEnable,
			"spaPort":               spaPort,
			"spaKeyPreview":         keyPreview,
			"spaKeySet":             spaKey != "",
			"spaMainPort":           spaMainPort,
			"spaWindowSeconds":      spaWindow,
			"spaTimestampTolerance": spaTolerance,
		},
	})
}

// generateNewKey یک کلید PSK جدید و تصادفی تولید می‌کند
func (c *SpaController) generateNewKey(ctx *gin.Context) {
	// پیاده‌سازی کاملاً مستقل بدون نیاز به پکیج‌های خارجی پروژه
	seed := fmt.Sprintf("spa-key-%d-%d", time.Now().UnixNano(), time.Now().Unix())
	h := sha256.Sum256([]byte(seed))
	newKey := base64.StdEncoding.EncodeToString(h[:])

	ctx.JSON(http.StatusOK, gin.H{
		"success": true,
		"obj":     gin.H{"key": newKey},
		"msg":     "کلید جدید تولید شد. آن را در تنظیمات SPA ذخیره کنید و در کلاینت هم وارد کنید.",
	})
}

// saveSpaConfig تنظیمات SPA را ذخیره می‌کند
func (c *SpaController) saveSpaConfig(ctx *gin.Context) {
	var req struct {
		SpaPort               string `json:"spaPort"`
		SpaKey                string `json:"spaKey"`
		SpaMainPort           string `json:"spaMainPort"`
		SpaWindowSeconds      string `json:"spaWindowSeconds"`
		SpaTimestampTolerance string `json:"spaTimestampTolerance"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		jsonMsg(ctx, "Invalid request", err)
		return
	}

	// اعتبارسنجی پورت SPA
	if req.SpaPort != "" {
		port, err := strconv.Atoi(req.SpaPort)
		if err != nil || port < 1 || port > 65535 {
			jsonMsg(ctx, "پورت SPA نامعتبر است (باید بین ۱ تا ۶۵۵۳۵ باشد)", nil)
			return
		}
	}

	// اعتبارسنجی پورت اصلی
	if req.SpaMainPort != "" {
		port, err := strconv.Atoi(req.SpaMainPort)
		if err != nil || port < 1 || port > 65535 {
			jsonMsg(ctx, "پورت اصلی نامعتبر است", nil)
			return
		}
	}

	// ذخیره تنظیمات
	if err := c.settingService.SetSpaPort(req.SpaPort); err != nil {
		jsonMsg(ctx, "Failed to save SPA port", err)
		return
	}
	if req.SpaKey != "" {
		if err := c.settingService.SetSpaKey(req.SpaKey); err != nil {
			jsonMsg(ctx, "Failed to save SPA key", err)
			return
		}
	}
	if err := c.settingService.SetSpaMainPort(req.SpaMainPort); err != nil {
		jsonMsg(ctx, "Failed to save SPA main port", err)
		return
	}
	if req.SpaWindowSeconds != "" {
		if err := c.settingService.SetSpaWindowSeconds(req.SpaWindowSeconds); err != nil {
			jsonMsg(ctx, "Failed to save SPA window", err)
			return
		}
	}

	log.Println("[SPA Controller] SPA configuration updated via panel")
	jsonMsg(ctx, "تنظیمات SPA با موفقیت ذخیره شد. برای اعمال تغییرات، SPA را راه‌اندازی مجدد کنید.", nil)
}

// toggleSpa سرویس SPA را فعال یا غیرفعال می‌کند
func (c *SpaController) toggleSpa(ctx *gin.Context) {
	var req struct {
		Enable bool `json:"enable"`
	}
	if err := ctx.ShouldBindJSON(&req); err != nil {
		jsonMsg(ctx, "Invalid request", err)
		return
	}

	enableStr := "false"
	if req.Enable {
		enableStr = "true"
	}

	if err := c.settingService.SetSpaEnable(enableStr); err != nil {
		jsonMsg(ctx, "Failed to toggle SPA", err)
		return
	}

	status := "غیرفعال"
	if req.Enable {
		status = "فعال"
	}

	log.Println("[SPA Controller] Anti-DPI SPA toggled:", status)
	jsonMsg(ctx, "وضعیت SPA به «"+status+"» تغییر کرد. سرور را ریستارت کنید تا اعمال شود.", nil)
}

// restartSpa سرویس SPA را با تنظیمات جدید راه‌اندازی مجدد می‌کند
func (c *SpaController) restartSpa(ctx *gin.Context) {
	if c.spaService == nil {
		jsonMsg(ctx, "سرویس SPA در دسترس نیست", nil)
		return
	}

	// متوقف کردن سرویس فعلی
	c.spaService.Stop()

	// بارگذاری تنظیمات جدید
	spaPort, err := c.settingService.GetSpaPort()
	if err != nil {
		jsonMsg(ctx, "Failed to read SPA port", err)
		return
	}

	spaKey, err := c.settingService.GetSpaKey()
	if err != nil || spaKey == "" {
		jsonMsg(ctx, "کلید SPA تنظیم نشده است. ابتدا یک کلید تولید و ذخیره کنید.", nil)
		return
	}

	spaMainPort, err := c.settingService.GetSpaMainPort()
	if err != nil {
		jsonMsg(ctx, "Failed to read SPA main port", err)
		return
	}

	spaWindow, _ := c.settingService.GetSpaWindowSeconds()
	spaTolerance, _ := c.settingService.GetSpaTimestampTolerance()

	if err := c.spaService.Configure(spaPort, spaKey, spaMainPort, spaWindow, spaTolerance); err != nil {
		jsonMsg(ctx, "SPA configuration error: "+err.Error(), err)
		return
	}

	if err := c.spaService.Start(); err != nil {
		jsonMsg(ctx, "Failed to start SPA service: "+err.Error(), err)
		return
	}

	log.Println("[SPA Controller] Anti-DPI SPA service restarted successfully")
	jsonMsg(ctx, "سرویس SPA با موفقیت راه‌اندازی مجدد شد.", nil)
}
