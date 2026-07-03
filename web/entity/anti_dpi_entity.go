package entity

// AntiDpiSettings تنظیمات کلی Anti-DPI پنل را نگه می‌دارد
type AntiDpiSettings struct {
	// ─── SPA: Single Packet Authorization ──────────────────────────────────────
	// وقتی فعال باشد، سرور فقط به کلاینت‌هایی که بسته SPA معتبر ارسال کرده‌اند
	// پورت اصلی را باز می‌کند. سیستم‌های Active Probing چیزی نمی‌بینند.
	SpaEnable bool   `json:"spaEnable" form:"spaEnable"`
	SpaPort   int    `json:"spaPort"   form:"spaPort"`   // پورت UDP مخفی (پیش‌فرض: 62201)
	SpaKey    string `json:"spaKey"    form:"spaKey"`    // کلید Pre-Shared Key (Base64, 32 بایت)
	// مدت زمان باز ماندن پورت برای IP کلاینت پس از دریافت SPA معتبر (ثانیه)
	SpaWindowSeconds int `json:"spaWindowSeconds" form:"spaWindowSeconds"`
	// محدودیت اعتبار timestamp بسته SPA برای جلوگیری از Replay Attack (ثانیه)
	SpaTimestampTolerance int `json:"spaTimestampTolerance" form:"spaTimestampTolerance"`
}
