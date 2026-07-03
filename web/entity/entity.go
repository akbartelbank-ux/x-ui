package entity

import (
	"crypto/tls"
	"net"
	"strings"
	"time"

	"github.com/alireza0/x-ui/util/common"
)

type Msg struct {
	Success bool        `json:"success"`
	Msg     string      `json:"msg"`
	Obj     interface{} `json:"obj"`
}

type AllSetting struct {
	WebListen        string `json:"webListen" form:"webListen"`
	WebDomain        string `json:"webDomain" form:"webDomain"`
	WebPort          int    `json:"webPort" form:"webPort"`
	WebCertFile      string `json:"webCertFile" form:"webCertFile"`
	WebKeyFile       string `json:"webKeyFile" form:"webKeyFile"`
	WebBasePath      string `json:"webBasePath" form:"webBasePath"`
	SessionMaxAge    int    `json:"sessionMaxAge" form:"sessionMaxAge"`
	PageSize         int    `json:"pageSize" form:"pageSize"`
	ExpireDiff       int    `json:"expireDiff" form:"expireDiff"`
	TrafficDiff      int    `json:"trafficDiff" form:"trafficDiff"`
	RemarkModel      string `json:"remarkModel" form:"remarkModel"`
	TgBotEnable      bool   `json:"tgBotEnable" form:"tgBotEnable"`
	TgBotToken       string `json:"tgBotToken" form:"tgBotToken"`
	TgBotChatId      string `json:"tgBotChatId" form:"tgBotChatId"`
	TgRunTime        string `json:"tgRunTime" form:"tgRunTime"`
	TgBotBackup      bool   `json:"tgBotBackup" form:"tgBotBackup"`
	TgBotLoginNotify bool   `json:"tgBotLoginNotify" form:"tgBotLoginNotify"`
	TgCpu            int    `json:"tgCpu" form:"tgCpu"`
	TgLang           string `json:"tgLang" form:"tgLang"`
	TimeLocation     string `json:"timeLocation" form:"timeLocation"`
	SubEnable        bool   `json:"subEnable" form:"subEnable"`
	SubListen        string `json:"subListen" form:"subListen"`
	SubPort          int    `json:"subPort" form:"subPort"`
	SubPath          string `json:"subPath" form:"subPath"`
	SubDomain        string `json:"subDomain" form:"subDomain"`
	SubCertFile      string `json:"subCertFile" form:"subCertFile"`
	SubKeyFile       string `json:"subKeyFile" form:"subKeyFile"`
	SubUpdates       int    `json:"subUpdates" form:"subUpdates"`
	SubEncrypt       bool   `json:"subEncrypt" form:"subEncrypt"`
	SubShowInfo      bool   `json:"subShowInfo" form:"subShowInfo"`
	SubURI           string `json:"subURI" form:"subURI"`
	SubJsonPath      string `json:"subJsonPath" form:"subJsonPath"`
	SubJsonURI       string `json:"subJsonURI" form:"subJsonURI"`
	SubJsonFragment  string `json:"subJsonFragment" form:"subJsonFragment"`
	SubJsonNoises    string `json:"subJsonNoises" form:"subJsonNoises"`
	SubJsonMux       string `json:"subJsonMux" form:"subJsonMux"`
	SubJsonRules     string `json:"subJsonRules" form:"subJsonRules"`

	// ─── Anti-DPI Settings ──────────────────────────────────────────────────────
	SpaEnable             bool   `json:"spaEnable" form:"spaEnable"`
	SpaPort               int    `json:"spaPort" form:"spaPort"`
	SpaKey                string `json:"spaKey" form:"spaKey"`
	SpaMainPort           int    `json:"spaMainPort" form:"spaMainPort"`
	SpaWindowSeconds      int    `json:"spaWindowSeconds" form:"spaWindowSeconds"`
	SpaTimestampTolerance int    `json:"spaTimestampTolerance" form:"spaTimestampTolerance"`
	SrtpEnable            bool   `json:"srtpEnable" form:"srtpEnable"`
	SrtpPort              int    `json:"srtpPort" form:"srtpPort"`
	SrtpTargetPort        int    `json:"srtpTargetPort" form:"srtpTargetPort"`
	SrtpKey               string `json:"srtpKey" form:"srtpKey"`
}

func (s *AllSetting) CheckValid() error {
	if s.WebListen != "" {
		ip := net.ParseIP(s.WebListen)
		if ip == nil {
			return common.NewError("web listen is not valid ip:", s.WebListen)
		}
	}

	if s.SubListen != "" {
		ip := net.ParseIP(s.SubListen)
		if ip == nil {
			return common.NewError("Sub listen is not valid ip:", s.SubListen)
		}
	}

	if s.WebPort <= 0 || s.WebPort > 65535 {
		return common.NewError("web port is not a valid port:", s.WebPort)
	}

	if s.SubPort <= 0 || s.SubPort > 65535 {
		return common.NewError("Sub port is not a valid port:", s.SubPort)
	}

	if s.SubPort == s.WebPort {
		return common.NewError("Sub and Web could not use same port:", s.SubPort)
	}

	// ─── Anti-DPI Validations ───
	if s.SpaEnable {
		if s.SpaPort <= 0 || s.SpaPort > 65535 {
			return common.NewError("SPA UDP port is not a valid port:", s.SpaPort)
		}
		if s.SpaMainPort <= 0 || s.SpaMainPort > 65535 {
			return common.NewError("SPA main port is not a valid port:", s.SpaMainPort)
		}
		if s.SpaKey == "" {
			return common.NewError("SPA key cannot be empty when enabled")
		}
	}

	if s.SrtpEnable {
		if s.SrtpPort <= 0 || s.SrtpPort > 65535 {
			return common.NewError("SRTP tunnel port is not a valid port:", s.SrtpPort)
		}
		if s.SrtpTargetPort <= 0 || s.SrtpTargetPort > 65535 {
			return common.NewError("SRTP target port is not a valid port:", s.SrtpTargetPort)
		}
		if s.SrtpKey == "" {
			return common.NewError("SRTP key cannot be empty when enabled")
		}
	}

	if s.WebCertFile != "" || s.WebKeyFile != "" {
		_, err := tls.LoadX509KeyPair(s.WebCertFile, s.WebKeyFile)
		if err != nil {
			return common.NewErrorf("cert file <%v> or key file <%v> invalid: %v", s.WebCertFile, s.WebKeyFile, err)
		}
	}

	if s.SubCertFile != "" || s.SubKeyFile != "" {
		_, err := tls.LoadX509KeyPair(s.SubCertFile, s.SubKeyFile)
		if err != nil {
			return common.NewErrorf("cert file <%v> or key file <%v> invalid: %v", s.SubCertFile, s.SubKeyFile, err)
		}
	}

	if !strings.HasPrefix(s.WebBasePath, "/") {
		s.WebBasePath = "/" + s.WebBasePath
	}
	if !strings.HasSuffix(s.WebBasePath, "/") {
		s.WebBasePath += "/"
	}

	if !strings.HasPrefix(s.SubPath, "/") {
		s.SubPath = "/" + s.SubPath
	}
	if !strings.HasSuffix(s.SubPath, "/") {
		s.SubPath += "/"
	}

	if !strings.HasPrefix(s.SubJsonPath, "/") {
		s.SubJsonPath = "/" + s.SubJsonPath
	}
	if !strings.HasSuffix(s.SubJsonPath, "/") {
		s.SubJsonPath += "/"
	}

	_, err := time.LoadLocation(s.TimeLocation)
	if err != nil {
		return common.NewError("time location not exist:", s.TimeLocation)
	}

	return nil
}

