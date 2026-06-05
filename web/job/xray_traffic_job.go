package job

import (
	"github.com/akbartelbank-ux/x-ui/logger"
	"github.com/akbartelbank-ux/x-ui/web/service"
)

type XrayTrafficJob struct {
	xrayService     service.XrayService
	inboundService  service.InboundService
	outboundService service.OutboundService
}

func NewXrayTrafficJob() *XrayTrafficJob {
	return new(XrayTrafficJob)
}

func (j *XrayTrafficJob) Run() {
	if !j.xrayService.IsXrayRunning() {
		return
	}

	traffics, clientTraffics, err := j.xrayService.GetXrayTraffic()
	if err != nil {
		logger.Warning("get xray traffic failed:", err)
		return
	}
	err, needRestart := j.inboundService.AddTraffic(traffics, clientTraffics)
	if err != nil {
		logger.Warning("add inbound traffic failed:", err)
	}
	if err := j.outboundService.AddTraffic(traffics); err != nil {
		logger.Warning("add outbound traffic failed:", err)
	}
	if needRestart {
		j.xrayService.SetToNeedRestart()
	}
}
