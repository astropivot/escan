package run

import (
	"escan/Common"
	"fmt"
	"sync"
)

var (
	LocalScan bool            // 本地扫描模式标识
	WebScan   bool            // Web扫描模式标识
	Mutex     = &sync.Mutex{} // 用于保护共享资源
)

func Scan(info *Common.HostInfoList) {
	Common.LogInfo("开始信息扫描")

	selectScanMode(info)
}

func selectScanMode(info *Common.HostInfoList) {
	switch {
	case len(Common.Args.URLs) > 0:
		WebScan = true
	default:
		executeHostScan(info)
	}
}

func executeHostScan(info *Common.HostInfoList) {
	if len(info.IPs) == 0 {
		Common.LogError("未指定扫描目标")
		return
	}
	Common.LogInfo("ip数,port数,url数: %d,%d,%d", len(info.IPs), len(info.Ports), len(info.Urls))
	Common.LogInfo("开始主机扫描")

	chan_livehost := CheckLive(info)
	for i := range chan_livehost {
		fmt.Println(i)
	}
	chan_portScan_Result := getAlivePorts(chan_livehost, info)
	for i := range chan_portScan_Result {
		// fmt.Println(i.ip.String(), i.port, "live")
		_ = i
	}
	fmt.Println("end")
}
