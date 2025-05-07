package run

import (
	"escan/Common"
	"fmt"
	"net/netip"
	"sync"
)

var (
	LocalScan bool            // 本地扫描模式标识
	WebScan   bool            // Web扫描模式标识
	Mutex     = &sync.Mutex{} // 用于保护共享资源
)

var (
	ExistIP      = make(map[netip.Addr]struct{})
	_lockExistIP = sync.Mutex{}
)

func IsExistIPwithAdd(ip netip.Addr) bool {
	_lockExistIP.Lock()
	defer _lockExistIP.Unlock()
	_, ok := ExistIP[ip]
	if !ok {
		ExistIP[ip] = struct{}{}
	}
	return ok
}

func IsExistIP(ip netip.Addr) bool {
	_lockExistIP.Lock()
	defer _lockExistIP.Unlock()
	_, ok := ExistIP[ip]
	return ok
}

func CousumeAchan(chan_ip chan netip.Addr) {
	for ip := range chan_ip {
		_ = ip
	}
}

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

	chan_liveipre := CheckLive(info)
	chan_liveip := printiplive(chan_liveipre)
	if Common.IsOnlyarp && Common.Args.Isarp {
		CousumeAchan(chan_liveip)
		return
	}
	chan_portScan_Result := getAlivePorts(chan_liveip, info)

	if Common.IsPlugin {
		ScanTasks := prepareScanTasks(chan_portScan_Result)
		for task := range ScanTasks {
			Common.LogInfo("开始插件扫描: %s", task.Name)
			plugin := Common.PluginManager[task.Name]
			plugin.ScanFunc(task.HostInfo)
		}
	} else {
		consumeScanResults(chan_portScan_Result)
	}

	fmt.Println("end")
}
func consumeScanResults(chan_port_result chan netip.AddrPort) {
	for addrport := range chan_port_result {
		_ = addrport
	}
}

func printiplive(ip_in chan netip.Addr) chan netip.Addr {
	ip_out := make(chan netip.Addr, 10)
	if Common.Isprintliveip {
		go func(in chan netip.Addr) {
			for ip := range in {
				Common.LogSuccess("目标 %s 存活", ip.String())
				ip_out <- ip
			}
			close(ip_out)
		}(ip_in)
	} else {
		go func(in chan netip.Addr) {
			for ip := range in {
				ip_out <- ip
			}
			close(ip_out)
		}(ip_in)
	}

	return ip_out
}

type ScanTask struct {
	Name     string
	HostInfo *Common.HostInfo
}

func prepareScanTasks(chan_port_result chan netip.AddrPort) chan ScanTask {
	tasks := make(chan ScanTask, 100)
	go __task_generator(chan_port_result, tasks)
	return tasks
}

func __task_generator(chan_port_result chan netip.AddrPort, chan_task chan ScanTask) {
	for addrport := range chan_port_result {
		for name, plugin := range Common.PluginManager {
			if plugin.HasPort(int(addrport.Port())) {
				chan_task <- ScanTask{
					Name: name,
					HostInfo: &Common.HostInfo{
						Host: addrport.Addr().String(),
						Port: int(addrport.Port()),
					},
				}
			}
		}

	}
	close(chan_task)
}
