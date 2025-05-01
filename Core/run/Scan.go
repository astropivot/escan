package run

import (
	"escan/Common"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
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
	// chan_portScan_Result := getAlivePorts(chan_livehost, info)
	// for i := range chan_portScan_Result {
	// 	// fmt.Println(i.ip.String(), i.port, "live")
	// 	_ = i
	// }
	fmt.Println("end")
}

const __PORT_SCAN_RESULT_LEN = 65536 * 4

func getAlivePorts(chan_livehost chan netip.Addr, info *Common.HostInfoList) chan netip.AddrPort {
	Common.LogInfo("开始端口扫描")
	chan_port_result := make(chan netip.AddrPort, __PORT_SCAN_RESULT_LEN)
	go RunPortScan(chan_livehost, info, Common.Args.Timeout_portScan, chan_port_result)
	return chan_port_result
}

type portScanResult struct {
	ip   net.IP
	port int
}

type Addr struct {
	ip   net.IP
	port int
}

// 通过入参chan_livehost和info，启动多线程扫描端口，并将结果通过chan_portScan_result返回
func RunPortScan(chan_livehost chan netip.Addr, info *Common.HostInfoList, timeout int64, chan_portScan_result chan netip.AddrPort) {
	var workerWg sync.WaitGroup
	var wg sync.WaitGroup

	chan_addr := make(chan netip.AddrPort, __PORT_SCAN_RESULT_LEN)

	for range Common.Args.ThreadsNum {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			for addr := range chan_addr {
				PortConnect(addr, chan_portScan_result, timeout, &wg)
			}
		}()
	}

	var _wg sync.WaitGroup
	for ip := range chan_livehost {
		Common.LogSuccess("目标 %s 存活", ip.String())
		_wg.Add(1)

		go func(ip netip.Addr) { // 多线程派发任务防止同ip的任务连续执行

			for _, _port := range info.Ports {
				wg.Add(1)
				time.Sleep(10 * time.Millisecond)
				// Common.LogDebug("开始扫描 %s:%d", ip.String(), _port)
				chan_addr <- netip.AddrPortFrom(ip, uint16(_port))
			}
			_wg.Done()
		}(ip)
	}
	_wg.Wait()
	close(chan_addr)

	workerWg.Wait()
	close(chan_portScan_result)
	wg.Wait()
	// 通过入参chan_portScan_result返回结果
}

// func PortConnect(addr Addr, chan_portScan_result chan portScanResult, timeout int, wg *sync.WaitGroup) {
// 	defer wg.Done()
// 	conn, err := WrapperTcpWithTimeout("tcp4", fmt.Sprintf("%s:%d", addr.ip.String(), addr.port), time.Duration(timeout)*time.Second)
// 	if err == nil {
// 		defer conn.Close()
// 		chan_portScan_result <- portScanResult{addr.ip, addr.port}
// 	}

// }

func PortConnect(addr netip.AddrPort, results chan<- netip.AddrPort, timeout int64, wg *sync.WaitGroup) {
	// TODO
	defer wg.Done()

	var isOpen bool
	var err error
	var conn net.Conn

	// 尝试建立TCP连接
	conn, err = Common.WrapperTcpWithTimeout("tcp4",
		fmt.Sprintf("%s:%v", net.IP(addr.Addr().AsSlice()), addr.Port()),
		time.Duration(timeout)*time.Second)
	if err == nil {
		defer conn.Close()
		isOpen = true
	}

	if err != nil || !isOpen {
		return
	}

	// 记录开放端口
	address := fmt.Sprintf("%s:%d", net.IP(addr.Addr().AsSlice()), addr.Port())
	Common.LogSuccess("端口开放 %s", address)

	// 保存端口扫描结果
	portResult := &Common.ScanResult{
		Time:   time.Now(),
		Type:   Common.PORT,
		Target: addr.Addr().String(),
		Status: "open",
		Details: map[string]any{
			"port": addr.Port(),
		},
	}
	Common.SaveResult(portResult)

	// 构造扫描结果

	results <- addr
}
