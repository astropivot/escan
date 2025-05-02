package run

import (
	"escan/Common"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const __PORT_SCAN_RESULT_LEN = 65536 * 4

func getAlivePorts(chan_livehost chan netip.Addr, info *Common.HostInfoList) chan netip.AddrPort {
	Common.LogInfo("开始端口扫描")
	chan_port_result := make(chan netip.AddrPort, __PORT_SCAN_RESULT_LEN)
	go RunPortScan(chan_livehost, info, Common.Args.Timeout_portScan, chan_port_result)
	return chan_port_result
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

	if !Common.IsSkipPortfinger && conn != nil {
		scanner := NewPortInfoScanner(addr.Addr().String(), int(addr.Port()), conn, time.Duration(timeout)*time.Second)
		if serviceInfo, err := scanner.Identify(); err == nil {
			// result.Service = serviceInfo
			var logMsg strings.Builder
			logMsg.WriteString(fmt.Sprintf("服务识别 %s => ", addr.String()))
			if serviceInfo.Name != "unknown" {
				logMsg.WriteString(fmt.Sprintf("[%s]", serviceInfo.Name))
			}
			if serviceInfo.Version != "" {
				logMsg.WriteString(fmt.Sprintf(" 版本:%s", serviceInfo.Version))
			}
			details := map[string]any{
				"port":    addr.Port(),
				"service": serviceInfo.Name,
			}
			if serviceInfo.Version != "" {
				details["version"] = serviceInfo.Version
			}
			// 添加产品信息
			if v, ok := serviceInfo.Extras["vendor_product"]; ok && v != "" {
				details["product"] = v
				logMsg.WriteString(fmt.Sprintf(" 产品:%s", v))
			}

			// 添加操作系统信息
			if v, ok := serviceInfo.Extras["os"]; ok && v != "" {
				details["os"] = v
				logMsg.WriteString(fmt.Sprintf(" 系统:%s", v))
			}

			// 添加额外信息
			if v, ok := serviceInfo.Extras["info"]; ok && v != "" {
				details["info"] = v
				logMsg.WriteString(fmt.Sprintf(" 信息:%s", v))
			}
			// 添加Banner信息
			if len(serviceInfo.Banner) > 0 && len(serviceInfo.Banner) < 100 {
				details["banner"] = strings.TrimSpace(serviceInfo.Banner)
				logMsg.WriteString(fmt.Sprintf(" Banner:[%s]", strings.TrimSpace(serviceInfo.Banner)))
			}
			serviceResult := &Common.ScanResult{
				Time:    time.Now(),
				Type:    Common.SERVICE,
				Target:  addr.Addr().String(),
				Status:  "identified",
				Details: details,
			}
			Common.SaveResult(serviceResult)

			Common.LogSuccess("%s", logMsg.String())
		}

	}

	// 构造扫描结果

	results <- addr
}
