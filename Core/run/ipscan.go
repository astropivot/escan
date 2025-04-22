package run

import (
	"bytes"
	"escan/Common"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/malfunkt/arpfox/arp"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const __LIVE_HOST_LEN = 512
const __MAYBE_NOT_LIVE_HOST_LEN = 512

func CheckLive(info *Common.HostInfoList) chan net.IP {
	chan_livehost := make(chan net.IP, __LIVE_HOST_LEN)
	chan_may_not_livehost := make(chan net.IP, __MAYBE_NOT_LIVE_HOST_LEN)

	if Common.Args.IsPing {
		Common.LogInfo("开始ping扫描")
		go RunPing(info, chan_livehost, chan_may_not_livehost)
	} else {
		Common.LogInfo("开始ICMP扫描")
		go RunICMP(info, chan_livehost, chan_may_not_livehost)
	}

	Common.LogInfo("开始arp扫描")
	go RunArpScan(info, chan_livehost, chan_may_not_livehost)

	Common.LogInfo("返回chan")
	return chan_livehost

}

func RunArpScan(info *Common.HostInfoList, chan_livehost chan net.IP, chan_may_not_livehost chan net.IP) {
	//todo
	for ip := range chan_may_not_livehost {
		if _do_arp_scan(ip) {
			Common.LogDebug("arp扫描成功:%s", ip.String())
			chan_livehost <- ip
		}
	}
	close(chan_livehost)
}

func _do_arp_scan(host net.IP) bool {
	_, err := arp.Lookup(host)
	return err == nil
}

func RunICMP(info *Common.HostInfoList, chan_livehost chan net.IP, chan_may_not_livehost chan net.IP) {
	Common.LogInfo("ICMP扫描todo")
	// chan_ipv4 := make(chan net.IP, __LIVE_HOST_LEN/2)
	// chan_ipv6 := make(chan net.IP, __LIVE_HOST_LEN/2)
	__icmp4scan(info, chan_livehost, chan_may_not_livehost)
	// go __icmp6scan(chan_ipv6, chan_livehost)
	// for _, i := range info.IPs {
	// 	if __isIP4(i) {
	// 		chan_ipv4 <- i
	// 	} else {
	// 		Common.LogInfo("ICMP6扫描暂时不支持")
	// 	}
	// }

}

func __icmp4scan(info *Common.HostInfoList, chan_livehost chan net.IP, chan_may_not_livehost chan net.IP) {
	endflag := false
	con, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")

	if err == nil {
		defer con.Close()

		go func() {
			var iplivemap = make(map[string]struct{})
			dych := DynamicQueue{
				buffer: make([]net.IP, 0),
			}
			go func() {
				chan_livehost <- dych.Dequeue()
			}()
			for {
				if endflag {
					return
				}
				// 接收ICMP响应
				msg := make([]byte, 100)
				_, sourceIP, _ := con.ReadFrom(msg)
				if sourceIP == nil {
					Common.LogError("ICMP4接收失败")
					return
				}
				ip := net.ParseIP(sourceIP.String())
				if _, ok := iplivemap[ip.String()]; ok {
					continue
				}
				iplivemap[ip.String()] = struct{}{}
				dych.Enqueue(ip)
			}
		}()

		for _, ip := range info.IPs {
			dst, _ := net.ResolveIPAddr("ip4", ip.String())
			pingMsg, err := makeIcmp4EchoMsg()
			if err != nil {
				Common.LogError("ICMP4消息创建失败")
				continue
			}
			if _, err := con.WriteTo(pingMsg, dst); err != nil {
				Common.LogError("ICMP4发送失败")
			}
			time.Sleep(time.Microsecond * 10)
		}

		start := time.Now()
		for {
			since := time.Since(start)
			wait := time.Second * 5

			if since > wait {
				break
			}
		}
		endflag = true
		Common.LogInfo("conclose")
		for {
			since := time.Since(start)
			wait := time.Second * 6
			if since > wait {
				break
			}
		}
		return
	}
	Common.LogError("ICMP4监听失败")
	RunPing(info, chan_livehost, chan_livehost)
}

func makeIcmp4EchoMsg() ([]byte, error) {
	m := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:  os.Getpid() & 0xffff,
			Seq: 1,
		},
	}
	return m.Marshal(nil)
}

func __icmp6scan(chan_ipv6, chan_livehost chan net.IP) {

}

func __isIP4(ip net.IP) bool {
	return ip.To4() != nil

}

func __isIP6(ip net.IP) bool {
	return !__isIP4(ip)

}

func PingIcmpEchoRequest(ip net.IP) bool {
	return false
}

func RunPing(info *Common.HostInfoList, chan_livehost chan net.IP, chan_may_not_livehost chan net.IP) {
	var wg sync.WaitGroup
	limiter := make(chan struct{}, Common.Args.ThreadPingNum)
	for _, host := range info.IPs {
		wg.Add(1)
		limiter <- struct{}{}
		time.Sleep(time.Microsecond * 10) //防止频繁ping导致cpu占用过高
		go func(host net.IP) {
			defer func() {
				wg.Done()
				<-limiter
			}()

			if PingwithOS_v2(host.String()) {
				chan_livehost <- host
			} else {
				chan_may_not_livehost <- host
			}
		}(host)
	}
	wg.Wait()
	close(chan_may_not_livehost)

}

func PingwithOS_v1(host string) bool {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		command = exec.Command("cmd", "/c", "ping -n 1 -w 1 "+host+" && echo true || echo false")
	case "linux":
		command = exec.Command("/bin/bash", "-c", "ping -c 1 -W 1 "+host+" && echo true || echo false")
	default:
		Common.LogError("不支持的操作系统")
		return false
	}
	var outinfo bytes.Buffer
	command.Stdout = &outinfo
	if err := command.Start(); err != nil {
		return false
	}
	if err := command.Wait(); err != nil {
		return false
	}
	out := outinfo.String()

	return strings.Contains(out, "true") && strings.Count(out, host) > 2

}

func PingwithOS_v2(host string) bool {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("ping", host, "-n", "1", "-w", "200")
	case "linux":
		cmd = exec.Command("ping", host, "-c", "1", "-W", "1")
	case "darwin":
		cmd = exec.Command("ping", host, "-c", "1", "-W", "200")
	case "freebsd":
		cmd = exec.Command("ping", "-c", "1", "-W", "200", host)
	case "openbsd":
		cmd = exec.Command("ping", "-c", "1", "-w", "200", host)
	case "netbsd":
		cmd = exec.Command("ping", "-c", "1", "-w", "2", host)
	default:
		cmd = exec.Command("ping", "-c", "1", host)
	}
	err := cmd.Run()
	if err != nil {
		return false
	}
	return true
}

func maybeDoSomeinit() {
	Common.LogInfo("初始化")
}

type DynamicQueue struct {
	buffer []net.IP // 动态缓冲
	lock   sync.Mutex
}

func (dq *DynamicQueue) Enqueue(v net.IP) {
	dq.lock.Lock()
	dq.buffer = append(dq.buffer, v)
	dq.lock.Unlock()
}

func (dq *DynamicQueue) Dequeue() net.IP {
	dq.lock.Lock()
	defer dq.lock.Unlock()
	if len(dq.buffer) == 0 {
		return nil
	}
	v := dq.buffer[0]
	dq.buffer = dq.buffer[1:]
	return v
}
