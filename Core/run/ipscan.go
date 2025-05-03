package run

import (
	"bytes"
	"escan/Common"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	__LIVE_HOST_LEN           = 512
	__MAYBE_NOT_LIVE_HOST_LEN = 512
)

func CheckLive(info *Common.HostInfoList) chan netip.Addr {
	chan_livehost := make(chan netip.Addr, __LIVE_HOST_LEN)
	chan_may_not_livehost := make(chan netip.Addr, __MAYBE_NOT_LIVE_HOST_LEN)
	if !Common.IsOnlyarp {
		if Common.Args.IsPing {
			Common.LogInfo("开始ping扫描")
			go RunPing(info.IPs, chan_livehost, chan_may_not_livehost)
			go RunArpScan(chan_livehost, chan_may_not_livehost)
		} else {
			Common.LogInfo("开始ICMP扫描")
			go RunICMP(info.IPs, chan_livehost, chan_may_not_livehost)
			go RunArpScan(chan_livehost, chan_may_not_livehost)
		}
	} else {
		Common.LogInfo("跳过ip扫描,只进行arp扫描")
		go gennotlivehost(info.IPs, chan_may_not_livehost)
		go RunArpScan(chan_livehost, chan_may_not_livehost)
	}
	Common.LogInfo("返回chan")
	return chan_livehost
}

func gennotlivehost(iplist []netip.Addr, chan_may_not_livehost chan netip.Addr) {
	for _, ip := range iplist {
		chan_may_not_livehost <- ip
	}
	close(chan_may_not_livehost)
}

func cousumechan(chan_may_not_livehost chan netip.Addr, chan_livehost chan netip.Addr) {
	CousumeAchan(chan_may_not_livehost)
	close(chan_livehost)
}

func RunArpScan(chan_livehost chan netip.Addr, chan_may_not_livehost chan netip.Addr) {
	if Common.Args.Isarp {
		Common.LogInfo("开始arp扫描")
		ScanARP(chan_may_not_livehost, chan_livehost)
		close(chan_livehost)
		Common.LogInfo("arp扫描结束")
	} else {
		cousumechan(chan_may_not_livehost, chan_livehost)
		Common.LogInfo("arp扫描跳过")
	}
}

func PingIcmpEchoRequest(ip net.IP) bool {
	return false
}

func RunPing(iplist []netip.Addr, chan_livehost chan netip.Addr, chan_may_not_livehost chan netip.Addr) {
	var wg sync.WaitGroup
	limiter := make(chan struct{}, Common.Args.ThreadPingNum)
	for _, host := range iplist {
		wg.Add(1)
		limiter <- struct{}{}
		time.Sleep(time.Microsecond * 10) // 防止频繁ping导致cpu占用过高

		go func(host netip.Addr) {
			defer func() {
				wg.Done()
				<-limiter
			}()

			if PingwithOS_v2(host.String()) {
				IsExistIPwithAdd(host)
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
	return err == nil
	//	if err != nil {
	//		return false
	//	}
	//	return true
}
