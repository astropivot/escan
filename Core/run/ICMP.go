package run

import (
	"context"
	"escan/Common"
	"net"
	"os"
	"sync"
	"time"

	"net/netip"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var (
	_ExistIP     = make(map[netip.Addr]struct{})
	_lockExistIP = sync.Mutex{}
)

func isExistIPwithAdd(ip netip.Addr) bool {
	_lockExistIP.Lock()
	defer _lockExistIP.Unlock()
	_, ok := _ExistIP[ip]
	if !ok {
		_ExistIP[ip] = struct{}{}
	}
	return ok
}

func RunICMP(iplist []netip.Addr, chan_live_result chan netip.Addr, chan_may_not_live chan netip.Addr) {
	con4, con6, err := initListeners()
	if err == nil {
		_runICMP(iplist, chan_live_result, con4, con6)
		for _, ip := range iplist {
			if _, ok := _ExistIP[ip]; !ok {
				chan_may_not_live <- ip
			}
		}
		close(chan_may_not_live)
		Common.LogDebug("icmp扫描完成")
		return
	}
	Common.LogDebug("initListeners 失败: %s", err.Error())
	Common.LogError("icmp扫描失败,使用ping扫描")
	RunPing(iplist, chan_live_result, chan_may_not_live)
}

func switchIP(ip netip.Addr) (net.Addr, int) {
	if ip.Is6() {
		return &net.IPAddr{IP: net.IP(ip.AsSlice())}, ProtocolICMPv6
	}
	return &net.IPAddr{IP: net.IP(ip.AsSlice())}, ProtocolICMPv4
}

func buildICMPPacket(proto int) *icmp.Message {
	switch proto {
	case ProtocolICMPv4:
		return &icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{
				ID:   os.Getpid() & 0xffff,
				Seq:  1,
				Data: []byte("SCAN_PROBE"),
			},
		}
	case ProtocolICMPv6:
		return &icmp.Message{
			Type: ipv6.ICMPTypeEchoRequest,
			Code: 0,
			Body: &icmp.Echo{
				ID:   os.Getpid() & 0xffff,
				Seq:  1,
				Data: []byte("SCAN_PROBE"),
			},
		}
	}
	return nil
}

func _runICMP(iplist []netip.Addr, chan_live_result chan netip.Addr, con4, con6 *icmp.PacketConn) {
	ctx, cancel := context.WithCancel(context.Background())
	wg := sync.WaitGroup{}
	wg.Add(1)
	go processResponse(ctx, &wg, con4, ProtocolICMPv4, chan_live_result)
	// go processResponse(ctx, &wg, con6, ProtocolICMPv6, chan_live_result)

	sem := make(chan struct{}, MaxParallel)
	for _, ip := range iplist {
		sem <- struct{}{}
		go func(ip netip.Addr) {
			addr, proto := switchIP(ip)
			pkt := buildICMPPacket(proto)
			wb, _ := pkt.Marshal(nil)
			if proto == ProtocolICMPv4 {
				con4.WriteTo(wb, addr)
			} else {
				con6.WriteTo(wb, addr)
			}
			// Common.LogDebug("send icmp packet to %s", ip.String())
			<-sem
		}(ip)
		// time.Sleep(10 * time.Millisecond)

	}
	Common.LogDebug("wait for icmp response")
	timer := time.NewTimer(Timeout)
	<-timer.C
	cancel()
	wg.Wait()
}

const (
	ProtocolICMPv4 = 1
	ProtocolICMPv6 = 58
	Timeout        = 3 * time.Second
	MaxParallel    = 100 // 并发控制
)

func processResponse(ctx context.Context, wg *sync.WaitGroup, conn *icmp.PacketConn, proto int, chan_live_result chan netip.Addr) {
	defer conn.Close()
	for {
		select {
		case <-ctx.Done():
			wg.Done()
			Common.LogDebug("processResponse exit")
			return
		default:
			buf := make([]byte, 100)
			conn.SetReadDeadline(time.Now().Add(Timeout))
			_, addr, err := conn.ReadFrom(buf)
			if err != nil {
				Common.LogDebug("err: %s", err.Error())
				continue
			}
			ip, err := netip.ParseAddr(addr.String())
			if err != nil {
				Common.LogDebug("err: %s", err.Error())
				continue
			}
			if !isExistIPwithAdd(ip) {
				chan_live_result <- ip
			}
		}
	}
}

func responseType(proto int) icmp.Type {
	if proto == ProtocolICMPv4 {
		return ipv4.ICMPTypeEchoReply
	}
	return ipv6.ICMPTypeEchoReply
}

func initListeners() (*icmp.PacketConn, *icmp.PacketConn, error) {
	conn4, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		Common.LogError("IPV4 listener error: %v\n", err.Error())
		return nil, nil, err
	}
	conn6, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		Common.LogError("IPv6 listener error: %v\n ", err.Error())
		defer conn4.Close()
		return nil, nil, err
	}
	return conn4, conn6, nil
}
