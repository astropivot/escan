package run

import (
	"context"
	"escan/Common"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var (
	_ExistIP     = make(map[string]struct{})
	_lockExistIP = sync.Mutex{}
)

func isExistIP(ip net.IP) bool {
	_lockExistIP.Lock()
	defer _lockExistIP.Unlock()
	_, ok := _ExistIP[ip.String()]
	return ok
}

func RunICMP(iplist []net.IP, chan_live_result chan net.IP, chan_may_not_live chan net.IP) {
	con4, con6, err := initListeners()
	if err != nil {
		_runICMP(iplist, chan_live_result, con4, con6)
		for _, ip := range iplist {
			if _, ok := _ExistIP[ip.String()]; !ok {
				chan_may_not_live <- ip
			}
		}
		return
	}
	Common.LogError("icmp扫描失败,使用ping扫描")
	RunPing(iplist, chan_live_result, chan_may_not_live)
}

func switchIP(ip net.IP) (net.Addr, int) {
	if ip.To4() == nil {
		return &net.IPAddr{IP: ip}, ProtocolICMPv6
	}
	return &net.IPAddr{IP: ip}, ProtocolICMPv4
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

func _runICMP(iplist []net.IP, chan_live_result chan net.IP, con4, con6 *icmp.PacketConn) {
	defer con4.Close()
	defer con6.Close()
	ctx, cancel := context.WithCancel(context.Background())
	go processResponse(ctx, con4, ProtocolICMPv4, chan_live_result)
	go processResponse(ctx, con6, ProtocolICMPv6, chan_live_result)

	sem := make(chan struct{}, MaxParallel)
	for _, ip := range iplist {
		sem <- struct{}{}
		go func(ip net.IP) {
			defer func() { <-sem }()
			addr, proto := switchIP(ip)
			pkt := buildICMPPacket(proto)
			wb, _ := pkt.Marshal(nil)
			if proto == ProtocolICMPv4 {
				con4.WriteTo(wb, addr)
			} else {
				con6.WriteTo(wb, addr)
			}
		}(ip)
	}
	timer := time.NewTimer(Timeout * 3)
	<-timer.C
	cancel()
}

const (
	ProtocolICMPv4 = 1
	ProtocolICMPv6 = 58
	Timeout        = 3 * time.Second
	MaxParallel    = 100 // 并发控制
)

func processResponse(ctx context.Context, conn *icmp.PacketConn, proto int, chan_live_result chan net.IP) {
	for {
		select {
		case <-ctx.Done():
			Common.LogDebug("processResponse exit")
			return
		default:
			buf := make([]byte, 1500)
			conn.SetReadDeadline(time.Now().Add(Timeout))
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				continue
			}
			msg, err := icmp.ParseMessage(proto, buf[:n])
			if err != nil || msg.Type != responseType(proto) {
				continue
			}
			ip := net.IP(addr.String())
			if isExistIP(ip) {
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
