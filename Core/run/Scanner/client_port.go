package scanner

import "net"

type PortClient struct {
	*client
	HandlerClosed func(addr net.IP, port int)
	HandlerOpen   func(addr net.IP, port int)
}
