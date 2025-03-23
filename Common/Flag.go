package Common

import (
	"flag"
)

func Flag() {
	flag.StringVar(&HostFile, "hostfile", "", "指定host文件")
	flag.StringVar(&PortFile, "portfile", "", "指定端口文件")
	flag.StringVar(&Ports, "ports", "", "指定端口")
	flag.StringVar(&Hosts, "hosts", "", "指定host")
	flag.Parse()
}
