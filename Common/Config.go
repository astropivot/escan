package Common

import (
	"flag"
	"net"
	"sync"
)

var OutputMutex sync.Mutex

// var (
// 	HostFile string
// 	PortFile string
// 	Hosts    string
// 	Ports    string
// 	URLs     string

// 	ThreadsNum    int
// 	ThreadPingNum int

//	IsSyncping bool
//	IsPing     bool
//
// )
type HostInfoList struct {
	IPs   []net.IP
	Ports []int
	Urls  string
}

type Hostinfo struct {
	Ip      net.IP
	port    int
	url     string
	infostr []string
}

var (
	OutputFilePath string // 输出文件路径
	OutputFormat   string // 输出格式
)

type args struct {
	HostFile string
	PortFile string
	Hosts    string
	Ports    string
	URLs     string

	Socks5Proxy string

	ThreadsNum       int
	ThreadPingNum    int
	Timeout_portScan int64

	IsSyncping bool
	IsPing     bool
	Isarp      bool
}

var Args = args{}

func (args *args) SetFlag() {
	flag.StringVar(&args.HostFile, "hostfile", "", "指定host文件")
	flag.StringVar(&args.PortFile, "portfile", "", "指定端口文件")
	flag.StringVar(&args.Ports, "ports", "", "指定端口")
	flag.StringVar(&args.Hosts, "hosts", "", "指定host")

	flag.StringVar(&args.Socks5Proxy, "socks5", "", "指定socks5代理")

	flag.StringVar(&OutputFormat, "output_format", "json", "指定输出格式")
	flag.StringVar(&OutputFilePath, "output_file", "./output.json", "指定输出文件路径")

	flag.IntVar(&args.ThreadsNum, "threadsnum", 100, "指定线程数")
	flag.IntVar(&args.ThreadPingNum, "threadpingnum", 100, "指定ping线程数")
	flag.Int64Var(&args.Timeout_portScan, "timeout_portScan", 3, "指定端口扫描超时时间")

	flag.BoolVar(&args.IsPing, "ping", true, "是否ping")
	flag.BoolVar(&args.IsSyncping, "syncping", false, "是否同步ping")
	flag.BoolVar(&args.Isarp, "arp", false, "是否arp")

	flag.Parse()
}
