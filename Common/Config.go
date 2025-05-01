package Common

import (
	"flag"
	"net/netip"
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
	IPs   []netip.Addr
	Ports []int
	Urls  string
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

var (
	DisableBrute    bool   // 是否禁用暴力破解模块
	MaxRetries      int    // 连接失败最大重试次数
	Timeout         int64  // 单个扫描操作超时时间(秒)
	GlobalTimeout   int64  // 整体扫描超时时间(秒)
	SshKeyPath      string // SSH私钥文件路径
	ModuleThreadNum int    // 模块内部线程数
)

var Args = args{}

func (args *args) SetFlag() {
	flag.StringVar(&args.HostFile, "hostfile", "", "指定host文件")
	flag.StringVar(&args.PortFile, "portfile", "", "指定端口文件")
	flag.StringVar(&args.Ports, "ports", "", "指定端口")
	flag.StringVar(&args.Hosts, "hosts", "", "指定host")

	flag.StringVar(&args.Socks5Proxy, "socks5", "", "指定socks5代理")

	flag.StringVar(&OutputFormat, "output_format", "json", "指定输出格式")
	flag.StringVar(&OutputFilePath, "output_file", "./output.json", "指定输出文件路径")
	flag.StringVar(&SshKeyPath, "ssh_key_path", "", "指定SSH私钥文件路径")

	flag.IntVar(&args.ThreadsNum, "threadsnum", 100, "指定线程数")
	flag.IntVar(&args.ThreadPingNum, "threadpingnum", 100, "指定ping线程数")
	flag.Int64Var(&args.Timeout_portScan, "timeout_portScan", 3, "指定端口扫描超时时间")
	flag.IntVar(&MaxRetries, "max_retries", 3, "指定连接失败最大重试次数")
	flag.Int64Var(&Timeout, "timeout", 3, "指定单个扫描操作超时时间(秒)")
	flag.Int64Var(&GlobalTimeout, "global_timeout", 180, "指定整体扫描超时时间(秒)")
	flag.IntVar(&ModuleThreadNum, "module_thread_num", 10, "指定模块内部线程数")

	flag.BoolVar(&args.IsSyncping, "syncping", false, "是否同步ping")
	flag.BoolVar(&args.Isarp, "arp", false, "是否arp")
	flag.BoolVar(&DisableBrute, "disable_brute", false, "是否禁用暴力破解模块")

	flag.Parse()
}

var Userdict = map[string][]string{
	"ftp":        {"ftp", "admin", "www", "web", "root", "db", "wwwroot", "data"},
	"mysql":      {"root", "mysql"},
	"mssql":      {"sa", "sql"},
	"smb":        {"administrator", "admin", "guest"},
	"rdp":        {"administrator", "admin", "guest"},
	"postgresql": {"postgres", "admin"},
	"ssh":        {"root", "admin"},
	"mongodb":    {"root", "admin"},
	"oracle":     {"sys", "system", "admin", "test", "web", "orcl"},
	"telnet":     {"root", "admin", "test"},
	"elastic":    {"elastic", "admin", "kibana"},
	"rabbitmq":   {"guest", "admin", "administrator", "rabbit", "rabbitmq", "root"},
	"kafka":      {"admin", "kafka", "root", "test"},
	"activemq":   {"admin", "root", "activemq", "system", "user"},
	"ldap":       {"admin", "administrator", "root", "cn=admin", "cn=administrator", "cn=manager"},
	"smtp":       {"admin", "root", "postmaster", "mail", "smtp", "administrator"},
	"imap":       {"admin", "mail", "postmaster", "root", "user", "test"},
	"pop3":       {"admin", "root", "mail", "user", "test", "postmaster"},
	"zabbix":     {"Admin", "admin", "guest", "user"},
	"rsync":      {"rsync", "root", "admin", "backup"},
	"cassandra":  {"cassandra", "admin", "root", "system"},
	"neo4j":      {"neo4j", "admin", "root", "test"},
}

var Passwords = []string{"123456", "admin", "admin123", "root", "", "pass123", "pass@123", "password", "Password", "P@ssword123", "123123", "654321", "111111", "123", "1", "admin@123", "Admin@123", "admin123!@#", "{user}", "{user}1", "{user}111", "{user}123", "{user}@123", "{user}_123", "{user}#123", "{user}@111", "{user}@2019", "{user}@123#4", "P@ssw0rd!", "P@ssw0rd", "Passw0rd", "qwe123", "12345678", "test", "test123", "123qwe", "123qwe!@#", "123456789", "123321", "666666", "a123456.", "123456~a", "123456!a", "000000", "1234567890", "8888888", "!QAZ2wsx", "1qaz2wsx", "abc123", "abc123456", "1qaz@WSX", "a11111", "a12345", "Aa1234", "Aa1234.", "Aa12345", "a123456", "a123123", "Aa123123", "Aa123456", "Aa12345.", "sysadmin", "system", "1qaz!QAZ", "2wsx@WSX", "qwe123!@#", "Aa123456!", "A123456s!", "sa123456", "1q2w3e", "Charge123", "Aa123456789", "elastic123"}
