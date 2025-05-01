package Common

import (
	"bufio"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
)

func Parse(info *HostInfoList) {
	Parseinfo(info)
}

func Parseinfo(info *HostInfoList) {
	readToInfoHosts(info)
	readToInfoPort(info)
}

func readToInfoHosts(info *HostInfoList) {
	tmpHosts := make(map[netip.Addr]struct{})
	defer func() {
		info.IPs = make([]netip.Addr, len(tmpHosts))
		i := 0
		for ip := range tmpHosts {
			info.IPs[i] = ip
			i++
		}
	}()
	if Args.Hosts != "" {
		if strings.Contains(Args.Hosts, ",") {
			IPlists := strings.SplitSeq(Args.Hosts, ",")
			for IP := range IPlists {
				if IP != "" {
					ips := ParseHost(IP)
					for _, i := range ips {
						ip, err := netip.ParseAddr(i)
						if err != nil {
							continue
						}
						if _, ok := tmpHosts[ip]; !ok {
							tmpHosts[ip] = struct{}{}
						}
					}
				}
			}
		} else {
			ips := ParseHost(Args.Hosts)
			for _, i := range ips {
				ip, err := netip.ParseAddr(i)
				if err != nil {
					continue
				}
				if _, ok := tmpHosts[ip]; !ok {
					tmpHosts[ip] = struct{}{}
				}
			}
		}
	}
	if Args.HostFile != "" {
		hosts, err := readfile(Args.HostFile)
		if err != nil {
			LogError("读取host文件失败:%s", err)
			return
		}
		for _, host := range hosts {
			if host != "" {
				ips := ParseHost(host)
				for _, i := range ips {
					ip, err := netip.ParseAddr(i)
					if err != nil {
						continue
					}
					if _, ok := tmpHosts[ip]; !ok {
						tmpHosts[ip] = struct{}{}
					}
				}
			}
		}
	}
}

func readToInfoPort(info *HostInfoList) {
	tmpPorts := make(map[int]struct{})
	defer func() {
		if len(tmpPorts) == 0 {
			info.Ports = []int{20, 21, 22, 23, 80, 81, 110, 135, 139, 143, 389, 443, 445, 502, 873, 993, 995, 1433, 1521, 3306, 5432, 5672, 6379, 7001, 7687, 8000, 8005, 8009, 8080, 8089, 8443, 9000, 9042, 9092, 9200, 10051, 11211, 15672, 27017, 61616}
		} else {
			info.Ports = make([]int, len(tmpPorts))
			i := 0
			for port := range tmpPorts {
				info.Ports[i] = port
				i++
			}
		}
	}()
	if Args.Ports != "" {
		if strings.Contains(Args.Ports, ",") {
			_Ports := strings.SplitSeq(Args.Ports, ",")
			for _Port := range _Ports {
				ports := ParsePort(_Port)
				for _, _port := range ports {
					if _, ok := tmpPorts[_port]; !ok {
						tmpPorts[_port] = struct{}{}
					}
				}
			}
		}
	}
	if Args.PortFile != "" {
		ports, err := readfile(Args.PortFile)
		if err != nil {
			LogError("读取端口文件失败:%s", err)
			return
		}
		for _, port := range ports {
			if port != "" {
				_port := ParsePort(port)
				for _, i := range _port {
					if _, ok := tmpPorts[i]; !ok {
						tmpPorts[i] = struct{}{}
					}
				}
			}
		}
	}

}

func readfile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		LogError("打开文件失败:%s,%s", filename, err.Error())
		return nil, err
	}
	defer file.Close()
	var content []string
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	lineCount := 0
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" {
			content = append(content, text)
			lineCount++
		}
	}
	if err := scanner.Err(); err != nil {
		LogError("读取文件失败:%s,%s", filename, err.Error())
		return nil, err
	}
	LogInfo("读取文件:%s,行数:%d", filename, lineCount)
	return content, nil
}

func ParsePort(ports string) []int {
	if ports == "" {
		return nil
	}

	port_range := strings.TrimSpace(ports)
	if port_range == "" {
		return nil
	}
	if strings.Contains(port_range, "-") {
		ranges := strings.Split(port_range, "-")
		if len(ranges) != 2 {
			LogError("端口范围错误:%s", port_range)
			return nil
		}
		start, err_startport := strconv.Atoi(ranges[0])
		end, err_endport := strconv.Atoi(ranges[1])
		if err_startport != nil || err_endport != nil {
			LogError("端口解析错误:%s", port_range)
			return nil
		}
		if start > end {
			start, end = end, start
		}
		if start < 1 || start > 65535 || end < 1 || end > 65535 {
			LogError("端口范围错误:%s", port_range)
			return nil
		}
		var _ports []int
		for i := start; i <= end; i++ {
			_ports = append(_ports, i)
		}
		return _ports
	}
	port, err := strconv.Atoi(port_range)
	if err != nil {
		LogError("端口解析错误:%s", port_range)
		return nil
	}
	if port < 1 || port > 65535 {
		LogError("端口范围错误:%s", port_range)
		return nil
	}
	return []int{port}
}

func ParseHost(host string) []string {
	reg := regexp.MustCompile(`[a-zA-Z]+`)
	switch {
	case strings.Contains(host, "/"):
		return ParseCIDRip(host)
	case reg.MatchString(host):
		return []string{host}
	default:
		_ip := net.ParseIP(host)
		if _ip != nil {
			return []string{host}
		} else {
			LogError("解析host错误:%s", host)
			return nil
		}
	}
}

func ParseCIDRip(host string) []string {
	_, ipnet, err := net.ParseCIDR(host)
	if err != nil {
		LogError("解析CIDR错误:%s,%s", host, err)
	}
	ipRange := IPRange(ipnet)
	LogInfo("解析CIDR:%s,范围:%s", host, ipnet.String())
	return ipRange
}

func IPRange(c *net.IPNet) []string {
	start := c.IP.String()
	mask := c.Mask
	bcst := make(net.IP, len(c.IP))
	copy(bcst, c.IP)

	for i := range mask {
		ipIdx := len(bcst) - i - 1
		bcst[ipIdx] = c.IP[ipIdx] | ^mask[len(mask)-i-1]
	}
	end := bcst.String()
	splitip1 := strings.Split(start, ".")
	splitip2 := strings.Split(end, ".")
	if len(splitip1) != 4 || len(splitip2) != 4 {
		LogError("IP范围错误:%s", c.String())
		return nil
	}
	from, to := [4]int{}, [4]int{}
	for i := range 4 {
		ip1, err1 := strconv.Atoi(splitip1[i])
		ip2, err2 := strconv.Atoi(splitip2[i])
		if err1 != nil || err2 != nil {
			LogError("IP范围错误:%s", c.String())
			return nil
		}
		from[i], to[i] = ip1, ip2
	}
	startNum := from[0]<<24 | from[1]<<16 | from[2]<<8 | from[3]
	endNum := to[0]<<24 | to[1]<<16 | to[2]<<8 | to[3]
	var allIP []string
	for num := startNum; num <= endNum; num++ {
		ip := strconv.Itoa((num>>24)&0xff) + "." +
			strconv.Itoa((num>>16)&0xff) + "." +
			strconv.Itoa((num>>8)&0xff) + "." +
			strconv.Itoa((num)&0xff)
		allIP = append(allIP, ip)
	}
	LogInfo("ip范围 from:%s to:%s", start, end)
	return allIP
}
