package Common

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

func Parse(info *Hostinfo) {

}

func Parseinfo(info *Hostinfo) error {
	tmpHosts := make(map[string]struct{})
	if HostFile != "" {
		hosts, err := readfile(HostFile)
		if err != nil {
			return fmt.Errorf("读取host文件失败:%s", err)
		}
		for _, host := range hosts {
			if host != "" {
				if _, ok := tmpHosts[host]; !ok {
					tmpHosts[host] = struct{}{}
					info.Host = append(info.Host, host)

				}
			}
		}
	}
	if Hosts != "" {
		if strings.Contains(Hosts, ",") {
			IPlists := strings.Split(Hosts, ",")
			for _, IP := range IPlists {
				if IP != "" {

				}
			}
		}

	}

	if PortFile != "" {
		ports, err := readfile(PortFile)
		if err != nil {
			return fmt.Errorf("读取端口文件失败:%s", err)
		}
		tmpPorts := make(map[int]struct{})
		for _, port := range ports {
			if port != "" {
				_port := ParsePort(port)
				for _, i := range _port {
					if _, ok := tmpPorts[i]; !ok {
						tmpPorts[i] = struct{}{}
						info.Port = append(info.Port, i)
					}
				}
			}
		}
	}
	return nil
}

func readfile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		LogError(EORROR_OPEN_FILE, filename, err.Error())
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
		LogError(EORROR_READ_FILE, filename, err.Error())
		return nil, err
	}
	LogInfo(SUCCESS_READ_FILE, filename, lineCount)
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

	for i := 0; i < len(mask); i++ {
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
	for i := 0; i < 4; i++ {
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
