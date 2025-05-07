package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	snapshotLen int32 = 65536
	promiscuous bool  = false
	err         error
	timeout     = 1 * time.Second
	handle      *pcap.Handle
)

func main() {
	var targetIP string
	var ports string
	flag.StringVar(&targetIP, "ip", "", "Target IP address to scan")
	// flag.StringVar(&ports, "p", "", "Port(s) to scan (e.g. 80,443,1-1024)")
	flag.Parse()

	if targetIP == "" || ports == "" {
		fmt.Println("Usage: synscan -ip <target-ip> -p <port-range>")
		os.Exit(1)
	}

	// 解析端口范围
	// portList, err := parsePorts(ports)
	// if err != nil {
	// 	fmt.Printf("Failed to parse ports: %v\n", err)
	// 	os.Exit(1)
	// }
	portList := []int{20, 21, 22, 23, 80, 81, 110, 135, 139, 143, 389, 443, 445, 502, 873, 993, 995, 1433, 1521, 3306, 5432, 5672, 6379, 7001, 7687, 8000, 8005, 8009, 8080, 8089, 8443, 9000, 9042, 9092, 9200, 10051, 11211, 15672, 27017, 61616}

	// 获取本地IP和网络接口
	localIP, device, err := getLocalInterface(targetIP)
	if err != nil {
		fmt.Printf("Failed to get local interface: %v\n", err)
		os.Exit(1)
	}

	// 打开网络接口
	handle, err = pcap.OpenLive(device.Name, snapshotLen, promiscuous, timeout)
	if err != nil {
		fmt.Printf("Error opening device %s: %v\n", device.Name, err)
		os.Exit(1)
	}
	defer handle.Close()

	// 启动goroutine捕获响应
	responseChan := make(chan int)
	go captureSynAck(handle, targetIP, responseChan)

	// 发送SYN包到每个端口
	for _, port := range portList {
		err := sendSynPacket(localIP, net.ParseIP(targetIP), port)
		if err != nil {
			fmt.Printf("Error sending SYN packet to port %d: %v\n", port, err)
		}
	}

	// 等待响应
	time.Sleep(2 * time.Second)
	close(responseChan)

	// 收集结果
	var openPorts []int
	for port := range responseChan {
		openPorts = append(openPorts, port)
	}

	fmt.Println("Open ports:")
	for _, port := range openPorts {
		fmt.Println(port)
	}
}

// parsePorts解析端口字符串
func parsePorts(portsStr string) ([]int, error) {
	var ports []int
	ranges := strings.Split(portsStr, ",")
	for _, r := range ranges {
		if strings.Contains(r, "-") {
			parts := strings.Split(r, "-")
			if len(parts) != 2 {
				return nil, errors.New("invalid port range")
			}
			start, err := strconv.Atoi(parts[0])
			if err != nil {
				return nil, err
			}
			end, err := strconv.Atoi(parts[1])
			if err != nil {
				return nil, err
			}
			for i := start; i <= end; i++ {
				ports = append(ports, i)
			}
		} else {
			port, err := strconv.Atoi(r)
			if err != nil {
				return nil, err
			}
			ports = append(ports, port)
		}
	}
	return ports, nil
}

// getLocalInterface获取本地网络接口和IP
func getLocalInterface(targetIP string) (net.IP, *net.Interface, error) {
	targetAddr := net.ParseIP(targetIP)
	if targetAddr == nil {
		return nil, nil, errors.New("invalid target IP")
	}

	// 连接到目标以确定出口接口
	conn, err := net.Dial("udp", targetIP+":80")
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	localIP := localAddr.IP

	// 获取网络接口
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if ok && ipNet.IP.Equal(localIP) {
				return localIP, &iface, nil
			}
		}
	}

	return nil, nil, errors.New("interface not found")
}

// sendSynPacket发送SYN包
func sendSynPacket(srcIP, dstIP net.IP, dstPort int) error {
	// 以太网层（自动填充）
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // 由pcap自动填充
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // 由pcap自动填充
		EthernetType: layers.EthernetTypeIPv4,
	}

	// IP层
	ip := &layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	// TCP层
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(54321), // 固定源端口
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
		Window:  14600,
		Seq:     1105024978, // 随机序列号
	}
	tcp.SetNetworkLayerForChecksum(ip)

	// 序列化包
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp)
	if err != nil {
		return err
	}

	// 发送数据包
	return handle.WritePacketData(buf.Bytes())
}

// captureSynAck捕获SYN-ACK响应
func captureSynAck(handle *pcap.Handle, targetIP string, results chan<- int) {
	// 设置过滤器
	filter := fmt.Sprintf("tcp and src host %s and dst port 54321", targetIP)
	err := handle.SetBPFFilter(filter)
	if err != nil {
		fmt.Printf("Error setting filter: %v\n", err)
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp.SYN && tcp.ACK {
			results <- int(tcp.SrcPort)
		}
	}
}
