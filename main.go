package main

import (
	"escan/Common"
	"escan/Core/run"
	"fmt"
	"os"
)

func main() {
	Common.InitLogger()
	var info Common.HostInfoList
	Common.Args.SetFlag()
	fmt.Println("开始解析参数")
	if err := Common.Parse(&info); err != nil {
		Common.LogError("Parse error:%s", err.Error())
		os.Exit(1)
	}
	fmt.Println("参数解析完成,loglevel:", Common.LogLevel)

	if err := Common.InitOutput(); err != nil {
		Common.LogError("InitOutput error:%s", err.Error())
		os.Exit(1)
	}
	if Common.TEST {
		fmt.Println("测试模式")
		_testfunc()
		return
	}
	defer Common.CloseOutput()
	run.Scan(&info)
}

func _testfunc() {
	s := `TCP SMBProgNeg q|\0\0\0\xa4\xff\x53\x4d\x42\x72\0\0\0\0\x08\x01\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\x06\0\0\x01\0\0\x81\0\x02PC NETWORK PROGRAM 1.0\0\x02MICROSOFT NETWORKS 1.03\0\x02MICROSOFT NETWORKS 3.0\0\x02LANMAN1.0\0\x02LM1.2X002\0\x02Samba\0\x02NT LANMAN 1.0\0\x02NT LM 0.12\0|
rarity 4
ports 42,88,135,139,445,660,1025,1027,1031,1112,3006,3900,5000,5009,5432,5555,5600,7461,9102,9103,18182,27000-27010
match netbios-ssn m|^\0\0\0.\xffSMBr\0\0\0\0\x88..\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x01\xff\xff\0\0$|s p/Samba smbd/ v/4/ cpe:/a:samba:samba:4/`
	probe := run.Probe{}
	if err := probe.FromString_(s); err != nil {
		Common.LogDebug(fmt.Sprintf("解析探测器失败: %v", err))
	}
	response := []byte{0x0, 0x0, 0x0, 0x25, 0xff, 0x53, 0x4d, 0x42, 0x72, 0x0, 0x0, 0x0, 0x0, 0x88, 0x3, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x40, 0x6, 0x0, 0x0, 0x1, 0x0, 0x1, 0xff, 0xff, 0x0, 0x0}

	fmt.Println(probe.Matchs)
	for _, match := range *probe.Matchs {
		mach := match.PatternCompiled.Matcher(response, 0)
		if mach.Matches() {
			fmt.Println(match.Service, "匹配成功")
			extr := mach.Extract()
			fmt.Printf("匹配结果: %+v\n", extr)
			exs := mach.ExtractString()
			fmt.Printf("匹配结果: %s\n", exs)
			groupCount := mach.Groups()
			for i := range groupCount {
				fmt.Printf("第%d个分组: %+v\n", i, mach.GroupIndices(i))
				fmt.Printf("第%d个分组: %+s\n", i, mach.Group(i))
				fmt.Printf("第%d个分组: %s\n", i, mach.GroupString(i))
				fmt.Println("======================")
			}

		} else {
			fmt.Println(match.Service, "匹配失败")
		}
		i := run.Info{}
		i.ProcessMatches(response, probe.Matchs)

	}
}
