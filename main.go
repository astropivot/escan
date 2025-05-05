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
	Common.Parse(&info)
	if err := Common.InitOutput(); err != nil {
		Common.LogError("InitOutput error:%s", err.Error())
		os.Exit(1)
	}
	defer Common.CloseOutput()
	run.Scan(&info)
}
