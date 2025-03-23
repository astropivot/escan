package main

import Common "escan/Common"

func main() {
	Common.InitLogger()
	var info Common.Hostinfo
	Common.Flag()
	Common.Parse(&info)

}
