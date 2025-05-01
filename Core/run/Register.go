package run

import (
	"escan/Common"
	"escan/Plugins"
)

func init() {
	Common.RegisterPlugin("ssh", Common.ScanPlugin{
		Name:     "SSH",
		Ports:    []int{22, 2222},
		ScanFunc: Plugins.SshScan,
	})
}
