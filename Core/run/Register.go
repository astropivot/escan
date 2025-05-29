package run

import (
	"escan/Common"
	"escan/Plugins"
)

func init() {
	Common.RegisterPlugin("netbios", Common.ScanPlugin{
		Name:     "NetBIOS",
		Ports:    []int{139},
		ScanFunc: Plugins.NetBIOS,
	})
	Common.RegisterPlugin("ssh", Common.ScanPlugin{
		Name:     "SSH",
		Ports:    []int{22, 2222},
		ScanFunc: Plugins.SshScan,
	})

	Common.RegisterPlugin("smb", Common.ScanPlugin{
		Name:     "SMB",
		Ports:    []int{445},
		ScanFunc: Plugins.SmbScan,
	})
	Common.RegisterPlugin("mysql", Common.ScanPlugin{
		Name:     "MySQL",
		Ports:    []int{3306},
		ScanFunc: Plugins.MysqlScan,
	})
	Common.RegisterPlugin("mssql", Common.ScanPlugin{
		Name:     "MSSQL",
		Ports:    []int{1433, 1434},
		ScanFunc: Plugins.MssqlScan,
	})
	Common.RegisterPlugin("findnet", Common.ScanPlugin{
		Name:     "FindNet",
		Ports:    []int{135},
		ScanFunc: Plugins.Findnet,
	})
}
