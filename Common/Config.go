package Common

import "sync"

var OutputMutex sync.Mutex

var (
	HostFile string
	PortFile string
	Hosts    string
	Ports    string
	URLs     string
)
