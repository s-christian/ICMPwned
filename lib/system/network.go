// For functions designed to retrieve system information.
package system

import (
	"net"
	"os"

	"github.com/s-christian/icmpwned/lib/logger"
	"github.com/s-christian/icmpwned/lib/utils"
)

const (
	tryIP string = "172.23.252.10"

	ERR_INTERFACE int = 40
)

/*
	Get preferred outbound IP address of the local machine.
*/
func GetHostIP() (hostIP net.IP) {
	/* --- commented out for testing
	netInterfaceAddresses, err := net.InterfaceAddrs()
	if err != nil {
		logger.LogError(err)
		os.Exit(ERR_INTERFACE)
	}

	for _, netInterfaceAddress := range netInterfaceAddresses {
		networkIp, ok := netInterfaceAddress.(*net.IPNet)
		if ok && !networkIp.IP.IsLoopback() && networkIp.IP.To4() != nil {
			hostIP = networkIp.IP
			return
		}
	}

	return
	*/

	// --- Older method ---
	// Because it uses UDP, the destination doesn't actually have to exist.
	// This will give us the IP address we would normally use to connect out.
	//garbageIP := "192.0.2.100"

	conn, err := net.Dial("udp", tryIP+":80")
	if err != nil {
		logger.LogError(err)
		os.Exit(ERR_INTERFACE)
	}
	defer utils.Close(conn)

	// We only want the IP, not "IP:port"
	hostIP = conn.LocalAddr().(*net.UDPAddr).IP

	return
}
