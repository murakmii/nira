package connector

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/murakmii/nira/log"
)

// TCP is ConnectorFunc implementation to proxy on TCP.
// This function is unnecessary for Tor client, but we use this for unit test.
func TCP(ip net.IP, port uint16, logger log.Logger) (net.IP, uint16, io.ReadWriteCloser, error) {
	addr := fmt.Sprintf("%s:%d", ip.String(), port)
	logger.D("TCP connector: connect to %s", addr)

	conn, err := net.DialTimeout("tcp4", addr, 5*time.Second)
	if err != nil {
		return nil, 0, nil, err
	}

	bindAddr := conn.LocalAddr().(*net.TCPAddr)
	return bindAddr.IP, uint16(bindAddr.Port), conn, nil
}
