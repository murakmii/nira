package connector

import (
	"fmt"
	"io"
	"net"
	"time"
)

func TCP(ip net.IP, port uint16) (net.IP, uint16, io.ReadWriteCloser, error) {
	addr := fmt.Sprintf("%s:%d", ip.String(), port)

	conn, err := net.DialTimeout("tcp4", addr, 5*time.Second)
	if err != nil {
		return nil, 0, nil, err
	}

	bindAddr := conn.LocalAddr().(*net.TCPAddr)
	return bindAddr.IP, uint16(bindAddr.Port), conn, nil
}
