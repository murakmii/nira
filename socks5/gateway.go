package socks5

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

type (
	Gateway struct {
		listenAddr string
		stopCh     chan struct{}
		connFunc   ConnectorFunc
	}

	ConnectorFunc func(ip net.IP, port uint16) (net.IP, uint16, io.ReadWriteCloser, error)
)

func BuildGateway(listenAddr string, connFunc ConnectorFunc) *Gateway {
	return &Gateway{
		listenAddr: listenAddr,
		stopCh:     make(chan struct{}),
		connFunc:   connFunc,
	}
}

func (g *Gateway) Addr() string {
	return g.listenAddr
}

func (g *Gateway) Listen() error {
	listener, err := net.Listen("tcp", g.listenAddr)
	if err != nil {
		return err
	}
	defer listener.Close()

	accepted := make(chan net.Conn)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				close(accepted)
				break
			}
			accepted <- conn
		}
	}()

	liveConn := &sync.WaitGroup{}
	for accepting := true; accepting; {
		select {
		case <-g.stopCh:
			listener.Close()
		case conn, ok := <-accepted:
			if !ok {
				accepting = false
			} else {
				liveConn.Add(1)
				go func() {
					g.handleConn(conn)
					liveConn.Done()
				}()
			}
		}
	}

	liveConn.Wait()
	return nil
}

func (g *Gateway) Stop() {
	close(g.stopCh)
}

func (g *Gateway) handleConn(src net.Conn) {
	dest, err := g.negotiate(src)
	if err != nil {
		fmt.Printf("negotiation error: %s\n", err)
		return
	}

	errCh := make(chan error, 2)
	go transfer(src, dest, errCh)
	go transfer(dest, src, errCh)

	var errs []error
	needClose := true

	for len(errs) < 2 {
		select {
		case err := <-errCh:
			errs = append(errs, err)
			if len(errs) == 1 && needClose {
				src.Close()
				dest.Close()
			}

		case <-g.stopCh:
			src.Close()
			dest.Close()
			needClose = false
		}
	}
}

func (g *Gateway) negotiate(src net.Conn) (io.ReadWriteCloser, error) {
	methods, err := ParseMethodSelection(src)
	if err != nil {
		src.Close()
		return nil, err
	}

	if !bytes.Contains(methods, []byte{0x00}) {
		src.Write([]byte{0x05, 0xFF})
		src.Close()
		return nil, errors.New("no acceptable methods")
	}

	if _, err := src.Write([]byte{0x05, 0x00}); err != nil {
		src.Close()
		return nil, err
	}

	addr, port, err := ParseRequest(src)
	if err != nil {
		if protoErr, ok := err.(*ProtocolError); ok {
			src.Write(protoErr.ToErrorReply())
			src.Close()
			return nil, err
		}
	}

	bindAddr, bindPort, conn, err := g.connFunc(addr, port)
	if err != nil {
		src.Write(NewProtocolError("failed to connect remote host", 0x03).ToErrorReply())
		src.Close()
		return nil, err
	}

	reply := make([]byte, 10)
	reply[0] = 0x05
	reply[1] = 0x00
	reply[3] = 0x01
	copy(reply[4:], bindAddr.To4())
	binary.BigEndian.PutUint16(reply[8:], bindPort)

	if _, err := src.Write(reply); err != nil {
		src.Close()
		conn.Close()
		return nil, err
	}

	return conn, nil
}

func transfer(from io.Reader, to io.Writer, errCh chan<- error) {
	buf := make([]byte, 2048)
	for {
		readBytes, err := from.Read(buf)
		if err != nil {
			errCh <- err
			break
		}

		if _, err := to.Write(buf[:readBytes]); err != nil {
			errCh <- err
			break
		}
	}
}
