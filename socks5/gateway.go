package socks5

import (
	"errors"
	"io"
	"net"
	"slices"
	"sync"

	"github.com/murakmii/nira/log"
)

type (
	Gateway struct {
		listenAddr string
		logger     log.Logger
		connFunc   ConnectorFunc

		stopCh chan struct{}
	}

	// ConnectorFunc is function receives remote host info and proxy on any protocol.
	// Return values are bind address and remote host IO stream.
	ConnectorFunc func(ip net.IP, port uint16, logger log.Logger) (net.IP, uint16, io.ReadWriteCloser, error)
)

func BuildGateway(listenAddr string, logger log.Logger, connFunc ConnectorFunc) *Gateway {
	if logger == nil {
		logger = log.NopLogger
	}

	return &Gateway{
		listenAddr: listenAddr,
		logger:     logger,
		connFunc:   connFunc,
		stopCh:     make(chan struct{}),
	}
}

func (g *Gateway) Addr() string {
	return g.listenAddr
}

// Listen starts accepting connection.
// This method blocks until calling Stop method and all connections closed.
func (g *Gateway) Listen() error {
	listener, err := net.Listen("tcp", g.listenAddr)
	if err != nil {
		return err
	}
	defer listener.Close()

	accepted := make(chan net.Conn)
	go func() {
		g.logger.I("listen on %s", listener.Addr())
		for {
			conn, err := listener.Accept()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					g.logger.E("listener stopped. %s", err)
				}
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
			g.logger.I("stopping...")
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
	g.logger.I("stopped")
	return nil
}

func (g *Gateway) Stop() {
	close(g.stopCh)
}

// handleConn method establishes connection
// and transfer data bidirectionally until connection closed.
func (g *Gateway) handleConn(src net.Conn) {
	dest, err := g.establish(src)
	if err != nil {
		g.logger.E("socks5 establishing failed: %s", err)
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

	g.logger.D("connection closed. err1=%s, err2=%s", errs[0], errs[1])
}

// establish method checks method selection and request message.
// We only accept CONNECT command(no auth) with IPv4 address.
// See: https://datatracker.ietf.org/doc/html/rfc1928
func (g *Gateway) establish(src net.Conn) (io.ReadWriteCloser, error) {
	methods, err := ParseMethodSelection(src)
	if err != nil {
		src.Close()
		return nil, err
	}

	if slices.Index(methods, noAuthMethod) == -1 {
		src.Write(noAcceptableMethodsReply)
		src.Close()
		return nil, errors.New("no acceptable methods")
	}

	if _, err := src.Write(noAuthSelectedReply); err != nil {
		src.Close()
		return nil, err
	}

	addr, port, err := ParseRequest(src)
	if err != nil {
		if protoErr, ok := err.(ErrorReplyCode); ok {
			src.Write(protoErr.ReplyBytes())
		}
		src.Close()
		return nil, err
	}

	bindAddr, bindPort, conn, err := g.connFunc(addr, port, g.logger)
	if err != nil {
		src.Write(UnreachableReply.ReplyBytes())
		src.Close()
		return nil, err
	}

	if _, err := src.Write(NewEstablishedReply(succeededReply, bindAddr, bindPort)); err != nil {
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
