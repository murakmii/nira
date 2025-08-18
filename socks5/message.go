package socks5

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
)

type (
	ErrorReplyCode byte
)

const (
	noAuthMethod   byte = 0x00
	succeededReply byte = 0x00

	FailureReply         ErrorReplyCode = 0x01
	UnreachableReply     ErrorReplyCode = 0x04
	CmdNotSupportedReply ErrorReplyCode = 0x07
	AddrTypeNotSupported ErrorReplyCode = 0x08
)

var (
	noAuthSelectedReply      = []byte{0x05, 0x00}
	noAcceptableMethodsReply = []byte{0x05, 0xFF}
)

func (repCode ErrorReplyCode) Error() string {
	switch repCode {
	case FailureReply:
		return "general SOCKS server failure"
	case UnreachableReply:
		return "Host unreachable"
	case CmdNotSupportedReply:
		return "Command not supported"
	case AddrTypeNotSupported:
		return "Address type not supported"
	default:
		return "Unknown reply code"
	}
}

func (repCode ErrorReplyCode) ReplyBytes() []byte {
	return NewEstablishedReply(byte(repCode), nil, 0)
}

func NewEstablishedReply(req byte, ip net.IP, port uint16) []byte {
	reply := make([]byte, 10)
	reply[0] = 0x05
	reply[1] = req
	reply[3] = 0x01

	if ip != nil {
		copy(reply[4:], ip.To4())
	}
	if port != 0 {
		binary.BigEndian.PutUint16(reply[8:], port)
	}

	return reply
}

func ParseMethodSelection(r io.Reader) ([]byte, error) {
	verAndCount := make([]byte, 2)
	if _, err := io.ReadFull(r, verAndCount); err != nil {
		return nil, err
	}
	if verAndCount[0] != 0x05 {
		return nil, errors.New("version is NOT 5")
	}
	if verAndCount[1] == 0 { // No suggested methods
		return nil, nil
	}

	methods := make([]byte, verAndCount[1])
	if _, err := io.ReadFull(r, methods); err != nil {
		return nil, err
	}

	return methods, nil
}

func ParseRequest(r io.Reader) (net.IP, uint16, error) {
	untilAddrType := make([]byte, 4)
	if _, err := io.ReadFull(r, untilAddrType); err != nil {
		return nil, 0, err
	}
	if untilAddrType[0] != 0x05 || untilAddrType[2] != 0x00 {
		return nil, 0, FailureReply
	}
	if untilAddrType[1] != 0x01 {
		return nil, 0, CmdNotSupportedReply
	}

	var addr net.IP
	var portBytes []byte

	switch untilAddrType[3] {
	case 0x01:
		addrBytes := make([]byte, 6)
		if _, err := io.ReadFull(r, addrBytes); err != nil {
			return nil, 0, err
		}
		addr = net.IPv4(addrBytes[0], addrBytes[1], addrBytes[2], addrBytes[3])
		portBytes = addrBytes[4:]

	case 0x03:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(r, lenByte); err != nil {
			return nil, 0, err
		}
		domain := make([]byte, lenByte[0]+2) // read more 2 bytes to read port number together
		if _, err := io.ReadFull(r, domain); err != nil {
			return nil, 0, err
		}
		resolved, err := net.ResolveIPAddr("ip4", string(domain[:len(domain)-2]))
		if err != nil {
			return nil, 0, err
		}
		addr = resolved.IP
		portBytes = domain[len(domain)-2:]

	case 0x04:
		return nil, 0, AddrTypeNotSupported
	}

	return addr, binary.BigEndian.Uint16(portBytes), nil
}
