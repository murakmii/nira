package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

type (
	ProtocolError struct {
		msg  string
		code byte
	}
)

func NewProtocolError(message string, code byte) *ProtocolError {
	return &ProtocolError{msg: message, code: code}
}

func (protoErr *ProtocolError) Code() byte    { return protoErr.code }
func (protoErr *ProtocolError) Error() string { return protoErr.msg }

func (protoErr *ProtocolError) ToErrorReply() []byte {
	reply := make([]byte, 10)
	reply[0] = 0x05
	reply[1] = protoErr.code
	reply[3] = 0x01
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
	if verAndCount[1] == 0 {
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
	if untilAddrType[0] != 0x05 {
		return nil, 0, NewProtocolError("version is NOT 5", 0x01)
	}
	if untilAddrType[1] != 0x01 {
		return nil, 0, NewProtocolError(fmt.Sprintf("command '%d' is NOT supported", untilAddrType[1]), 0x07)
	}
	if untilAddrType[2] != 0x00 {
		return nil, 0, NewProtocolError("reserved byte in request is MUST be 0", 0x01)
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
		domain := make([]byte, lenByte[0]+2)
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
		return nil, 0, NewProtocolError("IPv6 is NOT supported", 0x08)
	}

	return addr, binary.BigEndian.Uint16(portBytes), nil
}
