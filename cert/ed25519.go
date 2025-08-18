package cert

import (
	"encoding/binary"
	"errors"
	"time"
)

type (
	Type    byte
	ExtType byte

	CertifiedKeyType byte

	Ed25519 struct {
		typ        Type
		expires    time.Time
		keyType    CertifiedKeyType
		key        []byte
		extensions []*Ed25519Ext

		signature []byte
	}

	Ed25519Ext struct {
		typ       ExtType
		ignorable bool
		data      []byte
	}
)

const (
	ForTlsLink          Type = 1
	ForRsaID            Type = 2
	ForLinkAuth         Type = 3
	ForIdentitySigning  Type = 4
	ForSigningTlsCert   Type = 5
	ForSigningLinkAuth  Type = 6
	ForRsaIDIdentity    Type = 7
	ForBlinkedIdSigning Type = 8
	ForHsIpSigning      Type = 9
	ForNtorCcIdentity   Type = 10
	ForHsIpCcSigning    Type = 11
	ForFamilyIdentity   Type = 12

	SignedWithEd25519KeyExt ExtType = 4

	CertifiedEd25519Key   CertifiedKeyType = 1
	CertifiedDigestOfRsa  CertifiedKeyType = 2
	CertifiedDigestOfX509 CertifiedKeyType = 3
)

func ParseEd25519Cert(data []byte) (*Ed25519, error) {
	if len(data) < 40 || data[0] != 0x01 {
		return nil, errors.New("malformed Ed25519 cert")
	}

	cert := &Ed25519{
		typ:     Type(data[1]),
		expires: time.Unix(int64(binary.BigEndian.Uint32(data[2:]))*3600, 0),
		keyType: CertifiedKeyType(data[6]),
		key:     data[7:39],
	}

	nExt := data[39]
	data = data[40:]

	for i := byte(0); i < nExt; i++ {
		if len(data) < 2 {
			return nil, errors.New("malformed Ed25519 cert")
		}
		extLen := int(binary.BigEndian.Uint16(data))

		if len(data) < extLen+4 {
			return nil, errors.New("malformed Ed25519 cert")
		}

		cert.extensions = append(cert.extensions, &Ed25519Ext{
			typ:       ExtType(data[2]),
			ignorable: data[3] == 0,
			data:      data[4 : extLen+4],
		})
		data = data[extLen+4:]
	}

	if len(data) != 64 {
		return nil, errors.New("malformed Ed25519 cert")
	}
	cert.signature = data

	return cert, nil
}

func (c *Ed25519) Type() Type                { return c.typ }
func (c *Ed25519) Expires() time.Time        { return c.expires }
func (c *Ed25519) KeyType() CertifiedKeyType { return c.keyType }
func (c *Ed25519) Key() []byte               { return c.key }
func (c *Ed25519) Extensions() []*Ed25519Ext { return c.extensions }
func (c *Ed25519) Signature() []byte         { return c.signature }

// Encode cert without signature.
func (c *Ed25519) Encode() []byte {
	totalLen := 40
	for _, ext := range c.extensions {
		totalLen += ext.EncodedLen()
	}

	encoded := make([]byte, totalLen)
	encoded[0] = 1
	encoded[1] = byte(c.typ)
	binary.BigEndian.PutUint32(encoded[2:], uint32(c.expires.Unix()/3600))
	encoded[6] = byte(c.keyType)
	copy(encoded[7:], c.key)
	encoded[39] = byte(len(c.extensions))

	extStart := encoded[40:]
	for _, ext := range c.extensions {
		extStart = extStart[copy(extStart, ext.Encode()):]
	}

	return encoded
}

func (ext *Ed25519Ext) Type() ExtType   { return ext.typ }
func (ext *Ed25519Ext) Ignorable() bool { return ext.ignorable }
func (ext *Ed25519Ext) Data() []byte    { return ext.data }

func (ext *Ed25519Ext) EncodedLen() int {
	return len(ext.data) + 4
}

func (ext *Ed25519Ext) Encode() []byte {
	encoded := make([]byte, ext.EncodedLen())
	binary.BigEndian.PutUint16(encoded, uint16(len(ext.data)))
	encoded[2] = byte(ext.typ)

	if !ext.ignorable {
		encoded[3] = 0
	}

	copy(encoded[4:], ext.data)
	return encoded
}
