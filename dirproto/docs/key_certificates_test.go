package docs

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func rsaPEM(p string) *rsa.PublicKey {
	block, _ := pem.Decode([]byte(p))
	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return key
}

func TestParseKeyCertificates(t *testing.T) {
	f, err := os.Open("testdata/key_certificates.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	sut, err := ParseKeyCertificates(f)
	if err != nil {
		t.Errorf("ParseKeyCertificates error: %s", err)
	}

	expect := &KeyCertificates{
		fp: hexToBin("90ADABDA25819E52732AD9B58090E375D00CED83"),
		identKey: (*AuthorityIdentityKey)(rsaPEM(`-----BEGIN RSA PUBLIC KEY-----
MIIBigKCAYEA1g3AS8gte86fSpIxWMBB5Tj0Aof7fCN1IsySjWFCq+uiUSwD+d1K
OHo6RTCwaJ+rV3hT06OtjrSMDFLajgGtQ9iAizZcdmSTFYSVe1f3IZfMvcIQkVD4
bkKwtB1yB8IHaqP4G8/rwr2HKfAz3KqVq+pwejeiXHLNc+uXkhTjtSGyuV76xBfX
fNz2dKep3DT2a0t0CQKKWeLMTH7pYuo7zLMMKNx8PNq5To+k0smjZKpPa3hI3qJW
bRYSss/yFfG59FEY6UxbmpWGzoUCAxW9hKYo40/mrEP8gcdEYBeqqzJAeZATekja
9dhF08fTKhf9MoresLXm9oweP4GaHV65rkzYfR7ucWS0wUkjnpryxJzjkMieVRQX
z+QVmdaItml0sGhjyO86oDA8AaLJY/yq6HwcupP/bKOtWFUn/4kLbeo2L62Tp3w5
RKJjlrIR6ojsRtS+CNIFzAwo6buSBZ4GRM6/RpxBYnECVvdnTFHDjtgUh4jM5aFY
kaUvc9tcARC3AgMBAAE=
-----END RSA PUBLIC KEY-----`)),
		signingKey: (*AuthoritySigningKey)(rsaPEM(`-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAsYItdkEVHNBoEv1jE/p+O8q+uEqD/QJue1kZ1RrErdwLeD4XNg31
Xxs/QFCab9ZN62gD/yC4XQga/aBQlVRDsMMkH7pTdhkNFAjx6F4HqWVvZrl2DvJo
BZoZl79vtEdgmZ/z5MUx/sMemz0ZsCk9irBWxh9E6G+gJvgWhzni6mc0ANRb/xiw
BVsxqTyUG1TEV/MYDYiAMI3u+uK3k13MR6HkVjrTcV4Xq8+eunl4CZ/5QuL+wdui
Fa0e2wo1xissUtvxE0UcCnJOBsUVv7R1AV/ketJEIyzVlXzz0vKeLPcYa9ddlQqd
FfZUAyj3i5Y91/v0wkJfu6wDIzmzk3WiAwIDAQAB
-----END RSA PUBLIC KEY-----`)),
		expires: time.Date(2026, 8, 20, 3, 14, 11, 0, time.UTC),
	}

	diff := cmp.Diff(sut, expect, cmp.AllowUnexported(KeyCertificates{}, big.Int{}))
	if len(diff) > 0 {
		t.Errorf("ParseKeyCertificates returns unexpected: %s", diff)
	}
}

func TestVerifyConsensus(t *testing.T) {
	fc, err := os.Open("testdata/consensus.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer fc.Close()

	consensus, err := ParseConsensus(fc)
	if err != nil {
		t.Fatal(err)
	}

	fkc, err := os.Open("testdata/key_certificates.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer fkc.Close()

	cert, err := ParseKeyCertificates(fkc)
	if err != nil {
		t.Fatal(err)
	}

	err = VerifyConsensus(consensus, cert)
	if err != nil {
		t.Errorf("VerifyConsensus error: %s", err)
	}
}
