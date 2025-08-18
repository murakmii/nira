package cert

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/pem"
	"io"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func mustLoadTestPEM(path string) []byte {
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	content, err := io.ReadAll(f)
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode(content)
	return block.Bytes
}

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestParseEd25519Cert(t *testing.T) {
	got, err := ParseEd25519Cert(mustLoadTestPEM("testdata/cert.pem"))
	if err != nil {
		t.Fatalf("ParseEd25519Cert failed: %v", err)
	}

	expectCert := &Ed25519{
		typ:     ForIdentitySigning,
		expires: time.Date(2025, 8, 14, 9, 0, 0, 0, time.UTC),
		keyType: CertifiedEd25519Key,
		key:     mustDecodeHex("e5074f93cbb23122d87443eafb0fcf4a3aa2bb68d86ddb830e660cec709e935c"),
		extensions: []*Ed25519Ext{
			{
				typ:       SignedWithEd25519KeyExt,
				ignorable: true,
				data:      mustDecodeHex("aa92ff2f12d85445e0854efa886dcbb1223f516ecc0692113992b4001d7ce7ad"),
			},
		},
		signature: mustDecodeHex("2de9f4321c3128eb84916849c1d5c0ead4554c849f49d430ee07ff783d30d1a38522f63f4eed4e27e2518dfec665b5ec79bb57d12013201b2b8df2cc092cfb04"),
	}

	diff := cmp.Diff(got, expectCert, cmp.AllowUnexported(Ed25519{}, Ed25519Ext{}))
	if len(diff) > 0 {
		t.Errorf("ParseEd25519Cert returned unexpected cert: %s", diff)
	}

	if !ed25519.Verify(got.Extensions()[0].data, got.Encode(), got.signature) {
		t.Errorf("cert verification failed")
	}
}

func TestEd25519_Encode(t *testing.T) {
	srcBytes := mustLoadTestPEM("testdata/cert.pem")
	sut, err := ParseEd25519Cert(srcBytes)
	if err != nil {
		panic(err)
	}

	if !bytes.Equal(sut.Encode(), srcBytes[:len(srcBytes)-64]) {
		t.Errorf("Encode() returned unexpected bytes")
	}
}
