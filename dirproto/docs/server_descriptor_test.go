package docs

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func TestParseServerDescriptor(t *testing.T) {
	f, err := os.Open("testdata/server_descriptor.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	sut, err := ParseServerDescriptor(f)
	if err != nil {
		t.Errorf("ParseServerDescriptor() error = %v", err)
		return
	}

	if base64.RawStdEncoding.EncodeToString(sut.Digest()) != "TNVcBYlgNhsSYPvMSw2fjQ8E/F8" {
		t.Errorf("ParseServerDescriptor().Digest() = %v, want %v", sut.Digest(), "TNVcBYlgNhsSYPvMSw2fjQ8E/F8")
	}

	if strings.ToUpper(hex.EncodeToString(sut.Fingerprint())) != "0990AB9DD65A5239D6859FB34DA4BB2359A26C1A" {
		t.Errorf("ParseServerDescriptor().Fingerprint() = %v, want %v", sut.Fingerprint(), "0990AB9DD65A5239D6859FB34DA4BB2359A26C1A")
	}

	if base64.RawStdEncoding.EncodeToString(sut.NtorKey()) != "kmptPbBfqahC2ng1cB9rAfb/OTLFJIcmB4w+CV+p20A" {
		t.Errorf("ParseServerDescriptor().NtorKey() = %v, want %v", sut.NtorKey(), "kmptPbBfqahC2ng1cB9rAfb/OTLFJIcmB4w+CV+p20A")
	}
}
