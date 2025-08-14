package netdoc

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func toBin(hexString string) []byte {
	h, err := hex.DecodeString(hexString)
	if err != nil {
		panic(err)
	}
	return h
}

func TestParseDocument(t *testing.T) {
	tests := []struct {
		name            string
		inputNetDocPath string
		inputDigesters  []*Digester
		expectItems     []*Item
		expectErr       string
	}{
		{
			name:            "parses valid netdoc",
			inputNetDocPath: "testdata/valid.txt",
			inputDigesters: []*Digester{
				RequiredSignatureItem("ntor-onion-key-crosscert", sha1.New()),
				RequiredSignatureItem("ntor-onion-key-crosscert", sha256.New()),
			},
			expectItems: []*Item{
				NewItem("master-key-ed25519", []string{"hoge"}, nil),
				NewItem("platform", []string{"Tor", "0.4.8.10", "on", "Linux"}, nil),
				NewItem("onion-key", []string{}, NewObject("RSA PUBLIC KEY", []byte("foobar"))),
				NewItem("uptime", []string{"12345"}, nil),
				NewItem("ntor-onion-key-crosscert", []string{"0"}, NewObject("ED25519 CERT", []byte("1234567890"))).
					AttachDigest(toBin("57bf624f37f300f8e4c6ac57d7d4ca51e7c660e4")).
					AttachDigest(toBin("84cec57ef8b029a1a3852dac55bf4a5c0fc80f2634a769eca49c9c1097618096")),
				NewItem("ntor-onion-key-crosscert", []string{"1"}, NewObject("ED25519 CERT", []byte("1234567890"))).
					AttachDigest(toBin("57bf624f37f300f8e4c6ac57d7d4ca51e7c660e4")).
					AttachDigest(toBin("84cec57ef8b029a1a3852dac55bf4a5c0fc80f2634a769eca49c9c1097618096")),
			},
		},
		{
			name:            "error if keyword starts invalid character",
			inputNetDocPath: "testdata/invalid_kw_start.txt",
			expectErr:       "invalid keyword",
		},
		{
			name:            "error if contains empty line",
			inputNetDocPath: "testdata/empty_line.txt",
			expectErr:       "empty line",
		},
		{
			name:            "error if contains object without item",
			inputNetDocPath: "testdata/only_obj.txt",
			expectErr:       "invalid object",
		},
		{
			name:            "error if item has multiple objects",
			inputNetDocPath: "testdata/multiple_obj.txt",
			expectErr:       "invalid object",
		},
		{
			name:            "error if keyword of object is invalid",
			inputNetDocPath: "testdata/mismatch_obj_keyword.txt",
			expectErr:       "object is NOT terminated",
		},
		{
			name:            "error if signature item does not exist",
			inputNetDocPath: "testdata/valid_but_no_sig_item.txt",
			inputDigesters: []*Digester{
				RequiredSignatureItem("ntor-onion-key-crosscert", sha1.New()),
			},
			expectErr: "invalid signature items",
		},
		{
			name:            "error if signature item does not place in tail of document",
			inputNetDocPath: "testdata/sig_item_not_tail.txt",
			inputDigesters: []*Digester{
				RequiredSignatureItem("onion-key", sha1.New()),
			},
			expectErr: "invalid signature items",
		},
		{
			name:            "error if signature items order is invalid",
			inputNetDocPath: "testdata/sig_item_invalid_order.txt",
			inputDigesters: []*Digester{
				RequiredSignatureItem("router-sig-ed25519", sha1.New()),
				RequiredSignatureItem("router-signature", sha1.New()),
			},
			expectErr: "invalid signature items",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f, err := os.Open(test.inputNetDocPath)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()

			doc, err := ParseDocument(f, test.inputDigesters...)
			gotErr := ""
			if err != nil {
				gotErr = err.Error()
			}

			if test.expectErr != gotErr {
				t.Errorf("ParseDocument() error = %v, wantErr = %v", err, test.expectErr)
			}
			if len(gotErr) > 0 {
				return
			}

			diff := cmp.Diff(doc.Items(), test.expectItems, cmp.AllowUnexported(Item{}, Object{}))
			if len(diff) > 0 {
				t.Errorf("ParseDocument() items diff = %s", diff)
			}
		})
	}
}
