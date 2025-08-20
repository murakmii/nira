package docs

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func hexToBin(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return b
}

func b64ToBin(enc *base64.Encoding, b64 string) []byte {
	if enc == nil {
		enc = base64.RawStdEncoding
	}

	b, err := enc.DecodeString(b64)
	if err != nil {
		panic(err)
	}
	return b
}

func TestParseConsensus(t *testing.T) {
	f, err := os.Open("testdata/consensus.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	sut, err := ParseConsensus(f)
	if err != nil {
		t.Errorf("ParseConsensus failed: %v", err)
		return
	}

	expect := &Consensus{
		validAfter: time.Date(2025, 8, 20, 11, 45, 0, 0, time.UTC),
		freshUntil: time.Date(2025, 8, 20, 11, 50, 0, 0, time.UTC),
		validUntil: time.Date(2025, 8, 20, 12, 0, 0, 0, time.UTC),

		routers: []*RouterStatus{
			{
				nick:    "relay1",
				ident:   b64ToBin(nil, "CZCrndZaUjnWhZ+zTaS7I1mibBo"),
				digest:  b64ToBin(nil, "TNVcBYlgNhsSYPvMSw2fjQ8E/F8"),
				addr:    "10.5.1.20",
				orPort:  9001,
				dirPort: 0,
				flags: []RouterStatusFlag{
					FastFlag, GuardFlag, HSDirFlag, RunningFlag, StableFlag, V2DirFlag, ValidFlag,
				},
			},
			{
				nick:    "da1",
				ident:   b64ToBin(nil, "PkrNDwaaAhCJY+v9oCPQ9fhxDQk"),
				digest:  b64ToBin(nil, "dhOqLKtuXgIISx3iutyUb4yFY5U"),
				addr:    "10.5.1.10",
				orPort:  9001,
				dirPort: 80,
				flags: []RouterStatusFlag{
					AuthorityFlag, FastFlag, GuardFlag, HSDirFlag, RunningFlag, StableFlag, V2DirFlag, ValidFlag,
				},
			},
		},

		signatures: []*DirSignature{
			{
				signature:  b64ToBin(base64.StdEncoding, "bLmVDs//myb1uM8lNNiPGFh2+0/xsGCJlWvP05AuXJ7C83+5L4+D5bTCG7AAAszgQsj2RGZ5dnLDxosqxL9l+/U3gI5nKJ5TcPEe09xCoSCba+w6B9+OcH+hzguE8QVCbLbhD9TARiwZtrdIFp+0U/nadty2kutYccvbfu07u0RSOmsIdfVU25jCyinfMNb9DSwrE7efu9y362wM0xrBTheQujBnG0snBMZIFM2DvdslFPHLITiiMfarV8PtYwD/+amir3GgXfUz2E39qhCB5EDrLjHqc6zRFBSuF0nBN+ZRsFMvCi3bPYAjwJ/E9FfRdQpwgkD41B82HD/cfOG+Iw=="),
				digestS1:   hexToBin("f1c9bea658961b5774a204d4127767c21fae43da"),
				digestS2:   hexToBin("59ebebb627154187c38e8be6416aa0be5fb57e54275f33e7235a1e07450578e5"),
				ident:      hexToBin("90ADABDA25819E52732AD9B58090E375D00CED83"),
				signingKey: hexToBin("551665128062AB66356229F030F6C49B55D98D8E"),
			},
		},
	}

	diff := cmp.Diff(expect, sut, cmp.AllowUnexported(Consensus{}, RouterStatus{}, DirSignature{}))
	if len(diff) > 0 {
		t.Errorf("parsed consensus unexpected: %s\n", diff)
	}
}
