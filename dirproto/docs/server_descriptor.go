package docs

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/murakmii/nira/cert"
	"github.com/murakmii/nira/dirproto/netdoc"
)

type (
	// ServerDescriptor represents server descriptor.
	// See: https://spec.torproject.org/dir-spec/server-descriptor-format.html
	ServerDescriptor struct {
		fp RouterIdentity

		identEd  *cert.Ed25519
		identRsa *RouterIdentityRsaKey

		ntorKey []byte

		digest DescriptorDigest
	}

	RouterIdentityRsaKey rsa.PublicKey
)

var (
	routerEd25519SigItemKw = "router-sig-ed25519"
	routerSigItemKw        = "router-signature"
)

func ParseServerDescriptor(r io.Reader) (*ServerDescriptor, error) {
	// signature input for router-signature-ed25519 is prefixed by fixed string.
	// See: https://spec.torproject.org/dir-spec/server-descriptor-format.html#item:router-sig-ed25519
	sigEd25519 := sha256.New()
	sigEd25519.Write([]byte("Tor router descriptor signature v1"))

	parsed, err := netdoc.ParseDocument(r,
		netdoc.RequiredSignatureItem(routerEd25519SigItemKw, sigEd25519),
		netdoc.RequiredSignatureItem(routerSigItemKw, sha1.New()),
	)
	if err != nil {
		return nil, err
	}

	desc := &ServerDescriptor{}
	var masterKey []byte
	var sigEd25519Item, sigItem *netdoc.Item
	var ntorCC *cert.Ed25519
	var ntorCCBit bool

	for _, item := range parsed.Items() {
		switch item.Keyword() {
		case "identity-ed25519":
			if item.Object() == nil {
				return nil, fmt.Errorf("identity-ed25519 has no object")
			}
			desc.identEd, err = cert.ParseEd25519Cert(item.Object().Data())
			if err != nil {
				return nil, fmt.Errorf("failed to parse identity-ed25519: %w", err)
			}

		case "master-key-ed25519":
			masterKey, err = parseSingleBase64Item(item)
			if err != nil {
				return nil, fmt.Errorf("failed to parse master key: %w", err)
			}

		case "fingerprint":
			desc.fp, err = hex.DecodeString(strings.Join(item.Args(), ""))
			if err != nil {
				return nil, fmt.Errorf("invalid fingerprint: %w", err)
			}

		case "ntor-onion-key":
			desc.ntorKey, err = parseSingleBase64Item(item)
			if err != nil {
				return nil, fmt.Errorf("invalid ntor-onion-key: %w", err)
			}

		case "ntor-onion-key-crosscert":
			if len(item.Args()) != 1 || item.Object() == nil {
				return nil, fmt.Errorf("invalid ntor-onion-key-crosscert")
			}
			ntorCCBit = item.Args()[0] == "1"
			ntorCC, err = cert.ParseEd25519Cert(item.Object().Data())
			if err != nil {
				return nil, fmt.Errorf("failed to parse ntor-onion-key-crosscert object as ed25519 cert: %w", err)
			}

		case "signing-key":
			var key *rsa.PublicKey
			key, err = parseRSAPublicKey(item)
			if err != nil {
				return nil, fmt.Errorf("failed to parse signing key: %w", err)
			}
			desc.identRsa = (*RouterIdentityRsaKey)(key)

		case routerEd25519SigItemKw:
			sigEd25519Item = item
		case routerSigItemKw:
			desc.digest = (DescriptorDigest)(item.Digests()[0])
			sigItem = item
		}
	}

	return desc, desc.validate(masterKey, ntorCC, ntorCCBit, sigEd25519Item, sigItem)
}

func parseSingleBase64Item(item *netdoc.Item) ([]byte, error) {
	if len(item.Args()) != 1 {
		return nil, fmt.Errorf("%s must be exactly 1 args", item.Keyword())
	}

	return base64.RawStdEncoding.DecodeString(item.Args()[0])
}

func (desc *ServerDescriptor) validate(masterKey []byte, ntorCC *cert.Ed25519, ntorCCBit bool, sigEd25519Item, sigItem *netdoc.Item) error {
	if masterKey == nil || ntorCC == nil || sigItem == nil || sigEd25519Item == nil ||
		desc.fp == nil || desc.identRsa == nil || desc.identEd == nil || desc.ntorKey == nil {
		return fmt.Errorf("invalid server descriptor")
	}

	// check identity-ed25519 and master-key-ed25519
	if err := desc.identEd.VerifyAsIdentitySigning(); err != nil {
		return fmt.Errorf("invalid ed25519 identity cert: %w", err)
	}
	if !bytes.Equal(desc.identEd.Extensions()[0].Data(), masterKey) {
		return fmt.Errorf("invalid master key")
	}

	// check ntor-onion-key-crosscert
	if err := ntorCC.VerifyAsNtorCC(desc.ntorKey, ntorCCBit); err != nil {
		return err
	}
	if !bytes.Equal(ntorCC.Key(), desc.identEd.Extensions()[0].Data()) {
		return fmt.Errorf("key in ntor key cross certificate is NOT relay id key")
	}
	// verify signature of router-sig-ed25519
	sig, err := parseSingleBase64Item(sigEd25519Item)
	if err != nil {
		return fmt.Errorf("invalid ed25519 signature item: %w", err)
	}
	if !ed25519.Verify(desc.identEd.Key(), sigEd25519Item.Digests()[0], sig) {
		return fmt.Errorf("invalid ed25519 signature")
	}

	// check fingerprint and verify signature of router-signature
	if !bytes.Equal(desc.fp, computeKeyDigest(desc.identRsa.RSA())) {
		return fmt.Errorf("server descriptor fingerprint mismatch")
	}
	if err := rsa.VerifyPKCS1v15(desc.identRsa.RSA(), 0, sigItem.Digests()[0], sigItem.Object().Data()); err != nil {
		return err
	}

	return nil
}

func (desc *ServerDescriptor) Digest() DescriptorDigest    { return desc.digest }
func (desc *ServerDescriptor) Fingerprint() RouterIdentity { return desc.fp }
func (desc *ServerDescriptor) NtorKey() []byte             { return desc.ntorKey }

func (k *RouterIdentityRsaKey) RSA() *rsa.PublicKey { return (*rsa.PublicKey)(k) }
