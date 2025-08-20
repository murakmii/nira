package docs

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/murakmii/nira/dirproto/netdoc"
)

type (
	// KeyCertificates represents authority key certificates.
	// See: https://spec.torproject.org/dir-spec/creating-key-certificates.html
	KeyCertificates struct {
		fp AuthorityIdentity

		identKey   *AuthorityIdentityKey
		signingKey *AuthoritySigningKey

		expires time.Time
	}

	AuthorityIdentityKey rsa.PublicKey
	AuthoritySigningKey  rsa.PublicKey
)

var keyCertsSigItemKw = "dir-key-certification"

// ParseKeyCertificates parse key certificates formatted netdoc
func ParseKeyCertificates(r io.Reader) (*KeyCertificates, error) {
	parsed, err := netdoc.ParseDocument(r, netdoc.RequiredSignatureItem(keyCertsSigItemKw, sha1.New()))
	if err != nil {
		return nil, err
	}

	certs := &KeyCertificates{}
	var crossCertSig []byte
	var sigItem *netdoc.Item

	for _, item := range parsed.Items() {
		switch item.Keyword() {
		case "fingerprint":
			if len(item.Args()) != 1 {
				return nil, fmt.Errorf("%s has invalid argument", item.Keyword())
			}
			certs.fp, err = hex.DecodeString(item.Args()[0])
			if err != nil {
				return nil, fmt.Errorf("failed to decode hex of %s", item.Keyword())
			}

		case "dir-key-expires":
			certs.expires, err = parseTime(item)
			if err != nil {
				return nil, fmt.Errorf("%s has invalid time format: %w", item.Keyword(), err)
			}

		case "dir-identity-key":
			key, err := parseRSAPublicKey(item)
			if err != nil {
				return nil, fmt.Errorf("%s has invalid key: %w", item.Keyword(), err)
			}
			certs.identKey = (*AuthorityIdentityKey)(key)

		case "dir-signing-key":
			key, err := parseRSAPublicKey(item)
			if err != nil {
				return nil, fmt.Errorf("%s has invalid key: %w", item.Keyword(), err)
			}
			certs.signingKey = (*AuthoritySigningKey)(key)

		case "dir-key-crosscert":
			if item.Object() == nil {
				return nil, fmt.Errorf("%s item has no object", item.Keyword())
			}
			crossCertSig = item.Object().Data()

		case keyCertsSigItemKw:
			sigItem = item
		}
	}

	return certs, certs.validate(crossCertSig, sigItem)
}

func parseRSAPublicKey(item *netdoc.Item) (*rsa.PublicKey, error) {
	if item.Object() == nil {
		return nil, errors.New("no object")
	}

	return x509.ParsePKCS1PublicKey(item.Object().Data())
}

func (kc *KeyCertificates) Fingerprint() AuthorityIdentity     { return kc.fp }
func (kc *KeyCertificates) Expires() time.Time                 { return kc.expires }
func (kc *KeyCertificates) IdentityKey() *AuthorityIdentityKey { return kc.identKey }
func (kc *KeyCertificates) SigningKey() *AuthoritySigningKey   { return kc.signingKey }

// validate validates fields and verify cross-cert and signature.
func (kc *KeyCertificates) validate(crossCertSig []byte, sigItem *netdoc.Item) error {
	if crossCertSig == nil || sigItem == nil || sigItem.Object() == nil || len(sigItem.Digests()) == 0 ||
		kc.expires.IsZero() || kc.fp == nil || kc.identKey == nil || kc.signingKey == nil {
		return errors.New("invalid key certificate")
	}

	if !bytes.Equal(computeKeyDigest(kc.identKey.RSA()), kc.fp) {
		return errors.New("invalid fingerprint")
	}

	if err := rsa.VerifyPKCS1v15(kc.identKey.RSA(), 0, sigItem.Digests()[0], sigItem.Object().Data()); err != nil {
		return fmt.Errorf("document signature is invalid: %w", err)
	}

	if err := rsa.VerifyPKCS1v15(kc.signingKey.RSA(), 0, kc.fp, crossCertSig); err != nil {
		return fmt.Errorf("cross cert signature is invalid: %w", err)
	}

	return nil
}

func VerifyConsensus(consensus *Consensus, cert *KeyCertificates) error {
	sk := cert.SigningKey().RSA()
	skDigest := computeKeyDigest(sk)

	var dirSig *DirSignature
	for _, s := range consensus.Signatures() {
		if s.Identity().Equal(cert.Fingerprint()) && s.SigningKey().Equal(skDigest) {
			dirSig = s
			break
		}
	}
	if dirSig == nil {
		return errors.New("consensus has no signature")
	}

	return rsa.VerifyPKCS1v15(sk, 0, dirSig.DigestSHA1(), dirSig.Signature())
}

func computeKeyDigest(k *rsa.PublicKey) []byte {
	d := sha1.Sum(x509.MarshalPKCS1PublicKey(k))
	return d[:]
}

func (k *AuthorityIdentityKey) RSA() *rsa.PublicKey { return (*rsa.PublicKey)(k) }

func (k *AuthoritySigningKey) RSA() *rsa.PublicKey { return (*rsa.PublicKey)(k) }
