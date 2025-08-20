package docs

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/murakmii/nira/dirproto/netdoc"
)

type (
	// Consensus represents vote and status consensus document.
	// See: https://spec.torproject.org/dir-spec/consensus-formats.html
	Consensus struct {
		validAfter time.Time
		freshUntil time.Time
		validUntil time.Time

		routers    []*RouterStatus
		signatures []*DirSignature
	}

	RouterStatus struct {
		nick    string
		ident   RouterIdentity
		digest  DescriptorDigest
		addr    string
		orPort  int
		dirPort int
		flags   []RouterStatusFlag
	}

	DirSignature struct {
		signature  []byte
		digestS1   []byte
		digestS2   []byte
		ident      AuthorityIdentity
		signingKey AuthoritySignKeyDigest
	}

	AuthorityIdentity      []byte
	RouterIdentity         []byte
	DescriptorDigest       []byte
	AuthoritySignKeyDigest []byte
	RouterStatusFlag       byte
)

const (
	AuthorityFlag RouterStatusFlag = iota
	BadExitFlag
	ExitFlag
	FastFlag
	GuardFlag
	HSDirFlag
	MiddleOnlyFlag
	NoEdConsensusFlag
	StableFlag
	StaleDescFlag
	RunningFlag
	ValidFlag
	V2DirFlag
)

const (
	consensusSigItemKw = "directory-signature"
)

var routerStatusFlags = map[string]RouterStatusFlag{
	"Authority":     AuthorityFlag,
	"BadExit":       BadExitFlag,
	"Exit":          ExitFlag,
	"Fast":          FastFlag,
	"Guard":         GuardFlag,
	"HSDir":         HSDirFlag,
	"MiddleOnly":    MiddleOnlyFlag,
	"NoEdConsensus": NoEdConsensusFlag,
	"Stable":        StableFlag,
	"StaleDesc":     StaleDescFlag,
	"Running":       RunningFlag,
	"Valid":         ValidFlag,
	"V2Dir":         V2DirFlag,
}

func (id AuthorityIdentity) Equal(other AuthorityIdentity) bool {
	return bytes.Equal(id, other)
}

func (skd AuthoritySignKeyDigest) Equal(other AuthoritySignKeyDigest) bool {
	return bytes.Equal(skd, other)
}

// ParseConsensus parses vote and status consensus document formatted netdoc.
func ParseConsensus(r io.Reader) (*Consensus, error) {
	consensus := &Consensus{}
	parsed, err := netdoc.ParseDocument(r,
		netdoc.RequiredSignatureItem(consensusSigItemKw, sha1.New()),
		netdoc.RequiredSignatureItem(consensusSigItemKw, sha256.New()),
	)
	if err != nil {
		return nil, err
	}

	for _, item := range parsed.Items() {
		switch item.Keyword() {
		case consensusSigItemKw:
			sig, err := parseDirSignature(item)
			if err != nil {
				return nil, fmt.Errorf("failed to parse %s: %w", consensusSigItemKw, err)
			}

			consensus.signatures = append(consensus.signatures, sig)

		case "valid-after":
			consensus.validAfter, err = parseTime(item)
			if err != nil {
				return nil, fmt.Errorf("failed to parse %s: %w", item.Keyword(), err)
			}

		case "fresh-until":
			consensus.freshUntil, err = parseTime(item)
			if err != nil {
				return nil, fmt.Errorf("failed to parse %s: %w", item.Keyword(), err)
			}

		case "valid-until":
			consensus.validUntil, err = parseTime(item)
			if err != nil {
				return nil, fmt.Errorf("failed to parse %s: %w", item.Keyword(), err)
			}

		case "r":
			router, err := parseRouter(item)
			if err != nil {
				return nil, fmt.Errorf("failed to parse %s: %w", item.Keyword(), err)
			}
			consensus.routers = append(consensus.routers, router)

		case "s":
			if len(consensus.routers) == 0 {
				return nil, fmt.Errorf("failed to parse %s: no related router status", item.Keyword())
			}
			consensus.routers[len(consensus.routers)-1].flags = parseRouterStatusFlags(item)
		}
	}

	return consensus, consensus.validate()
}

func parseRouter(item *netdoc.Item) (*RouterStatus, error) {
	if len(item.Args()) != 8 {
		return nil, errors.New("invalid arguments count")
	}

	router := &RouterStatus{nick: item.Args()[0], addr: item.Args()[5]}

	var err error
	router.ident, err = base64.RawStdEncoding.DecodeString(item.Args()[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode ident: %w", err)
	}

	router.digest, err = base64.RawStdEncoding.DecodeString(item.Args()[2])
	if err != nil {
		return nil, fmt.Errorf("failed to decode digest: %w", err)
	}

	router.orPort, err = strconv.Atoi(item.Args()[6])
	if err != nil {
		return nil, fmt.Errorf("failed to parse orport: %w", err)
	}

	router.dirPort, err = strconv.Atoi(item.Args()[7])
	if err != nil {
		return nil, fmt.Errorf("failed to parse dirport: %w", err)
	}

	return router, nil
}

func parseDirSignature(item *netdoc.Item) (*DirSignature, error) {
	if len(item.Args()) < 2 {
		return nil, fmt.Errorf("'%s' item has invalid arguments", consensusSigItemKw)
	}
	if item.Object() == nil {
		return nil, fmt.Errorf("'%s' item has no object", consensusSigItemKw)
	}

	identOffset := len(item.Args()) - 2
	ident, err := hex.DecodeString(item.Args()[identOffset])
	if err != nil {
		return nil, err
	}

	signing, err := hex.DecodeString(item.Args()[identOffset+1])
	if err != nil {
		return nil, err
	}

	return &DirSignature{
		signature:  item.Object().Data(),
		digestS1:   item.Digests()[0],
		digestS2:   item.Digests()[1],
		ident:      ident,
		signingKey: signing,
	}, nil
}

func parseTime(item *netdoc.Item) (time.Time, error) {
	if len(item.Args()) != 2 {
		return time.Time{}, errors.New("invalid arguments count")
	}

	return time.Parse(time.DateTime, strings.Join(item.Args(), " "))
}

func parseRouterStatusFlags(item *netdoc.Item) []RouterStatusFlag {
	flags := make([]RouterStatusFlag, 0, len(item.Args()))
	for _, flagStr := range item.Args() {
		flag, ok := routerStatusFlags[flagStr]
		if ok {
			flags = append(flags, flag)
		}
	}
	return flags
}

func (c *Consensus) validate() error {
	if c.validAfter.IsZero() || c.freshUntil.IsZero() || c.validUntil.IsZero() {
		return errors.New("consensus has no life time")
	}

	if len(c.signatures) == 0 {
		return errors.New("consensus has no signatures")
	}

	return nil
}

func (r *RouterStatus) Nick() string                       { return r.nick }
func (r *RouterStatus) Flags() []RouterStatusFlag          { return r.flags }
func (r *RouterStatus) Identity() RouterIdentity           { return r.ident }
func (r *RouterStatus) DescriptorDigest() DescriptorDigest { return r.digest }
func (r *RouterStatus) Addr() string                       { return r.addr }
func (r *RouterStatus) OrPort() int                        { return r.orPort }
func (r *RouterStatus) DirPort() int                       { return r.dirPort }

func (s *DirSignature) Identity() AuthorityIdentity        { return s.ident }
func (s *DirSignature) DigestSHA1() []byte                 { return s.digestS1 }
func (s *DirSignature) DigestSHA256() []byte               { return s.digestS2 }
func (s *DirSignature) SigningKey() AuthoritySignKeyDigest { return s.signingKey }
func (s *DirSignature) Signature() []byte                  { return s.signature }

func (c *Consensus) Routers() []*RouterStatus    { return c.routers }
func (c *Consensus) ValidAfter() time.Time       { return c.validAfter }
func (c *Consensus) FreshUntil() time.Time       { return c.freshUntil }
func (c *Consensus) ValidUntil() time.Time       { return c.validUntil }
func (c *Consensus) Signatures() []*DirSignature { return c.signatures }
