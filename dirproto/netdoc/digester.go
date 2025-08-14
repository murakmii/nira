package netdoc

import "hash"

type (
	DocDigest []byte

	// Digester computes digest from initial item to signature item.
	// See: https://spec.torproject.org/dir-spec/netdoc.html#signing
	Digester struct {
		sigItem string
		hs      hash.Hash
		sum     []byte
	}
)

var (
	lineFeedBytes = []byte{'\n'}
	spaceBytes    = []byte{' '}
)

func RequiredSignatureItem(sigItem string, hs hash.Hash) *Digester {
	return &Digester{sigItem: sigItem, hs: hs}
}

// WriteItem add item data to digest.
// If we should attach digest to item(signature item), this method returns digest.
func (d *Digester) WriteItem(item *Item, rawLine string) DocDigest {
	if d.sigItem != item.keyword {
		d.WriteLine(rawLine)
		return nil
	} else if d.sum != nil {
		// If digest was confirmed once, we always use it.
		return d.sum
	}

	// If 'item' is signature item, we terminate digest data with item's keyword and line feed or space.
	// Use space if signature item has arguments(e.g. 'directory-signature')
	d.hs.Write([]byte(item.keyword))
	if len(item.Args()) == 0 {
		d.hs.Write(lineFeedBytes)
	} else {
		d.hs.Write(spaceBytes)
	}

	d.sum = d.hs.Sum(nil)
	return d.sum
}

func (d *Digester) WriteLine(line string) {
	if d.sum != nil {
		return
	}

	d.hs.Write([]byte(line))
	d.hs.Write(lineFeedBytes)
}
