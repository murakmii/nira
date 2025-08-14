package netdoc

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"slices"
	"strings"
)

type (
	Document struct {
		items []*Item
	}

	Item struct {
		keyword string
		args    []string
		object  *Object
		digests []DocDigest
	}

	Object struct {
		keyword string
		data    []byte
	}
)

var keywordStart [256]bool

func init() {
	// Head character of keyword accepts only following characters: a ~ z, A ~ Z, 0 ~ 9
	for i := 0; i < 256; i++ {
		if (i >= 0x30 && i <= 0x39) || (i >= 0x41 && i <= 0x5A) || (i >= 0x61 && i <= 0x7A) {
			keywordStart[i] = true
		}
	}
}

// For scanner function to exclude empty line.
func scanLinesNotEmpty(data []byte, atEOF bool) (int, []byte, error) {
	advance, token, err := bufio.ScanLines(data, atEOF)
	if advance > 0 && len(token) == 0 {
		return 0, nil, errors.New("empty line")
	}
	return advance, token, err
}

// ParseDocument parses netdoc formatted document(key certificates, consensus, server description)
// https://spec.torproject.org/dir-spec/netdoc.html
//
// Also, this method computes digest for signature items.
// Signature items specified by 'digesters' will be attached digest from initial item.
func ParseDocument(r io.Reader, digesters ...*Digester) (*Document, error) {
	doc := &Document{}
	var err error

	scanner := bufio.NewScanner(r)
	scanner.Split(scanLinesNotEmpty)
	for scanner.Scan() {
		line := scanner.Text()

		if line[0] == '-' {
			if len(doc.items) == 0 || doc.items[len(doc.items)-1].object != nil {
				return nil, errors.New("invalid object")
			}

			if doc.items[len(doc.items)-1].object, err = parseObject(scanner, line, digesters); err != nil {
				return nil, err
			}
		} else if !keywordStart[line[0]] {
			return nil, errors.New("invalid keyword")
		} else {
			kwArgs := strings.Split(line, " ")
			item := &Item{keyword: kwArgs[0], args: kwArgs[1:]}
			doc.items = append(doc.items, item)

			for _, digester := range digesters {
				if digest := digester.WriteItem(item, line); digest != nil {
					item.AttachDigest(digest)
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return doc, checkSignatureItems(doc.items, digesters)
}

func writeDigesters(digesters []*Digester, line string) {
	for _, d := range digesters {
		d.WriteLine(line)
	}
}

func parseObject(scanner *bufio.Scanner, begin string, digesters []*Digester) (*Object, error) {
	writeDigesters(digesters, begin)
	if !strings.HasPrefix(begin, "-----BEGIN ") || !strings.HasSuffix(begin, "-----") {
		return nil, errors.New("include invalid beginning line for object")
	}

	obj := &Object{keyword: begin[11 : len(begin)-5]}
	buf := bytes.NewBufferString("")
	var err error

	for scanner.Scan() {
		data := scanner.Text()
		writeDigesters(digesters, data)

		if data == "-----END "+obj.keyword+"-----" {
			if obj.data, err = base64.StdEncoding.DecodeString(buf.String()); err != nil {
				return nil, err
			}
			return obj, nil
		}

		if _, err := buf.WriteString(data); err != nil {
			return nil, err
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return nil, errors.New("object is NOT terminated")
}

// Signature items must be placed at tail of document. We guarantee it.
func checkSignatureItems(items []*Item, digesters []*Digester) error {
	var sigItems []string
	for i := len(digesters) - 1; i >= 0; i-- {
		if len(sigItems) == 0 || sigItems[len(sigItems)-1] != digesters[i].sigItem {
			sigItems = append(sigItems, digesters[i].sigItem)
		}
	}

	var tailItems []string
	for i := len(items) - 1; i >= 0 && len(tailItems) < len(sigItems); i-- {
		if len(tailItems) == 0 || tailItems[len(tailItems)-1] != items[i].Keyword() {
			tailItems = append(tailItems, items[i].Keyword())
		}
	}

	if !slices.Equal(tailItems, sigItems) {
		return errors.New("invalid signature items")
	}
	return nil
}

func (doc *Document) Items() []*Item { return doc.items }

func NewItem(kw string, args []string, obj *Object) *Item {
	return &Item{keyword: kw, args: args, object: obj}
}

func (item *Item) Keyword() string      { return item.keyword }
func (item *Item) Args() []string       { return item.args }
func (item *Item) Object() *Object      { return item.object }
func (item *Item) Digests() []DocDigest { return item.digests }

func (item *Item) AttachDigest(digest DocDigest) *Item {
	item.digests = append(item.digests, digest)
	return item
}

func NewObject(kw string, data []byte) *Object {
	return &Object{keyword: kw, data: data}
}

func (obj *Object) Keyword() string { return obj.keyword }
func (obj *Object) Data() []byte    { return obj.data }
