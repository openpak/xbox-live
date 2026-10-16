// SPDX-License-Identifier: AGPL-3.0-only
// Package krb implements the Kerberos 5 / Xbox Live wire structures needed by
// the original Xbox key distribution centre and security gateway. Structure
// and constants follow RFC 4120 and the public Xombie source (libs/xblive
// krb, services/kdc); this is a clean Go port with bounded, strict parsing.
package krb

import (
	"errors"
	"fmt"
	"time"
	"unicode/utf8"
)

// ErrMalformed is returned for every structurally invalid encoding.
var ErrMalformed = errors.New("krb: malformed ASN.1")

const (
	tagInteger    = 0x02
	tagBitString  = 0x03
	tagOctet      = 0x04
	tagSequence   = 0x30
	tagGenTime    = 0x18
	tagGeneralStr = 0x1b

	maxStringLen = 256
	maxListLen   = 64
	maxDERLen    = 1 << 16
)

func malformed(what string) error { return fmt.Errorf("%w: %s", ErrMalformed, what) }

// ---- writer ----

func lengthBytes(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x100:
		return []byte{0x81, byte(n)}
	case n < 0x10000:
		return []byte{0x82, byte(n >> 8), byte(n)}
	default:
		return []byte{0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

func tlv(tag byte, parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n+5)
	out = append(out, tag)
	out = append(out, lengthBytes(n)...)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func seq(parts ...[]byte) []byte { return tlv(tagSequence, parts...) }
func ctx(n int, v []byte) []byte { return tlv(0xa0|byte(n), v) }
func app(n int, v []byte) []byte { return tlv(0x60|byte(n), v) }
func octets(b []byte) []byte     { return tlv(tagOctet, b) }
func genString(s string) []byte  { return tlv(tagGeneralStr, []byte(s)) }
func genTime(t time.Time) []byte { return tlv(tagGenTime, []byte(t.UTC().Format("20060102150405Z"))) }
func flagsBits(f uint32) []byte {
	return tlv(tagBitString, []byte{0, byte(f >> 24), byte(f >> 16), byte(f >> 8), byte(f)})
}
func intg(v int64) []byte {
	var b []byte
	for {
		b = append([]byte{byte(v)}, b...)
		v >>= 8
		if (v == 0 && b[0]&0x80 == 0) || (v == -1 && b[0]&0x80 != 0) {
			break
		}
	}
	return tlv(tagInteger, b)
}

// ---- reader ----

// readTLV reads one element with a single-byte tag and a definite length.
// It returns the tag, content and the remaining input.
func readTLV(b []byte) (tag byte, content, rest []byte, err error) {
	if len(b) < 2 {
		return 0, nil, nil, malformed("truncated header")
	}
	tag = b[0]
	if tag&0x1f == 0x1f {
		return 0, nil, nil, malformed("high tag number")
	}
	l := int(b[1])
	off := 2
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 3 || len(b) < 2+n {
			return 0, nil, nil, malformed("bad length")
		}
		l = 0
		for i := 0; i < n; i++ {
			l = l<<8 | int(b[2+i])
		}
		if l < 0x80 || (n > 1 && l < 1<<(8*(n-1))) {
			return 0, nil, nil, malformed("non-minimal length")
		}
		off += n
	}
	if l > maxDERLen || len(b)-off < l {
		return 0, nil, nil, malformed("length out of range")
	}
	return tag, b[off : off+l], b[off+l:], nil
}

// expect reads one element and requires the given tag and no trailing bytes.
func expect(b []byte, tag byte) ([]byte, error) {
	t, c, rest, err := readTLV(b)
	if err != nil {
		return nil, err
	}
	if t != tag || len(rest) != 0 {
		return nil, malformed("unexpected tag or trailing data")
	}
	return c, nil
}

// fields maps context tags [0..30] of a SEQUENCE body to the (single) inner
// element, rejecting duplicates and out-of-order tags. Unknown tags are kept
// (RFC 4120 extensibility) but never interpreted.
type fields map[int][]byte

func parseFields(body []byte) (fields, error) {
	f := fields{}
	last := -1
	for len(body) > 0 {
		t, c, rest, err := readTLV(body)
		if err != nil {
			return nil, err
		}
		if t&0xe0 != 0xa0 {
			return nil, malformed("expected context tag")
		}
		n := int(t & 0x1f)
		if n <= last {
			return nil, malformed("context tags out of order")
		}
		last = n
		f[n] = c
		body = rest
	}
	return f, nil
}

func (f fields) need(n int) ([]byte, error) {
	v, ok := f[n]
	if !ok {
		return nil, malformed(fmt.Sprintf("missing field [%d]", n))
	}
	return v, nil
}

func seqFields(b []byte) (fields, error) {
	body, err := expect(b, tagSequence)
	if err != nil {
		return nil, err
	}
	return parseFields(body)
}

func appFields(b []byte, n int) (fields, error) {
	inner, err := expect(b, 0x60|byte(n))
	if err != nil {
		return nil, err
	}
	return seqFields(inner)
}

func readInt(b []byte) (int64, error) {
	c, err := expect(b, tagInteger)
	if err != nil {
		return 0, err
	}
	if len(c) == 0 || len(c) > 8 {
		return 0, malformed("integer size")
	}
	if len(c) > 1 && ((c[0] == 0 && c[1]&0x80 == 0) || (c[0] == 0xff && c[1]&0x80 != 0)) {
		return 0, malformed("non-minimal integer")
	}
	v := int64(int8(c[0]))
	for _, x := range c[1:] {
		v = v<<8 | int64(x)
	}
	return v, nil
}

func readInt32(b []byte) (int32, error) {
	v, err := readInt(b)
	if err != nil || v < -1<<31 || v > 1<<31-1 {
		return 0, malformed("int32 range")
	}
	return int32(v), nil
}

func readUint32(b []byte) (uint32, error) {
	v, err := readInt(b)
	if err != nil || v < 0 || v > 1<<32-1 {
		return 0, malformed("uint32 range")
	}
	return uint32(v), nil
}

func readOctets(b []byte, max int) ([]byte, error) {
	c, err := expect(b, tagOctet)
	if err != nil {
		return nil, err
	}
	if len(c) > max {
		return nil, malformed("octet string too long")
	}
	return c, nil
}

func readString(b []byte) (string, error) {
	t, c, rest, err := readTLV(b)
	if err != nil || len(rest) != 0 {
		return "", malformed("string")
	}
	switch t {
	case tagGeneralStr, 0x0c, 0x16, 0x13:
	default:
		return "", malformed("string tag")
	}
	if len(c) > maxStringLen || !utf8.Valid(c) {
		return "", malformed("string content")
	}
	for _, r := range string(c) {
		if r < 0x20 || r == 0x7f {
			return "", malformed("control character in string")
		}
	}
	return string(c), nil
}

func readTime(b []byte) (time.Time, error) {
	c, err := expect(b, tagGenTime)
	if err != nil || len(c) != 15 || c[14] != 'Z' {
		return time.Time{}, malformed("time")
	}
	t, err := time.Parse("20060102150405Z", string(c))
	if err != nil {
		return time.Time{}, malformed("time value")
	}
	return t, nil
}

func readFlags(b []byte) (uint32, error) {
	c, err := expect(b, tagBitString)
	if err != nil || len(c) != 5 || c[0] > 7 {
		return 0, malformed("flags")
	}
	return uint32(c[1])<<24 | uint32(c[2])<<16 | uint32(c[3])<<8 | uint32(c[4]), nil
}

// readList applies fn to every element of a SEQUENCE OF.
func readList(b []byte, fn func(elem []byte) error) error {
	body, err := expect(b, tagSequence)
	if err != nil {
		return err
	}
	for n := 0; len(body) > 0; n++ {
		if n >= maxListLen {
			return malformed("list too long")
		}
		_, _, rest, err := readTLV(body)
		if err != nil {
			return err
		}
		if err := fn(body[:len(body)-len(rest)]); err != nil {
			return err
		}
		body = rest
	}
	return nil
}

// readNonce reads a 32-bit nonce. Real Xbox clients encode a random 32-bit
// value as a signed (two's complement) INTEGER, so about half of all nonces are
// negative on the wire; Xombie-style positive values above 2^31 are accepted
// too. The result is the 32-bit pattern; replies re-encode it as signed int32,
// which is the form the client sent and compares against.
func readNonce(b []byte) (uint32, error) {
	v, err := readInt(b)
	if err != nil || v < -1<<31 || v > 1<<32-1 {
		return 0, malformed("nonce range")
	}
	return uint32(v), nil
}
