// SPDX-License-Identifier: AGPL-3.0-only
// Derived from the discovery table of Xombie services/faux-dns (AGPL-3.0);
// see servers/xbox-live/docs/provenance.md. Go rewrite, exact-name only.

// Package xbdns answers original-Xbox discovery queries for a fixed set of
// exact names. It never recurses and never matches by suffix.
package xbdns

import "net/netip"

const (
	MaxQuery  = 512 // larger datagrams are dropped, not parsed
	headerLen = 12
	maxName   = 255

	RcodeOK       = 0
	RcodeFormErr  = 1
	RcodeNXDomain = 3
	RcodeNotImp   = 4
	RcodeRefused  = 5

	TypeA   = 1
	TypeANY = 255
	ClassIN = 1
	// TTL matches the 117 s used by the Xombie source.
	TTL = 117
)

// Auth names known from the Xombie source. All map to the main auth address.
var AuthNames = []string{
	"as.xboxlive.com", "as.part.xboxlive.com",
	"macs.xboxlive.com", "macs.part.xboxlive.com",
	"tgs.xboxlive.com", "tgs.part.xboxlive.com",
}

// Table maps exact lowercase names to IPv4 addresses.
type Table map[string]netip.Addr

// Answer builds the response for req, or returns nil when the datagram must be
// dropped silently (too short, oversized, or itself a response).
func (t Table) Answer(req []byte) (resp []byte, rcode int, hit bool) {
	if len(req) < headerLen || len(req) > MaxQuery {
		return nil, 0, false
	}
	flags := uint16(req[2])<<8 | uint16(req[3])
	if flags&0x8000 != 0 { // QR set: never answer responses
		return nil, 0, false
	}
	id := req[0:2]
	rd := flags & 0x0100
	opcode := (flags >> 11) & 0xf
	mk := func(rc int, question []byte, ans *netip.Addr) []byte {
		out := make([]byte, 0, headerLen+len(question)+16)
		f := 0x8000 | rd | uint16(rc)
		if rc != RcodeFormErr && rc != RcodeNotImp {
			f |= 0x0400 // AA
		}
		an := byte(0)
		if ans != nil {
			an = 1
		}
		qd := byte(0)
		if question != nil {
			qd = 1
		}
		out = append(out, id[0], id[1], byte(f>>8), byte(f), 0, qd, 0, an, 0, 0, 0, 0)
		out = append(out, question...)
		if ans != nil {
			a := ans.As4()
			out = append(out, 0xc0, 0x0c, 0, TypeA, 0, ClassIN,
				byte(TTL>>24), byte(TTL>>16), byte(TTL>>8), byte(TTL), 0, 4, a[0], a[1], a[2], a[3])
		}
		return out
	}
	if opcode != 0 {
		return mk(RcodeNotImp, nil, nil), RcodeNotImp, false
	}
	qd := int(req[4])<<8 | int(req[5])
	if qd != 1 {
		return mk(RcodeFormErr, nil, nil), RcodeFormErr, false
	}
	name, end, ok := readName(req, headerLen)
	if !ok || end+4 > len(req) {
		return mk(RcodeFormErr, nil, nil), RcodeFormErr, false
	}
	qtype := uint16(req[end])<<8 | uint16(req[end+1])
	qclass := uint16(req[end+2])<<8 | uint16(req[end+3])
	question := req[headerLen : end+4]
	// Anything after the question must be an additional section (EDNS) we
	// ignore; answer/authority counts in a query must be zero.
	if req[6]|req[7]|req[8]|req[9] != 0 {
		return mk(RcodeFormErr, nil, nil), RcodeFormErr, false
	}
	if qclass != ClassIN {
		return mk(RcodeRefused, nil, nil), RcodeRefused, false
	}
	addr, known := t[name]
	if !known {
		return mk(RcodeNXDomain, question, nil), RcodeNXDomain, false
	}
	if qtype == TypeA || qtype == TypeANY {
		return mk(RcodeOK, question, &addr), RcodeOK, true
	}
	return mk(RcodeOK, question, nil), RcodeOK, true // NODATA
}

// readName parses an uncompressed question name into lowercase dotted form.
// Compression pointers, over-long labels/names and bad bounds are rejected.
func readName(b []byte, off int) (string, int, bool) {
	var name []byte
	for {
		if off >= len(b) {
			return "", 0, false
		}
		l := int(b[off])
		off++
		if l == 0 {
			break
		}
		if l > 63 || off+l > len(b) { // also rejects 0xC0 pointers
			return "", 0, false
		}
		if len(name)+l+1 > maxName {
			return "", 0, false
		}
		if len(name) > 0 {
			name = append(name, '.')
		}
		for _, c := range b[off : off+l] {
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			name = append(name, c)
		}
		off += l
	}
	if len(name) == 0 {
		return "", 0, false
	}
	return string(name), off, true
}
