// SPDX-License-Identifier: AGPL-3.0-only

package svc5

import (
	"context"
	"encoding/binary"
	"errors"
	"log"
	"strconv"
	"unicode/utf16"

	"openpak/xb-live/internal/xbfeature"
	"openpak/xb-live/services/xb-account/internal/enrol"
	"openpak/xb-live/services/xb-account/internal/voucher"
)

// Status values for the subscription-code and signup steps (dashboard table,
// see docs/xbox/account-service-protocol.md section 2).
const (
	errCodeInvalid = 0x80154007 // "This subscription code is invalid."
	errCodeUsed    = 0x80154009 // "This subscription code is already in use."
)

// OfferID is the 8-byte offer identifier answered to verifyvouchergetoffer and
// echoed by the dashboard in OfferingDetailsNoUser ("OPENPAK" + 0x01). There is
// one OpenPak offer; the value has no meaning beyond being echoed back.
const OfferID uint64 = 0x4f50454e50414b01

// VoucherChecker is voucher.Service's non-consuming check.
type VoucherChecker interface {
	Check(ctx context.Context, machineID, typed string) error
}

// Signups is enrol.Service's createowneracct side.
type Signups interface {
	CompleteSignup(ctx context.Context, machineID, typedCode, gamertag string) (enrol.Signup, error)
}

// parseVoucher decodes the verifyvoucher / verifyvouchergetoffer body: country
// byte, u16 LE length, code (UTF-8). The length must account for every byte and
// the whole body is at most 0x4e bytes (the client's request buffer).
func parseVoucher(b []byte) (country byte, code string, ok bool) {
	if len(b) < 3 || len(b) > 0x4e {
		return 0, "", false
	}
	n := int(binary.LittleEndian.Uint16(b[1:3]))
	if len(b) != 3+n || n == 0 {
		return 0, "", false
	}
	return b[0], string(b[3:]), true
}

func voucherStatus(err error) response {
	switch {
	case err == nil:
		return response{}
	case errors.Is(err, voucher.ErrBad):
		return xerr(errCodeInvalid)
	case errors.Is(err, voucher.ErrUsed):
		return xerr(errCodeUsed)
	case errors.Is(err, voucher.ErrRateLimited):
		return xerr(errAccountClosed)
	case errors.Is(err, voucher.ErrInvalid):
		return xerr(errCodeInvalid)
	}
	log.Printf("svc5 voucher: store error")
	return status(503)
}

// verifyVoucher answers verifyvoucher and verifyvouchergetoffer: the code is
// checked for this device's own account without being consumed; success carries
// the 8-byte offer id (client reader: 8 bytes at the start of the body).
func (s *Server) verifyVoucher(ctx context.Context, info xbfeature.Info, body []byte) response {
	_, code, ok := parseVoucher(body)
	if !ok {
		return status(400)
	}
	if err := s.Vouchers.Check(ctx, info.PrincipalID, code); err != nil {
		return voucherStatus(err)
	}
	return response{code: 200, hasErr: true, body: binary.LittleEndian.AppendUint64(nil, OfferID)}
}

// offeringDetails answers /xbos/OfferingDetailsNoUser.ashx. Request body (27
// bytes, from the client's request builder): country byte, machine id (8),
// u32, offer id (8), u32, u16. The reply is the client's offer record: a 21-byte
// binary header, a u32 text length and a UTF-16LE INI with a [SubInfo] section
// (VERSION must be 1; TITLE; PURCHASE_DETAILS).
func (s *Server) offeringDetails(_ context.Context, info xbfeature.Info, body []byte) response {
	if len(body) != 27 {
		return status(400)
	}
	if mid := binary.LittleEndian.Uint64(body[1:9]); strconv.FormatUint(mid, 16) == "" || !machineMatches(mid, info.PrincipalID) {
		return status(400)
	}
	if binary.LittleEndian.Uint64(body[13:21]) != OfferID {
		return xerr(errCodeInvalid)
	}
	text := encodeINI("SubInfo", [][2]string{
		{"VERSION", "1"},
		{"TITLE", "OpenPak Xbox Live"},
		{"PURCHASE_DETAILS", "Create your OpenPak Xbox Live account. No payment is needed."},
	})
	out := make([]byte, 0x15, 0x15+len(text))
	binary.LittleEndian.PutUint32(out[0x11:], uint32(len(text)))
	return response{code: 200, hasErr: true, body: append(out, text...)}
}

func machineMatches(id uint64, principal string) bool {
	v, err := strconv.ParseUint(principal, 16, 64)
	return err == nil && v == id
}

// encodeINI builds the dashboard's UTF-16LE text file (BOM, CR LF, values in
// double quotes, no escapes). Values must not contain '"' or CR.
func encodeINI(section string, kv [][2]string) []byte {
	units := []uint16{0xFEFF}
	add := func(s string) { units = append(units, utf16.Encode([]rune(s))...) }
	add("[" + section + "]\r\n")
	for _, p := range kv {
		add(p[0] + "=\"" + p[1] + "\"\r\n")
	}
	b := make([]byte, 0, 2*len(units))
	for _, u := range units {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	return b
}

// Client request layout of createowneracct (from the request builder): a
// 34-byte fixed part (machine id at 0; signup-record words; country byte at
// 22) then 19 strings, each u16 LE length + UTF-8; the first is the gamertag,
// the last the subscription code.
const (
	ownerFixed   = 34
	ownerStrings = 19
)

func parseOwner(b []byte) (machine uint64, gamertag, code string, ok bool) {
	if len(b) < ownerFixed {
		return 0, "", "", false
	}
	machine = binary.LittleEndian.Uint64(b[0:8])
	rest := b[ownerFixed:]
	var strs [ownerStrings]string
	for i := range strs {
		if len(rest) < 2 {
			return 0, "", "", false
		}
		n := int(binary.LittleEndian.Uint16(rest))
		if len(rest) < 2+n {
			return 0, "", "", false
		}
		strs[i], rest = string(rest[2:2+n]), rest[2+n:]
	}
	if len(rest) != 0 {
		return 0, "", "", false
	}
	return machine, strs[0], strs[ownerStrings-1], true
}

// createOwner answers createowneracct: it consumes the subscription code and
// creates the Xbox user via enrol.CompleteSignup, then returns the account
// record the console stores: XUID (8, LE), account key (16), domain (20, NUL
// padded), realm (24, NUL padded), the layout the client's reply handler copies
// into its stored user (key at stored offset 0x50, domain 0x24, realm 0x38).
func (s *Server) createOwner(ctx context.Context, info xbfeature.Info, body []byte) response {
	mid, gamertag, code, ok := parseOwner(body)
	if !ok || !machineMatches(mid, info.PrincipalID) {
		return status(400)
	}
	if !ValidName(gamertag) {
		return xerr(errInvalidName)
	}
	su, err := s.Signups.CompleteSignup(ctx, info.PrincipalID, code, gamertag)
	switch {
	case err == nil:
	case errors.Is(err, enrol.ErrVoucherBad), errors.Is(err, enrol.ErrInvalid):
		return xerr(errCodeInvalid)
	case errors.Is(err, enrol.ErrVoucherUsed):
		return xerr(errCodeUsed)
	case errors.Is(err, enrol.ErrGamertagTaken):
		return xerr(errNameTaken)
	case errors.Is(err, enrol.ErrRateLimited), errors.Is(err, enrol.ErrNoDevice):
		return xerr(errAccountClosed)
	default:
		log.Printf("svc5 createowneracct: signup error")
		return status(503)
	}
	xuid, err := strconv.ParseUint(su.XUID, 16, 64)
	if err != nil {
		log.Printf("svc5 createowneracct: bad xuid")
		return status(503)
	}
	blob, err := s.AccountBlob(xuid)
	if err != nil {
		log.Printf("svc5 createowneracct: account record unavailable")
		return status(503)
	}
	return response{code: 200, hasErr: true, body: blob}
}

// AccountRecord builds the createowneracct reply: xuid (8, LE), key (16),
// domain (20, NUL padded), realm (24, NUL padded).
func AccountRecord(xuid uint64, key [16]byte, domain, realm string) ([]byte, error) {
	if len(domain) >= 20 || len(realm) >= 24 {
		return nil, errors.New("svc5: account field too long")
	}
	b := make([]byte, 8+16+20+24)
	binary.LittleEndian.PutUint64(b, xuid)
	copy(b[8:], key[:])
	copy(b[24:], domain)
	copy(b[44:], realm)
	return b, nil
}
