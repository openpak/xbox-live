// SPDX-License-Identifier: AGPL-3.0-only

package svc5

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"openpak/xb-live/services/xb-account/internal/enrol"
	"openpak/xb-live/services/xb-account/internal/voucher"
)

type fakeV struct{ err error }

func (f fakeV) Check(context.Context, string, string) error { return f.err }

type fakeS struct {
	err        error
	gotMachine string
	gotCode    string
	gotName    string
}

func (f *fakeS) CompleteSignup(_ context.Context, m, c, g string) (enrol.Signup, error) {
	f.gotMachine, f.gotCode, f.gotName = m, c, g
	return enrol.Signup{XUID: "0009d941ad372efd", Gamertag: g}, f.err
}

func vbody(code string) []byte {
	b := []byte{103}
	b = binary.LittleEndian.AppendUint16(b, uint16(len(code)))
	return append(b, code...)
}

func ownerBody(machine uint64, name, code string) []byte {
	b := make([]byte, ownerFixed)
	binary.LittleEndian.PutUint64(b, machine)
	for i := 0; i < ownerStrings; i++ {
		s := "x"
		if i == 0 {
			s = name
		} else if i == ownerStrings-1 {
			s = code
		}
		b = binary.LittleEndian.AppendUint16(b, uint16(len(s)))
		b = append(b, s...)
	}
	return b
}

func newSignupServer(t *testing.T, v error, s *fakeS) *Server {
	srv, _ := newServer(t)
	srv.Vouchers = fakeV{v}
	srv.Signups = s
	srv.AccountBlob = func(x uint64) ([]byte, error) {
		return AccountRecord(x, [16]byte{1, 2, 3}, "xbox.com", "passport.net")
	}
	return srv
}

func TestVerifyVoucher(t *testing.T) {
	code := "ABCDEFGHJKLMNPQRSTUVWXYZ2"
	for _, path := range []string{"/xuacs/verifyvoucher.ashx", "/xuacs/verifyvouchergetoffer.ashx"} {
		r := do(t, newSignupServer(t, nil, &fakeS{}), infoA, "POST", path, "xon/5", vbody(code))
		want := binary.LittleEndian.AppendUint64(nil, OfferID)
		if !strings.HasPrefix(r, "HTTP/1.0 200") || !strings.Contains(r, "X-Err: 0\r\n") || !strings.HasSuffix(r, string(want)) {
			t.Fatalf("%s: %q", path, r)
		}
	}
	for _, c := range []struct {
		err  error
		want string
	}{{voucher.ErrBad, "X-Err: 80154007"}, {voucher.ErrUsed, "X-Err: 80154009"}, {voucher.ErrRateLimited, "X-Err: 8015400a"}, {voucher.ErrUnavailable, "HTTP/1.0 503"}} {
		r := do(t, newSignupServer(t, c.err, &fakeS{}), infoA, "POST", "/xuacs/verifyvoucher.ashx", "xon/5", vbody(code))
		if !strings.Contains(r, c.want) || strings.Contains(r, code) {
			t.Fatalf("%v: %q", c.err, r)
		}
	}
	// malformed: length lies, empty
	if r := do(t, newSignupServer(t, nil, &fakeS{}), infoA, "POST", "/xuacs/verifyvoucher.ashx", "xon/5", append(vbody(code), 'x')); !strings.HasPrefix(r, "HTTP/1.0 400") {
		t.Fatal(r)
	}
}

func TestCreateOwner(t *testing.T) {
	f := &fakeS{}
	srv := newSignupServer(t, nil, f)
	r := do(t, srv, infoA, "POST", "/xuacs/createowneracct.ashx", "xon/5", ownerBody(0xce0d452f69, "OpenPakTest", "ABCDEFGHJKLMNPQRSTUVWXYZ2"))
	_, bodyPart, _ := strings.Cut(r, "\r\n\r\n")
	if !strings.Contains(r, "X-Err: 0\r\n") || len(bodyPart) != 68 || f.gotName != "OpenPakTest" || f.gotMachine != machineA {
		t.Fatalf("%q %+v", r, f)
	}
	b := []byte(bodyPart)
	if binary.LittleEndian.Uint64(b) != 0x0009d941ad372efd || !bytes.Equal(b[8:11], []byte{1, 2, 3}) || string(bytes.TrimRight(b[24:44], "\x00")) != "xbox.com" || string(bytes.TrimRight(b[44:], "\x00")) != "passport.net" {
		t.Fatalf("%x", b)
	}
	for _, c := range []struct {
		err  error
		want string
	}{{enrol.ErrVoucherBad, "X-Err: 80154007"}, {enrol.ErrVoucherUsed, "X-Err: 80154009"}, {enrol.ErrGamertagTaken, "X-Err: 80154000"}, {enrol.ErrNoDevice, "X-Err: 8015400a"}, {enrol.ErrUnavailable, "HTTP/1.0 503"}} {
		r := do(t, newSignupServer(t, nil, &fakeS{err: c.err}), infoA, "POST", "/xuacs/createowneracct.ashx", "xon/5", ownerBody(0xce0d452f69, "OpenPakTest", "ABCDEFGHJKLMNPQRSTUVWXYZ2"))
		if !strings.Contains(r, c.want) || strings.Contains(r, "OpenPakTest") {
			t.Fatalf("%v: %q", c.err, r)
		}
	}
	// machine id inside the body must be the ticket's device; bad names; truncation
	for name, b := range map[string][]byte{
		"other machine": ownerBody(1, "OpenPakTest", "C"),
		"truncated":     ownerBody(0xce0d452f69, "OpenPakTest", "C")[:50],
		"trailing":      append(ownerBody(0xce0d452f69, "OpenPakTest", "C"), 0),
	} {
		if r := do(t, newSignupServer(t, nil, &fakeS{}), infoA, "POST", "/xuacs/createowneracct.ashx", "xon/5", b); !strings.HasPrefix(r, "HTTP/1.0 400") {
			t.Fatalf("%s: %q", name, r)
		}
	}
	if r := do(t, newSignupServer(t, nil, &fakeS{}), infoA, "POST", "/xuacs/createowneracct.ashx", "xon/5", ownerBody(0xce0d452f69, "1bad", "C")); !strings.Contains(r, "X-Err: 80154002") {
		t.Fatal(r)
	}
}

func TestOfferingDetails(t *testing.T) {
	b := make([]byte, 27)
	b[0] = 103
	binary.LittleEndian.PutUint64(b[1:], 0xce0d452f69)
	binary.LittleEndian.PutUint64(b[13:], OfferID)
	r := do(t, newSignupServer(t, nil, &fakeS{}), infoA, "POST", "/xbos/OfferingDetailsNoUser.ashx", "xon/4", b)
	_, p, _ := strings.Cut(r, "\r\n\r\n")
	n := int(binary.LittleEndian.Uint32([]byte(p)[0x11:]))
	if !strings.Contains(r, "X-Err: 0\r\n") || len(p) != 0x15+n || p[0x15] != 0xff || p[0x16] != 0xfe {
		t.Fatalf("%q", r)
	}
	binary.LittleEndian.PutUint64(b[13:], 7)
	if r := do(t, newSignupServer(t, nil, &fakeS{}), infoA, "POST", "/xbos/OfferingDetailsNoUser.ashx", "xon/4", b); !strings.Contains(r, "X-Err: 80154007") {
		t.Fatal(r)
	}
	if r := do(t, newSignupServer(t, nil, &fakeS{}), infoA, "POST", "/xbos/OfferingDetailsNoUser.ashx", "xon/5", b); !strings.HasPrefix(r, "HTTP/1.0 400") {
		t.Fatal(r)
	}
}
