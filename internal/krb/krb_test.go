// SPDX-License-Identifier: AGPL-3.0-only
package krb

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
	"time"

	"openpak/xb-live/internal/xbcrypto"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Public Xombie fixture (internal/xbcrypto test): a PA-ENC-TS-ENC plaintext.
func TestPAEncTimestampFixture(t *testing.T) {
	raw := unhex(t, "301aa011180f32303230303431353033313735325aa10502030e9a48")
	p, err := ParsePAEncTSEnc(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Time.Equal(time.Date(2020, 4, 15, 3, 17, 52, 0, time.UTC)) || p.Usec != 0x0e9a48 {
		t.Fatalf("unexpected %v %d", p.Time, p.Usec)
	}
	if !bytes.Equal(p.Marshal(), raw) {
		t.Fatal("re-encoding differs from the Xombie fixture")
	}
}

// Fixture from Xombie libs/xblive/src/krb/service.rs tests.
const serviceRequestHex = `0100 6c00 0100 0000 2d17 0100 1201 ffff 00001000 07000080
 0000000000000000 0000000000000000 0000000000000000 0000000000000000
 02000000 06000000 14000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000`

func TestServiceRequestFixture(t *testing.T) {
	raw := unhex(t, serviceRequestHex)
	r, err := ParseServiceRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if r.LibraryVersion != [4]uint16{1, 0, 0x172d, 1} || r.TitleID != 0xffff0112 || r.TitleVersion != 0x100000 ||
		r.TitleRegion != 0x80000007 || r.NumServices != 2 || r.ServiceIDs[0] != 6 || r.ServiceIDs[1] != 20 {
		t.Fatalf("unexpected %+v", r)
	}
	if !bytes.Equal(r.Marshal(), raw) {
		t.Fatal("re-encoding differs")
	}
	for _, bad := range [][]byte{raw[:107], append(bytes.Clone(raw), 0)} {
		if _, err := ParseServiceRequest(bad); err == nil {
			t.Fatal("accepted wrong length")
		}
	}
	for _, mut := range []func([]byte){
		func(b []byte) { b[0] = 2 },    // version
		func(b []byte) { b[2] = 0x6d }, // size
		func(b []byte) { b[56] = 13 },  // num_services
	} {
		b := bytes.Clone(raw)
		mut(b)
		if _, err := ParseServiceRequest(b); err == nil {
			t.Fatal("accepted invalid header")
		}
	}
}

func TestServiceAddressLayout(t *testing.T) {
	a := &ServiceAddress{HR: 0x971ebb52, BWLimit: 0x1cc7bab4, SiteIP: netip.MustParseAddr("5.108.171.232"), NumServices: 3}
	a.HRUser = [4]uint32{1, 2, 3, 4}
	a.Results[0] = ServiceResult{ID: 0x98765432, HR: 0x87654321, Port: 0xfeff}
	b := a.Marshal()
	if len(b) != 0xe0 {
		t.Fatalf("size %#x", len(b))
	}
	if !bytes.Equal(b[0x48:0x4c], []byte{5, 108, 171, 232}) {
		t.Fatal("site ip must be network order at 0x48")
	}
	// ServiceResult wire fixture from Xombie: 32547698 21436587 fffe 0000 (reserved zero).
	if !bytes.Equal(b[0x50:0x5c], unhex(t, "32547698 21436587 fffe 0000")) {
		t.Fatalf("result bytes %x", b[0x50:0x5c])
	}
	back, err := ParseServiceAddress(b)
	if err != nil || *back != *a {
		t.Fatalf("roundtrip %v", err)
	}
}

func TestStructuresRoundTrip(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	kvno := uint32(7)
	name := PrincipalName{Type: NameTypeEnterprise, Parts: []string{"Player One@xbox.com"}}
	start := now.Add(-time.Second)
	e := &EncTicketPart{Flags: FlagInitial | FlagPreAuth, Key: EncryptionKey{ETypeRC4HMAC, bytes.Repeat([]byte{1}, 16)},
		CRealm: "passport.net", CName: name, Transited: Transited{1, []byte("passport.net\x00")},
		AuthTime: now, StartTime: &start, EndTime: now.Add(time.Hour),
		AuthData: []AuthData{{ADUsers, []byte{1, 2, 3, 4, 5, 6, 7, 8}}}}
	got, err := ParseEncTicketPart(e.Marshal())
	if err != nil || !bytes.Equal(got.Marshal(), e.Marshal()) {
		t.Fatalf("enc ticket part: %v", err)
	}
	tk := Ticket{VNO: 5, Realm: "passport.net", SName: PrincipalName{NameTypeSrvInst, []string{"krbtgt", "XBOX.COM"}},
		Enc: EncryptedData{ETypeRC4HMAC, &kvno, bytes.Repeat([]byte{9}, 40)}}
	pt, err := ParseTicket(tk.Marshal())
	if err != nil || *pt.Enc.KVNO != 7 || !bytes.Equal(pt.Marshal(), tk.Marshal()) {
		t.Fatalf("ticket: %v", err)
	}
	auth := &Authenticator{"passport.net", name, 123456, now}
	pa, err := ParseAuthenticator(auth.Marshal())
	if err != nil || !bytes.Equal(pa.Marshal(), auth.Marshal()) {
		t.Fatalf("authenticator: %v", err)
	}
	ee := &Error{STime: now, Code: ErrAPSkew, Realm: "passport.net", SName: tk.SName, CName: &name}
	pe, err := ParseError(ee.Marshal())
	if err != nil || pe.Code != ErrAPSkew || !IsError(ee.Marshal()) {
		t.Fatalf("error: %v", err)
	}
	for _, v := range []int64{0, 1, 127, 128, 255, 256, 65535, 1 << 31, 0xffffffff, -1, -128, -129} {
		got, err := readInt(intg(v))
		if err != nil || got != v {
			t.Fatalf("int %d -> %d %v", v, got, err)
		}
	}
}

func TestParseKDCReqRejectsMalformed(t *testing.T) {
	name := PrincipalName{NameTypeEnterprise, []string{"Player@xbox.com"}}
	req := MarshalKDCReq(&KDCReq{MsgType: MsgASReq, CName: &name, Realm: "passport.net", Nonce: 0xdeadbeef,
		ETypes: []int32{ETypeRC4HMAC}, PAData: []PAData{{PAXboxClientVersion, []byte{1}}}})
	r, err := ParseKDCReq(req)
	if err != nil || r.Nonce != 0xdeadbeef || r.CName == nil || len(r.PAData) != 1 {
		t.Fatalf("valid request rejected: %v", err)
	}
	if _, err := ParseKDCReq(append(bytes.Clone(req), 0)); err == nil {
		t.Fatal("accepted trailing byte")
	}
	for i := 0; i < len(req); i++ {
		if _, err := ParseKDCReq(req[:i]); err == nil {
			t.Fatalf("accepted truncation at %d", i)
		}
	}
	for i := range req { // never panic on single-byte corruption
		b := bytes.Clone(req)
		b[i] ^= 0xff
		ParseKDCReq(b)
	}
	if _, err := ParseKDCReq([]byte{0x6a, 0x84, 0xff, 0xff, 0xff, 0xff}); err == nil {
		t.Fatal("accepted oversized length")
	}
}

func FuzzParseKDCReq(f *testing.F) {
	name := PrincipalName{NameTypeEnterprise, []string{"Player@xbox.com"}}
	f.Add(MarshalKDCReq(&KDCReq{MsgType: MsgASReq, CName: &name, Realm: "r", ETypes: []int32{23}}))
	f.Add(MarshalKDCReq(&KDCReq{MsgType: MsgTGSReq, Realm: "r", ETypes: []int32{23}, PAData: []PAData{{1, []byte{1, 2}}}}))
	f.Fuzz(func(t *testing.T, b []byte) {
		ParseKDCReq(b)
		ParseAPReq(b)
		ParseTicketSequence(b)
		ParseEncTicketPart(b)
		ParseAuthenticator(b)
		ParseServiceRequest(b)
	})
}

func TestKeyringValidation(t *testing.T) {
	good := `{"active":2,"keys":{"1":"00112233445566778899aabbccddeeff","2":"ffeeddccbbaa99887766554433221100"}}`
	k, err := ParseKeyring([]byte(good), 16)
	if err != nil {
		t.Fatal(err)
	}
	if id, _ := k.Active(); id != 2 || k.IDs()[0] != 2 || k.IDs()[1] != 1 {
		t.Fatal("rotation order")
	}
	for name, bad := range map[string]string{
		"missing active": `{"active":3,"keys":{"1":"00112233445566778899aabbccddeeff"}}`,
		"zero key":       `{"active":1,"keys":{"1":"00000000000000000000000000000000"}}`,
		"short":          `{"active":1,"keys":{"1":"0011"}}`,
		"id zero":        `{"active":0,"keys":{"0":"00112233445566778899aabbccddeeff"}}`,
		"public key":     `{"active":1,"keys":{"1":"205cbb97cff0058123c22658fecd6898"}}`,
		"duplicate":      `{"active":1,"keys":{"1":"00112233445566778899aabbccddeeff","2":"00112233445566778899aabbccddeeff"}}`,
		"unknown field":  `{"active":1,"keys":{"1":"00112233445566778899aabbccddeeff"},"x":1}`,
		"empty":          `{}`,
	} {
		if _, err := ParseKeyring([]byte(bad), 16); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestDeriveUserKeyIsDeterministicAndSeparated(t *testing.T) {
	s1, s2 := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	if DeriveUserKey(s1, 5) != DeriveUserKey(s1, 5) || DeriveUserKey(s1, 5) == DeriveUserKey(s1, 6) ||
		DeriveUserKey(s1, 5) == DeriveUserKey(s2, 5) {
		t.Fatal("derivation not deterministic/separated")
	}
	a, _ := NewSessionKey()
	b, _ := NewSessionKey()
	if a == b || a == (xbcrypto.Key{}) {
		t.Fatal("session keys must be random")
	}
}
