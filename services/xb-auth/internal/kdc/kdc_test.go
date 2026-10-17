// SPDX-License-Identifier: AGPL-3.0-only
package kdc_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"openpak/xb-live/internal/krb"
	"openpak/xb-live/internal/xbaccountapi"
	"openpak/xb-live/internal/xbcrypto"
	"openpak/xb-live/services/xb-auth/internal/kdc"
	"openpak/xb-live/services/xb-auth/internal/memresolver"
)

const (
	tag       = "PlayerOne"
	xuid      = uint64(0x0009000000000001)
	xuidHex   = "0009000000000001"
	gatewayIP = "145.241.228.207"
	otherXUID = uint64(0x0009000000000002)
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func ring(t testing.TB, size int, active uint32, ids ...uint32) *krb.Keyring {
	t.Helper()
	keys := ""
	for i, id := range ids {
		k := make([]byte, size)
		for j := range k {
			k[j] = byte(int(id)*17 + j + size + i*3 + 1)
		}
		if i > 0 {
			keys += ","
		}
		keys += fmt.Sprintf("%q:%q", fmt.Sprint(id), hex.EncodeToString(k))
	}
	r, err := krb.ParseKeyring([]byte(fmt.Sprintf(`{"active":%d,"keys":{%s}}`, active, keys)), size)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

type env struct {
	t     *testing.T
	clock *clock
	res   *memresolver.Resolver
	kdc   *kdc.KDC
	cfg   kdc.Config
}

func newEnv(t *testing.T, mutate ...func(*kdc.Config)) *env {
	t.Helper()
	e := &env{t: t, clock: &clock{t: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}, res: memresolver.New()}
	e.res.SetUser(tag, xuidHex, xbaccountapi.StatusActive)
	e.cfg = kdc.DefaultConfig()
	e.cfg.Now = e.clock.Now
	e.cfg.TGSKeys = ring(t, 16, 1, 1)
	e.cfg.SGKeys = ring(t, 16, 5, 4, 5)
	e.cfg.UserKeys = ring(t, 32, 1, 1)
	for _, m := range mutate {
		m(&e.cfg)
	}
	var err error
	if e.kdc, err = kdc.New(e.cfg, e.res, e.res); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) userKey() xbcrypto.Key {
	id, secret := e.cfg.UserKeys.Active()
	_ = id
	return krb.DeriveUserKey(secret, xuid)
}

func (e *env) handle(b []byte) []byte { return e.kdc.Handle(context.Background(), b) }

func cname() *krb.PrincipalName {
	return &krb.PrincipalName{Type: krb.NameTypeEnterprise, Parts: []string{tag + "@xbox.com"}}
}

func tgsName() krb.PrincipalName {
	return krb.PrincipalName{Type: krb.NameTypeSrvInst, Parts: []string{"krbtgt", "XBOX.COM"}}
}

func (e *env) asReq(key xbcrypto.Key, ts time.Time, nonce uint32, mutate ...func(*krb.KDCReq)) []byte {
	e.t.Helper()
	enc, err := krb.Seal(key, krb.UsageASReqTimestamp, nil, krb.PAEncTSEnc{Time: ts, Usec: 4242}.Marshal())
	if err != nil {
		e.t.Fatal(err)
	}
	sn := tgsName()
	r := &krb.KDCReq{MsgType: krb.MsgASReq, CName: cname(), Realm: "passport.net", SName: &sn, Nonce: nonce,
		ETypes: []int32{krb.ETypeRC4HMAC},
		PAData: []krb.PAData{{Type: krb.PAXboxClientVersion, Value: []byte{1, 2, 3}}, {Type: krb.PAEncTimestamp, Value: enc.Marshal()}}}
	for _, m := range mutate {
		m(r)
	}
	return krb.MarshalKDCReq(r)
}

type tgt struct {
	ticket  krb.Ticket
	session xbcrypto.Key
	end     time.Time
}

func (e *env) mustErr(reply []byte, code int32) {
	e.t.Helper()
	if !krb.IsError(reply) {
		if reply == nil {
			e.t.Fatalf("expected KRB-ERROR %d, request was dropped", code)
		}
		e.t.Fatalf("expected KRB-ERROR %d, got %x...", code, reply[:min(8, len(reply))])
	}
	pe, err := krb.ParseError(reply)
	if err != nil || pe.Code != code {
		e.t.Fatalf("expected error %d, got %+v %v", code, pe, err)
	}
}

func (e *env) login() tgt {
	e.t.Helper()
	key := e.userKey()
	reply := e.handle(e.asReq(key, e.clock.Now(), 0x11223344))
	if reply == nil || krb.IsError(reply) {
		e.t.Fatalf("AS failed: %x", reply)
	}
	rep, err := krb.ParseKDCRep(reply, krb.MsgASRep)
	if err != nil {
		e.t.Fatal(err)
	}
	plain, err := krb.Open(key, krb.UsageKDCRepPart, rep.Enc)
	if err != nil {
		e.t.Fatal("AS-REP does not open with the user key:", err)
	}
	part, err := krb.ParseEncKDCRepPart(plain, krb.MsgASRep)
	if err != nil || part.Nonce != 0x11223344 {
		e.t.Fatalf("bad AS-REP part: %v", err)
	}
	s, _ := krb.ToKey(part.Key.Value)
	return tgt{rep.Ticket, s, part.EndTime}
}

type tgsOpts struct {
	nonce   uint32
	xuids   [4]uint64
	ids     []uint32
	skipSR  bool
	authKey *xbcrypto.Key
	ctime   *time.Time
	cname   *krb.PrincipalName
	sname   *krb.PrincipalName
}

func (e *env) tgsReq(t tgt, o tgsOpts) []byte {
	e.t.Helper()
	if o.nonce == 0 {
		o.nonce = 0x55667788
	}
	ctime := e.clock.Now()
	if o.ctime != nil {
		ctime = *o.ctime
	}
	cn := *cname()
	if o.cname != nil {
		cn = *o.cname
	}
	authKey := t.session
	if o.authKey != nil {
		authKey = *o.authKey
	}
	auth, _ := krb.Seal(authKey, krb.UsageTGSReqAuth, nil,
		(&krb.Authenticator{CRealm: "passport.net", CName: cn, CUsec: 99, CTime: ctime}).Marshal())
	ap := (&krb.APReq{Ticket: t.ticket, Authenticator: auth}).Marshal()
	pas := []krb.PAData{{Type: krb.PAAPReq, Value: ap}}
	if !o.skipSR {
		sr := &krb.ServiceRequest{StructVersion: 1, StructSize: krb.ServiceRequestSize, LibraryVersion: [4]uint16{1, 0, 0x172d, 1},
			TitleID: 0xffff0112, XUIDs: o.xuids, NumServices: uint32(len(o.ids))}
		copy(sr.ServiceIDs[:], o.ids)
		enc, _ := krb.Seal(xbcrypto.NonceKey(t.session, o.nonce), krb.UsageServiceRequest, nil, sr.Marshal())
		pas = append(pas, krb.PAData{Type: krb.PAXboxServiceRequest, Value: enc.Marshal()})
	}
	sn := krb.PrincipalName{Type: krb.NameTypeSrvInst, Parts: []string{"xbox", "gw"}}
	if o.sname != nil {
		sn = *o.sname
	}
	return krb.MarshalKDCReq(&krb.KDCReq{MsgType: krb.MsgTGSReq, Realm: "XBOX.COM", SName: &sn, Nonce: o.nonce,
		ETypes: []int32{krb.ETypeRC4HMAC}, PAData: pas})
}

func le(x uint64) []byte { b := make([]byte, 8); binary.LittleEndian.PutUint64(b, x); return b }

// The headline test: AS -> TGS in-process, every field checked from the
// client's point of view and from the gateway's.
func TestASThenTGS(t *testing.T) {
	e := newEnv(t)
	tk := e.login()
	if tk.ticket.VNO != kdc.TGTTicketVNO || tk.ticket.Enc.KVNO == nil || *tk.ticket.Enc.KVNO != 1 {
		t.Fatalf("TGT envelope %+v", tk.ticket)
	}
	if !tk.end.Equal(e.clock.Now().Add(24 * time.Hour)) {
		t.Fatalf("TGT end %v", tk.end)
	}
	if tk.session == (xbcrypto.Key{}) {
		t.Fatal("zero session key")
	}

	req := e.tgsReq(tk, tgsOpts{xuids: [4]uint64{xuid, 0, otherXUID, 0}, ids: []uint32{6, 20, 0, 21}})
	reply := e.handle(req)
	if reply == nil || krb.IsError(reply) {
		t.Fatalf("TGS failed: %x", reply)
	}
	rep, err := krb.ParseKDCRep(reply, krb.MsgTGSRep)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := krb.Open(tk.session, krb.UsageKDCRepPart, rep.Enc)
	if err != nil {
		t.Fatal("TGS-REP part does not open with the TGT session key")
	}
	part, err := krb.ParseEncKDCRepPart(plain, krb.MsgTGSRep)
	if err != nil || part.Nonce != 0x55667788 {
		t.Fatalf("part %v", err)
	}

	// PA_XBOX_SERVICE_ADDRESS: encrypted under the nonce key, advertises the
	// configured public gateway and per-service ports.
	enc, ok := krb.FindPA(rep.PAData, krb.PAXboxServiceAddress)
	if !ok {
		t.Fatal("no PA_XBOX_SERVICE_ADDRESS")
	}
	ed, err := krb.ParseEncryptedData(enc)
	if err != nil {
		t.Fatal(err)
	}
	ab, err := krb.Open(xbcrypto.NonceKey(tk.session, 0x55667788), krb.UsageServiceAddress, ed)
	if err != nil {
		t.Fatal("service address does not open:", err)
	}
	addr, err := krb.ParseServiceAddress(ab)
	if err != nil {
		t.Fatal(err)
	}
	if addr.SiteIP != netip.MustParseAddr(gatewayIP) || addr.HR != 0 || addr.NumServices != 4 {
		t.Fatalf("address %+v", addr)
	}
	if r := addr.Results[0]; r.ID != 6 || r.HR != 0 || r.Port != 106 {
		t.Fatalf("service 6: %+v", r)
	}
	if r := addr.Results[1]; r.ID != 20 || r.HR != 0 || r.Port != 120 {
		t.Fatalf("service 20: %+v", r)
	}
	if r := addr.Results[2]; r.HR != krb.HRInvalidService || r.Port != 0 {
		t.Fatalf("service 0: %+v", r)
	}
	if r := addr.Results[3]; r.ID != 21 || r.HR != krb.HRUnknownService || r.Port != 0 {
		t.Fatalf("service 21: %+v", r)
	}
	if addr.HRUser != [4]uint32{krb.HRSuccess, krb.HRInvalidService, krb.HRAccessDenied, krb.HRInvalidService} {
		t.Fatalf("user results %x (another user's xuid must not be granted)", addr.HRUser)
	}
	// The granted user carries the country byte in bits 8..15; ungranted slots carry nothing.
	if want := [4]uint32{uint32(kdc.DefaultUserCountryID) << 8, 0, 0, 0}; addr.UserFlags != want {
		t.Fatalf("user flags %x, want %x", addr.UserFlags, want)
	}

	// Gateway side: the service ticket opens with the shared SG ring only.
	svc, err := krb.OpenTicket(e.cfg.SGKeys, krb.UsageSGTicket, rep.Ticket)
	if err != nil {
		t.Fatal("gateway cannot open the ticket:", err)
	}
	if *rep.Ticket.Enc.KVNO != 5 || rep.Ticket.SName.Parts[0] != "xbox" {
		t.Fatalf("ticket envelope %+v", rep.Ticket)
	}
	if !bytes.Equal(svc.Key.Value, part.Key.Value) || bytes.Equal(svc.Key.Value, tk.session[:]) {
		t.Fatal("service session key must be fresh and shared with the client")
	}
	if svc.CName.Parts[0] != tag+"@xbox.com" || svc.CRealm != "passport.net" ||
		!svc.EndTime.Equal(tk.end) && !svc.EndTime.Equal(e.clock.Now().Add(24*time.Hour)) {
		t.Fatalf("ticket content %+v", svc)
	}
	var users, addrs []byte
	for _, ad := range svc.AuthData {
		switch ad.Type {
		case krb.ADUsers:
			users = ad.Data
		case krb.ADServiceAddresses:
			addrs = ad.Data
		}
	}
	if !bytes.Equal(users, le(xuid)) || !bytes.Equal(addrs, ab) {
		t.Fatal("authorization data must carry the KDC-asserted xuid and service address")
	}
	if _, err := krb.OpenTicket(e.cfg.TGSKeys, krb.UsageSGTicket, rep.Ticket); err == nil {
		t.Fatal("ticket must not open with the TGS ring")
	}

	// Without a service request the reply has no address PA.
	e.clock.Advance(time.Second)
	reply = e.handle(e.tgsReq(tk, tgsOpts{skipSR: true}))
	if rep2, err := krb.ParseKDCRep(reply, krb.MsgTGSRep); err != nil || len(rep2.PAData) != 0 {
		t.Fatalf("plain TGS: %v", err)
	}
}

func TestSessionKeysAndConfoundersAreFresh(t *testing.T) {
	e := newEnv(t)
	a := e.login()
	e.clock.Advance(time.Second) // new timestamp => not a replay
	b := e.login()
	if a.session == b.session || bytes.Equal(a.ticket.Enc.Cipher, b.ticket.Enc.Cipher) {
		t.Fatal("two logins produced identical keys or tickets")
	}
}

func TestKeyRotation(t *testing.T) {
	e := newEnv(t)
	tk := e.login() // TGT under TGS key id 1
	// Rotate: id 2 becomes active, id 1 stays for existing TGTs.
	e.cfg.TGSKeys = ring(t, 16, 2, 1, 2)
	e.cfg.SGKeys = ring(t, 16, 6, 4, 5, 6)
	k2, err := kdc.New(e.cfg, e.res, e.res)
	if err != nil {
		t.Fatal(err)
	}
	e.kdc = k2
	reply := e.handle(e.tgsReq(tk, tgsOpts{}))
	rep, err := krb.ParseKDCRep(reply, krb.MsgTGSRep)
	if err != nil || *rep.Ticket.Enc.KVNO != 6 {
		t.Fatalf("old TGT must still work and new tickets use the new SG key id: %v", err)
	}
	// Retire id 1: the old TGT is refused.
	e.cfg.TGSKeys = ring(t, 16, 2, 2)
	k3, _ := kdc.New(e.cfg, e.res, e.res)
	e.kdc = k3
	e.clock.Advance(time.Second)
	e.mustErr(e.handle(e.tgsReq(tk, tgsOpts{})), krb.ErrAPModified)
}

func TestASNegative(t *testing.T) {
	e := newEnv(t)
	good := e.userKey()
	now := e.clock.Now()

	t.Run("wrong key", func(t *testing.T) {
		wrong := krb.DeriveUserKey(bytes.Repeat([]byte{9}, 32), xuid)
		e.mustErr(e.handle(e.asReq(wrong, now, 1)), krb.ErrPreauthFailed)
	})
	t.Run("another user's key", func(t *testing.T) {
		e.mustErr(e.handle(e.asReq(krb.DeriveUserKey(bytes.Repeat([]byte{1}, 32), otherXUID), now, 1)), krb.ErrPreauthFailed)
	})
	t.Run("stale and future timestamps", func(t *testing.T) {
		e.mustErr(e.handle(e.asReq(good, now.Add(-6*time.Minute), 1)), krb.ErrAPSkew)
		e.mustErr(e.handle(e.asReq(good, now.Add(6*time.Minute), 1)), krb.ErrAPSkew)
	})
	t.Run("no preauth", func(t *testing.T) {
		e.mustErr(e.handle(e.asReq(good, now, 1, func(r *krb.KDCReq) { r.PAData = r.PAData[:1] })), krb.ErrPreauthRequired)
		e.mustErr(e.handle(e.asReq(good, now, 1, func(r *krb.KDCReq) { r.PAData = r.PAData[1:] })), krb.ErrPreauthRequired)
		e.mustErr(e.handle(e.asReq(good, now, 1, func(r *krb.KDCReq) { r.PAData = append(r.PAData, r.PAData[1]) })), krb.ErrPreauthRequired)
	})
	t.Run("bad names and etypes", func(t *testing.T) {
		e.mustErr(e.handle(e.asReq(good, now, 1, func(r *krb.KDCReq) { r.CName = nil })), krb.ErrCPrincipalUnknown)
		for _, n := range []string{"PlayerOne", "PlayerOne@evil.com", "@xbox.com", "A Very Long Gamertag Indeed@xbox.com", "Pl!ayer@xbox.com", "Play/er@xbox.com"} {
			e.mustErr(e.handle(e.asReq(good, now, 1, func(r *krb.KDCReq) { r.CName = &krb.PrincipalName{Type: 10, Parts: []string{n}} })), krb.ErrCPrincipalUnknown)
		}
		e.mustErr(e.handle(e.asReq(good, now, 1, func(r *krb.KDCReq) {
			r.CName = &krb.PrincipalName{Type: 1, Parts: []string{tag + "@xbox.com"}}
		})), krb.ErrCPrincipalUnknown)
		e.mustErr(e.handle(e.asReq(good, now, 1, func(r *krb.KDCReq) { r.ETypes = []int32{17, 18} })), krb.ErrETypeNoSupp)
	})
	t.Run("unknown, banned, unlinked, unavailable", func(t *testing.T) {
		e.res.SetUser(tag, xuidHex, xbaccountapi.StatusBanned)
		e.mustErr(e.handle(e.asReq(good, now, 2)), krb.ErrClientRevoked)
		e.res.SetUser(tag, xuidHex, xbaccountapi.StatusUnlinked)
		e.mustErr(e.handle(e.asReq(good, now, 3)), krb.ErrCPrincipalUnknown)
		e.res.Remove(tag)
		e.mustErr(e.handle(e.asReq(good, now, 4)), krb.ErrCPrincipalUnknown)
		e.res.SetUser(tag, xuidHex, xbaccountapi.StatusActive)
		e.res.Unavailable = true
		e.mustErr(e.handle(e.asReq(good, now, 5)), krb.ErrSvcUnavailable)
		e.res.Unavailable = false
		e.mustErr(e.handle(e.asReq(good, now, 6, func(r *krb.KDCReq) {
			r.CName = &krb.PrincipalName{Type: 10, Parts: []string{"Nobody@xbox.com"}}
		})), krb.ErrCPrincipalUnknown)
	})
	t.Run("replay", func(t *testing.T) {
		req := e.asReq(good, now, 7)
		if r := e.handle(req); r == nil || krb.IsError(r) {
			t.Fatal("first request must succeed")
		}
		e.mustErr(e.handle(req), krb.ErrAPRepeat)
	})
	t.Run("failed attempts do not poison the cache", func(t *testing.T) {
		// A wrong-key attempt must not consume the legitimate timestamp slot.
		e.clock.Advance(time.Second)
		ts := e.clock.Now()
		wrong := krb.DeriveUserKey(bytes.Repeat([]byte{9}, 32), xuid)
		e.handle(e.asReq(wrong, ts, 8))
		if r := e.handle(e.asReq(good, ts, 8)); krb.IsError(r) {
			t.Fatal("legitimate request rejected after garbage")
		}
	})
}

func TestTGSNegative(t *testing.T) {
	e := newEnv(t)
	tk := e.login()

	t.Run("expired TGT", func(t *testing.T) {
		e2 := newEnv(t)
		tk := e2.login()
		e2.clock.Advance(24*time.Hour + time.Second)
		e2.mustErr(e2.handle(e2.tgsReq(tk, tgsOpts{})), krb.ErrAPTktExpired)
	})
	t.Run("authenticator skew", func(t *testing.T) {
		old := e.clock.Now().Add(-10 * time.Minute)
		e.mustErr(e.handle(e.tgsReq(tk, tgsOpts{ctime: &old})), krb.ErrAPSkew)
	})
	t.Run("replayed", func(t *testing.T) {
		req := e.tgsReq(tk, tgsOpts{ids: []uint32{6}})
		if r := e.handle(req); krb.IsError(r) {
			t.Fatal("first TGS must succeed")
		}
		e.mustErr(e.handle(req), krb.ErrAPRepeat)
	})
	t.Run("wrong session key", func(t *testing.T) {
		wrong := krb.DeriveUserKey(bytes.Repeat([]byte{3}, 32), 1)
		e.mustErr(e.handle(e.tgsReq(tk, tgsOpts{authKey: &wrong})), krb.ErrAPBadIntegrity)
	})
	t.Run("forged or foreign TGT", func(t *testing.T) {
		forged := tk
		forged.ticket.Enc.Cipher = bytes.Clone(tk.ticket.Enc.Cipher)
		forged.ticket.Enc.Cipher[20] ^= 1
		e.mustErr(e.handle(e.tgsReq(forged, tgsOpts{})), krb.ErrAPModified)
		// A TGT sealed with a key the KDC does not hold.
		other := newEnv(t, func(c *kdc.Config) { c.TGSKeys = ring(t, 16, 1, 1); c.TGSKeys = ring(t, 16, 9, 9) })
		foreign := other.login()
		e.mustErr(e.handle(e.tgsReq(foreign, tgsOpts{})), krb.ErrAPModified)
		// A service ticket is not a TGT.
		reply := e.handle(e.tgsReq(tk, tgsOpts{skipSR: true}))
		rep, _ := krb.ParseKDCRep(reply, krb.MsgTGSRep)
		as := tgt{ticket: rep.Ticket, session: tk.session}
		e.mustErr(e.handle(e.tgsReq(as, tgsOpts{})), krb.ErrSPrincipalUnknown)
	})
	t.Run("cname mismatch", func(t *testing.T) {
		n := krb.PrincipalName{Type: 10, Parts: []string{"Mallory@xbox.com"}}
		e.mustErr(e.handle(e.tgsReq(tk, tgsOpts{cname: &n})), krb.ErrAPModified)
	})
	t.Run("service names", func(t *testing.T) {
		for _, n := range []krb.PrincipalName{{Type: 2, Parts: []string{"krbtgt", "XBOX.COM"}}, {Type: 2, Parts: []string{""}}, {Type: 2, Parts: []string{"a", "b", "c", "d"}}} {
			n := n
			e.mustErr(e.handle(e.tgsReq(tk, tgsOpts{sname: &n})), krb.ErrSPrincipalUnknown)
		}
	})
	t.Run("bad service request", func(t *testing.T) {
		// Valid MAC, invalid structure: too many services.
		sr := &krb.ServiceRequest{StructVersion: 1, StructSize: krb.ServiceRequestSize, NumServices: 13}
		enc, _ := krb.Seal(xbcrypto.NonceKey(tk.session, 77), krb.UsageServiceRequest, nil, sr.Marshal())
		auth, _ := krb.Seal(tk.session, krb.UsageTGSReqAuth, nil,
			(&krb.Authenticator{CRealm: "passport.net", CName: *cname(), CUsec: 5, CTime: e.clock.Now()}).Marshal())
		sn := krb.PrincipalName{Type: 2, Parts: []string{"xbox", "gw"}}
		req := krb.MarshalKDCReq(&krb.KDCReq{MsgType: krb.MsgTGSReq, Realm: "XBOX.COM", SName: &sn, Nonce: 77, ETypes: []int32{23},
			PAData: []krb.PAData{{Type: 1, Value: (&krb.APReq{Ticket: tk.ticket, Authenticator: auth}).Marshal()}, {Type: 201, Value: enc.Marshal()}}})
		e.mustErr(e.handle(req), krb.ErrPolicy)
		// Service request sealed under the wrong nonce.
		e.clock.Advance(time.Second)
		bad := e.tgsReq(tk, tgsOpts{nonce: 5, ids: []uint32{6}})
		r, _ := krb.ParseKDCReq(bad)
		r.Nonce = 6 // header nonce no longer matches the nonce key
		e.mustErr(e.handle(krb.MarshalKDCReq(r)), krb.ErrPolicy)
	})
	t.Run("banned, unlinked, removed, unavailable after login", func(t *testing.T) {
		for _, tc := range []struct {
			set  func()
			unav bool
			code int32
		}{
			{func() { e.res.SetUser(tag, xuidHex, xbaccountapi.StatusBanned) }, false, krb.ErrClientRevoked},
			{func() { e.res.SetUser(tag, xuidHex, xbaccountapi.StatusUnlinked) }, false, krb.ErrCPrincipalUnknown},
			{func() { e.res.Remove(tag) }, false, krb.ErrCPrincipalUnknown},
			{func() { e.res.SetUser(tag, xuidHex, xbaccountapi.StatusActive) }, true, krb.ErrSvcUnavailable},
		} {
			e.clock.Advance(time.Second)
			tc.set()
			e.res.Unavailable = tc.unav
			e.mustErr(e.handle(e.tgsReq(tk, tgsOpts{ids: []uint32{6}})), tc.code)
		}
		e.res.Unavailable = false
		e.res.SetUser(tag, xuidHex, xbaccountapi.StatusActive)
		e.clock.Advance(time.Second)
		if r := e.handle(e.tgsReq(tk, tgsOpts{})); krb.IsError(r) {
			t.Fatal("restored principal must work again")
		}
	})
}

func TestMalformedInputIsDropped(t *testing.T) {
	e := newEnv(t)
	good := e.asReq(e.userKey(), e.clock.Now(), 1)
	for i := 0; i < len(good); i++ {
		if r := e.handle(good[:i]); r != nil {
			t.Fatalf("answered a truncated datagram (%d bytes)", i)
		}
	}
	for _, b := range [][]byte{nil, {}, {0x6a}, {0x6a, 0x00}, {0x6c, 0x82, 0xff, 0xff}, bytes.Repeat([]byte{0x6a}, 100), bytes.Repeat([]byte{0xff}, 64)} {
		if e.handle(b) != nil {
			t.Fatalf("answered garbage %x", b)
		}
	}
	for i := range good { // corruption must never panic
		b := bytes.Clone(good)
		b[i] ^= 0x5a
		e.handle(b)
	}
	// A control character in a name is a malformed string, not an unknown user.
	ctl := e.asReq(e.userKey(), e.clock.Now(), 1, func(r *krb.KDCReq) {
		r.CName = &krb.PrincipalName{Type: 10, Parts: []string{"Play\x01er@xbox.com"}}
	})
	if e.handle(ctl) != nil {
		t.Fatal("answered a name with a control character")
	}
	// TGS with an AP-REQ that does not parse is dropped; a missing one is an error.
	sn := krb.PrincipalName{Type: 2, Parts: []string{"x"}}
	noap := krb.MarshalKDCReq(&krb.KDCReq{MsgType: krb.MsgTGSReq, Realm: "XBOX.COM", SName: &sn, ETypes: []int32{23}})
	e.mustErr(e.handle(noap), krb.ErrPreauthRequired)
	junk := krb.MarshalKDCReq(&krb.KDCReq{MsgType: krb.MsgTGSReq, Realm: "XBOX.COM", SName: &sn, ETypes: []int32{23},
		PAData: []krb.PAData{{Type: 1, Value: []byte{1, 2, 3}}}})
	if e.handle(junk) != nil {
		t.Fatal("answered an unparseable AP-REQ")
	}
}

func wrapSeq(b []byte) []byte {
	n := len(b)
	switch {
	case n < 0x80:
		return append([]byte{0x30, byte(n)}, b...)
	case n < 0x100:
		return append([]byte{0x30, 0x81, byte(n)}, b...)
	}
	return append([]byte{0x30, 0x82, byte(n >> 8), byte(n)}, b...)
}

func TestConfigRejectsUnsafe(t *testing.T) {
	cases := map[string]func(*kdc.Config){
		"private gateway":  func(c *kdc.Config) { c.GatewayIP = netip.MustParseAddr("10.147.17.3") },
		"zerotier-ish":     func(c *kdc.Config) { c.GatewayIP = netip.MustParseAddr("172.28.1.1") },
		"loopback":         func(c *kdc.Config) { c.GatewayIP = netip.MustParseAddr("127.0.0.1") },
		"cgnat":            func(c *kdc.Config) { c.GatewayIP = netip.MustParseAddr("100.64.1.1") },
		"unset gateway":    func(c *kdc.Config) { c.GatewayIP = netip.Addr{} },
		"ipv6 gateway":     func(c *kdc.Config) { c.GatewayIP = netip.MustParseAddr("2001:db8::1") },
		"missing keys":     func(c *kdc.Config) { c.SGKeys = nil },
		"shared key rings": func(c *kdc.Config) { c.SGKeys = c.TGSKeys },
		"zero skew":        func(c *kdc.Config) { c.ClockSkew = 0 },
	}
	for name, m := range cases {
		cfg := newEnv(t).cfg
		m(&cfg)
		if _, err := kdc.New(cfg, memresolver.New(), memresolver.New()); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := kdc.New(newEnv(t).cfg, nil, nil); err == nil {
		t.Error("nil resolver accepted")
	}
	if kdc.DefaultConfig().GatewayIP.String() != gatewayIP {
		t.Error("default gateway must be the secondary public address")
	}
}

func TestReplayCacheBoundedAndFailsClosed(t *testing.T) {
	now := time.Now()
	c := kdc.NewReplayCache(time.Minute, 3)
	for i := 0; i < 3; i++ {
		if err := c.CheckAndAdd([32]byte{byte(i)}, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.CheckAndAdd([32]byte{9}, now); err != kdc.ErrFull {
		t.Fatalf("full cache must refuse, got %v", err)
	}
	if err := c.CheckAndAdd([32]byte{1}, now); err != kdc.ErrReplay {
		t.Fatal("replay must still be detected when full")
	}
	// Entries survive at least one ttl, then age out.
	if err := c.CheckAndAdd([32]byte{1}, now.Add(59*time.Second)); err != kdc.ErrReplay {
		t.Fatal("forgot an entry inside its ttl")
	}
	if err := c.CheckAndAdd([32]byte{1}, now.Add(3*time.Minute)); err != nil {
		t.Fatalf("entry never expires: %v", err)
	}
}

func TestUDPServerEndToEnd(t *testing.T) {
	e := newEnv(t)
	// The in-process clock must follow wall time for a real socket test.
	e.cfg.Now = time.Now
	k, err := kdc.New(e.cfg, e.res, e.res)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback UDP:", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (&kdc.Server{KDC: k, Conn: conn}).Serve(ctx) }()
	defer func() { cancel(); <-done }()

	client, _ := net.Dial("udp", conn.LocalAddr().String())
	defer client.Close()
	roundTrip := func(b []byte) []byte {
		client.SetDeadline(time.Now().Add(3 * time.Second))
		client.Write(b)
		buf := make([]byte, 8192)
		n, err := client.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		return buf[:n]
	}
	e.clock.t = time.Now()
	req := e.asReq(e.userKey(), time.Now().UTC().Truncate(time.Second), 1)
	first := roundTrip(req)
	if krb.IsError(first) {
		t.Fatalf("AS over UDP failed")
	}
	// Retransmission from the same peer gets the identical reply, not a replay error.
	if second := roundTrip(req); !bytes.Equal(first, second) {
		t.Fatal("retransmission must receive the cached reply")
	}
	// The same bytes from a different source port are a replay.
	other, _ := net.Dial("udp", conn.LocalAddr().String())
	defer other.Close()
	other.SetDeadline(time.Now().Add(3 * time.Second))
	other.Write(req)
	buf := make([]byte, 8192)
	n, err := other.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if pe, err := krb.ParseError(buf[:n]); err != nil || pe.Code != krb.ErrAPRepeat {
		t.Fatalf("replay from another peer must be refused, got %v %v", pe, err)
	}
	// Garbage gets no answer.
	client.SetDeadline(time.Now().Add(200 * time.Millisecond))
	client.Write([]byte{0x6a, 0x01})
	if _, err := client.Read(buf); err == nil {
		t.Fatal("answered garbage")
	}
}

func TestUserAccountBlobMatchesSignInKey(t *testing.T) {
	e := newEnv(t)
	blob, err := e.kdc.UserAccountBlob(context.Background(), xuidHex)
	if err != nil || len(blob) != 84 {
		t.Fatalf("%v %d", err, len(blob))
	}
	if binary.LittleEndian.Uint64(blob) != xuid || string(bytes.TrimRight(blob[8:24], "\x00")) != tag {
		t.Fatalf("blob %x", blob)
	}
	k := e.userKey()
	if !bytes.Equal(blob[68:], k[:]) {
		t.Fatal("blob key is not the AS pre-authentication key")
	}
	e.res.SetUser(tag, xuidHex, xbaccountapi.StatusBanned)
	if _, err := e.kdc.UserAccountBlob(context.Background(), xuidHex); err == nil {
		t.Fatal("blob issued for a banned user")
	}
}
