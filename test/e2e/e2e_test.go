// SPDX-License-Identifier: AGPL-3.0-only

// Package e2e runs the whole native sign-in slice in one process, over real
// sockets and mutual TLS: web-approved provisioning in xb-account (fake core)
// -> MACS -> machine AS -> compound user AS -> TGS (xb-auth) -> SG-init
// admission in xb-gateway. The "console" side below is a test client written
// against the same wire structures; no retail console or emulator has run this.
package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"openpak/xb-live/internal/krb"
	"openpak/xb-live/internal/sgwire"
	"openpak/xb-live/internal/xbaccountapi"
	"openpak/xb-live/internal/xbcrypto"
	account "openpak/xb-live/services/xb-account/testkit"
	auth "openpak/xb-live/services/xb-auth/testkit"
	gw "openpak/xb-live/services/xb-gateway/testkit"
)

const (
	serial     = "123456789012"
	machineID  = "0000001cbe991a14"
	coreAcct   = "core-account-1"
	gamertag   = "Player One"
	gatewayAdv = "203.0.113.5"
)

// ---- mutual TLS plumbing ----

type pki struct {
	ca   *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "e2e ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &pki{ca, k, pool}
}

func (p *pki) leaf(t *testing.T, spiffe string, server bool) tls.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse(spiffe)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: spiffe},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, URIs: []*url.URL{u}}
	if server {
		tpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.ca, &k.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func (p *pki) client(t *testing.T, spiffe string) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: p.pool, Certificates: []tls.Certificate{p.leaf(t, spiffe, false)}}}}
}

// ---- the world ----

type world struct {
	t        *testing.T
	p        *pki
	acct     *account.Account
	base     string
	prov     *http.Client
	authC    *xbaccountapi.Client
	kdc      *auth.KDC
	sgKeys   *krb.Keyring
	userKeys *krb.Keyring
	gwSrv    *gw.Server
	gwAddr   netip.AddrPort
}

func ring(t *testing.T, size int, seed byte) *krb.Keyring {
	t.Helper()
	k := make([]byte, size)
	for i := range k {
		k[i] = seed + byte(i)*3
	}
	hexs := make([]byte, size*2)
	const d = "0123456789abcdef"
	for i, b := range k {
		hexs[2*i], hexs[2*i+1] = d[b>>4], d[b&15]
	}
	r, err := krb.ParseKeyring([]byte(`{"active":1,"keys":{"1":"`+string(hexs)+`"}}`), size)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func newWorld(t *testing.T) *world {
	t.Helper()
	p := newPKI(t)
	a, err := account.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	a.AddActiveAccount(coreAcct)
	srv := httptest.NewUnstartedServer(a.Handler)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{p.leaf(t, "spiffe://openpak/xb-account", true)},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: p.pool}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	w := &world{t: t, p: p, acct: a, base: srv.URL, prov: p.client(t, account.Provisioner),
		authC:    &xbaccountapi.Client{Base: srv.URL, HTTP: p.client(t, account.Auth)},
		sgKeys:   ring(t, 16, 0x31),
		userKeys: ring(t, 32, 0x57)}
	cfg := auth.DefaultConfig()
	cfg.GatewayIP = netip.MustParseAddr(gatewayAdv)
	cfg.TGSKeys, cfg.SGKeys, cfg.UserKeys = ring(t, 16, 0x11), w.sgKeys, w.userKeys
	if w.kdc, err = auth.New(cfg, w.authC); err != nil {
		t.Fatal(err)
	}
	gwClient := &xbaccountapi.Client{Base: srv.URL, HTTP: p.client(t, account.Gateway)}
	if w.gwSrv, err = gw.New(netip.MustParseAddr(gatewayAdv), w.sgKeys, gwClient); err != nil {
		t.Fatal(err)
	}
	w.gwAddr = w.gwSrv.Addr()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.gwSrv.Serve(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return w
}

// console holds what the console knows after provisioning.
type console struct {
	machineKey xbcrypto.Key
	xuid       string
}

func consoleKey() xbcrypto.Key {
	return xbcrypto.MachineKey(xbcrypto.Key{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, xbcrypto.Key{0xa0, 0xa1, 0xa2, 0xa3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
}

func (w *world) post(c *http.Client, path string, body any) (int, []byte) {
	w.t.Helper()
	b, _ := json.Marshal(body)
	resp, err := c.Post(w.base+path, "application/json", bytes.NewReader(b))
	if err != nil {
		w.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

// provision performs web approval (Begin by the web side) and the console's
// finalize with its machine key as proof material.
func (w *world) provision(key xbcrypto.Key) console {
	w.t.Helper()
	const challenge = "console-generated-challenge-0123456789"
	code, body := w.post(w.prov, "/internal/v1/provisions", map[string]string{"core_account_id": coreAcct, "machine_id": machineID, "challenge": challenge})
	if code != 200 {
		w.t.Fatalf("begin %d %s", code, body)
	}
	var b struct{ Token string }
	json.Unmarshal(body, &b)
	code, body = w.post(w.prov, "/internal/v1/provisions/finalize", map[string]string{"token": b.Token, "machine_id": machineID,
		"challenge": challenge, "gamertag": gamertag, "proof": base64.StdEncoding.EncodeToString(key[:])})
	if code != 200 {
		w.t.Fatalf("finalize %d %s", code, body)
	}
	var f struct{ XUID string }
	json.Unmarshal(body, &f)
	return console{machineKey: key, xuid: f.XUID}
}

// ---- console-side Kerberos ----

func (w *world) kdcCall(req []byte) []byte { return w.kdc.Handle(context.Background(), req) }

func errCode(t *testing.T, reply []byte) int32 {
	t.Helper()
	if !krb.IsError(reply) {
		t.Fatalf("expected KRB-ERROR, got %x", reply)
	}
	e, err := krb.ParseError(reply)
	if err != nil {
		t.Fatal(err)
	}
	return e.Code
}

func macsReq(key xbcrypto.Key, nonce uint32) []byte {
	enc, _ := krb.Seal(key, krb.UsageASReqTimestamp, nil, krb.PAEncTSEnc{Time: time.Now(), Usec: 7}.Marshal())
	sn := krb.PrincipalName{Type: krb.NameTypeSrvInst, Parts: []string{"krbtgt", krb.MACSRealm}}
	return krb.MarshalKDCReq(&krb.KDCReq{MsgType: krb.MsgASReq, Realm: krb.MACSRealm, SName: &sn, Nonce: nonce,
		CName:  &krb.PrincipalName{Type: krb.NameTypeEnterprise, Parts: []string{serial}},
		ETypes: []int32{krb.ETypeRC4HMAC}, Options: krb.KDCOptCanonicalize,
		PAData: []krb.PAData{
			{Type: krb.PAEncTimestamp, Value: enc.Marshal()}, {Type: krb.PAForCheckDups, Value: []byte{1, 2, 3}},
			{Type: krb.PAXboxPPA, Value: []byte{4, 5}},
			{Type: krb.PAXboxClientVersion, Value: krb.SignClientVersion(key, []byte("Version=1.00.5849.3 Title=0xFFFE0000\x00"))}}})
}

// macs returns the machine account blob, or the KRB-ERROR code.
func (w *world) macs(key xbcrypto.Key) (blob []byte, code int32) {
	w.t.Helper()
	const nonce = 0x1234
	reply := w.kdcCall(macsReq(key, nonce))
	if krb.IsError(reply) {
		return nil, errCode(w.t, reply)
	}
	rep, err := krb.ParseKDCRep(reply, krb.MsgASRep)
	if err != nil {
		w.t.Fatal(err)
	}
	pa, _ := krb.FindPA(rep.PAData, krb.PAXboxAccountCreate)
	ed, _ := krb.ParseEncryptedData(pa)
	blob, err = krb.Open(xbcrypto.NonceKey(key, nonce), krb.UsageMachineAccount, ed)
	if err != nil {
		w.t.Fatal("account blob does not open with the machine key")
	}
	return blob, 0
}

func asReq(name string, key xbcrypto.Key, nonce uint32, compound []byte) []byte {
	enc, _ := krb.Seal(key, krb.UsageASReqTimestamp, nil, krb.PAEncTSEnc{Time: time.Now(), Usec: 4242}.Marshal())
	sn := krb.PrincipalName{Type: krb.NameTypeSrvInst, Parts: []string{"krbtgt", "XBOX.COM"}}
	pas := []krb.PAData{{Type: krb.PAXboxClientVersion, Value: []byte{1, 2, 3}}, {Type: krb.PAEncTimestamp, Value: enc.Marshal()}}
	if compound != nil {
		pas = append(pas, krb.PAData{Type: krb.PACompoundIdentity, Value: compound})
	}
	return krb.MarshalKDCReq(&krb.KDCReq{MsgType: krb.MsgASReq, Realm: "passport.net", SName: &sn, Nonce: nonce,
		CName:  &krb.PrincipalName{Type: krb.NameTypeEnterprise, Parts: []string{name + "@xbox.com"}},
		ETypes: []int32{krb.ETypeRC4HMAC}, PAData: pas})
}

type tgt struct {
	ticket  krb.Ticket
	session xbcrypto.Key
}

func (w *world) as(name string, key xbcrypto.Key, nonce uint32, compound []byte) (tgt, int32) {
	w.t.Helper()
	reply := w.kdcCall(asReq(name, key, nonce, compound))
	if krb.IsError(reply) {
		return tgt{}, errCode(w.t, reply)
	}
	rep, err := krb.ParseKDCRep(reply, krb.MsgASRep)
	if err != nil {
		w.t.Fatal(err)
	}
	plain, err := krb.Open(key, krb.UsageKDCRepPart, rep.Enc)
	if err != nil {
		w.t.Fatal("AS-REP does not open with the client key")
	}
	part, err := krb.ParseEncKDCRepPart(plain, krb.MsgASRep)
	if err != nil || part.Nonce != nonce {
		w.t.Fatalf("AS-REP part: %v", err)
	}
	s, _ := krb.ToKey(part.Key.Value)
	return tgt{rep.Ticket, s}, 0
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

// signIn runs machine AS then the compound user AS and returns the user TGT.
func (w *world) signIn(c console, machineAccountKey, userKey xbcrypto.Key, nonce uint32) (tgt, int32) {
	w.t.Helper()
	m, code := w.as("SN."+serial, machineAccountKey, nonce, nil)
	if code != 0 {
		return tgt{}, code
	}
	compound := xbcrypto.CompoundKey(userKey, m.session)
	return w.as(gamertag, compound, nonce+1, wrapSeq(m.ticket.Marshal()))
}

func (w *world) tgs(t tgt, name string, xuid uint64) (krb.Ticket, xbcrypto.Key, int32) {
	w.t.Helper()
	const nonce = 0x55667788
	cn := krb.PrincipalName{Type: krb.NameTypeEnterprise, Parts: []string{name + "@xbox.com"}}
	authc, _ := krb.Seal(t.session, krb.UsageTGSReqAuth, nil, (&krb.Authenticator{CRealm: "passport.net", CName: cn, CUsec: 99, CTime: time.Now()}).Marshal())
	ap := (&krb.APReq{Ticket: t.ticket, Authenticator: authc}).Marshal()
	sr := &krb.ServiceRequest{StructVersion: 1, StructSize: krb.ServiceRequestSize, LibraryVersion: [4]uint16{1, 0, 0x172d, 1},
		TitleID: 0xffff0112, XUIDs: [4]uint64{xuid}, NumServices: 1}
	sr.ServiceIDs[0] = 6
	enc, _ := krb.Seal(xbcrypto.NonceKey(t.session, nonce), krb.UsageServiceRequest, nil, sr.Marshal())
	sn := krb.PrincipalName{Type: krb.NameTypeSrvInst, Parts: []string{"xbox", "gw"}}
	reply := w.kdcCall(krb.MarshalKDCReq(&krb.KDCReq{MsgType: krb.MsgTGSReq, Realm: "XBOX.COM", SName: &sn, Nonce: nonce,
		ETypes: []int32{krb.ETypeRC4HMAC}, PAData: []krb.PAData{{Type: krb.PAAPReq, Value: ap}, {Type: krb.PAXboxServiceRequest, Value: enc.Marshal()}}}))
	if krb.IsError(reply) {
		return krb.Ticket{}, xbcrypto.Key{}, errCode(w.t, reply)
	}
	rep, err := krb.ParseKDCRep(reply, krb.MsgTGSRep)
	if err != nil {
		w.t.Fatal(err)
	}
	plain, err := krb.Open(t.session, krb.UsageKDCRepPart, rep.Enc)
	if err != nil {
		w.t.Fatal(err)
	}
	part, _ := krb.ParseEncKDCRepPart(plain, krb.MsgTGSRep)
	s, _ := krb.ToKey(part.Key.Value)
	return rep.Ticket, s, 0
}

// ---- SG init ----

// sgInit sends a native init datagram carrying the ticket and returns the
// gateway reply (nil when dropped) and whether a session now exists.
func (w *world) sgInit(tk krb.Ticket, session xbcrypto.Key, name string) (reply []byte, admitted bool) {
	w.t.Helper()
	_, pub, err := sgwire.GenerateDH(nil)
	if err != nil {
		w.t.Fatal(err)
	}
	var nonce [8]byte
	rand.Read(nonce[:])
	body := binary.LittleEndian.AppendUint16(nil, 0)
	body = binary.LittleEndian.AppendUint16(body, 2)
	body = binary.LittleEndian.AppendUint32(body, 0x59a300)
	body = append(body, nonce[:]...)
	body = binary.LittleEndian.AppendUint32(body, 0)
	head, err := sgwire.MarshalChunks([]sgwire.Chunk{{Tag: sgwire.TagInit, Data: body}, {Tag: sgwire.TagDH, Data: pub[:]}})
	if err != nil {
		w.t.Fatal(err)
	}
	mac := hmac.New(sha1.New, session[:])
	mac.Write(head)
	seqNo := uint32(77)
	cn := krb.PrincipalName{Type: krb.NameTypeEnterprise, Parts: []string{name + "@xbox.com"}}
	a := &krb.SGAuthenticator{Authenticator: krb.Authenticator{CRealm: "passport.net", CName: cn, CUsec: 123456, CTime: time.Now()},
		CksumType: krb.ChecksumTypeSGParam, Cksum: mac.Sum(nil), SeqNumber: &seqNo}
	encAuth, err := krb.Seal(session, krb.UsageAPReqAuth, nil, a.Marshal())
	if err != nil {
		w.t.Fatal(err)
	}
	tail, err := sgwire.MarshalChunks([]sgwire.Chunk{{Tag: sgwire.TagAPReq, Data: (&krb.APReq{Ticket: tk, Authenticator: encAuth}).Marshal()},
		{Tag: sgwire.TagPadding, Data: make([]byte, 8)}})
	if err != nil {
		w.t.Fatal(err)
	}
	dg := append(append([]byte{0, 0, 0, 0}, head...), tail...)
	before := w.gwSrv.SessionCount()
	conn, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(w.gwAddr))
	if err != nil {
		w.t.Fatal(err)
	}
	defer conn.Close()
	conn.Write(dg)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, w.gwSrv.SessionCount() > before
	}
	return buf[:n], w.gwSrv.SessionCount() > before
}

// fullSignIn drives provisioning through to a service ticket.
type signed struct {
	c        console
	userKey  xbcrypto.Key
	userTGT  tgt
	svc      krb.Ticket
	svcKey   xbcrypto.Key
	accountK xbcrypto.Key
}

func (w *world) fullSignIn(c console) signed {
	w.t.Helper()
	blob, code := w.macs(c.machineKey)
	if code != 0 {
		w.t.Fatalf("MACS error %d", code)
	}
	var mk, uk xbcrypto.Key
	copy(mk[:], blob[68:])
	ublob, err := w.kdc.UserAccountBlob(context.Background(), c.xuid)
	if err != nil {
		w.t.Fatal(err)
	}
	if got := strings.TrimRight(string(ublob[8:24]), "\x00"); got != gamertag {
		w.t.Fatalf("user blob gamertag %q", got)
	}
	copy(uk[:], ublob[68:])
	ut, code := w.signIn(c, mk, uk, 10)
	if code != 0 {
		w.t.Fatalf("sign-in error %d", code)
	}
	var xuid uint64
	for i, b := range ublob[:8] {
		xuid |= uint64(b) << (8 * i)
	}
	svc, svcKey, code := w.tgs(ut, gamertag, xuid)
	if code != 0 {
		w.t.Fatalf("TGS error %d", code)
	}
	return signed{c, uk, ut, svc, svcKey, mk}
}

// ---- tests ----

func TestProvisionToGatewayAdmission(t *testing.T) {
	w := newWorld(t)
	c := w.provision(consoleKey())
	s := w.fullSignIn(c)

	// The user key the console stored is the one AS verified, and the machine
	// account blob names the console's serial.
	if len(s.userKey) != 16 || s.userKey == (xbcrypto.Key{}) {
		t.Fatal("empty user key")
	}
	reply, admitted := w.sgInit(s.svc, s.svcKey, gamertag)
	if reply == nil || !admitted || w.gwSrv.SessionCount() != 1 {
		t.Fatal("gateway did not admit the xb-auth ticket for a provisioned user")
	}
	// AP-REP is sealed with the ticket session key (mutual authentication).
	chunks, err := sgwire.ParseChunks(reply[4:])
	if err != nil || len(chunks) != 3 {
		t.Fatalf("reply chunks: %v", err)
	}
	enc, err := krb.ParseAPRep(chunks[2].Data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := krb.Open(s.svcKey, krb.UsageAPRepEncPart, enc); err != nil {
		t.Fatal("AP-REP does not open with the service session key")
	}
}

func TestRevokedAfterProvisioning(t *testing.T) {
	t.Run("unlink event stops MACS, sign-in, TGS and gateway", func(t *testing.T) {
		w := newWorld(t)
		c := w.provision(consoleKey())
		s := w.fullSignIn(c)
		if err := w.acct.EmitAndProcess(context.Background(), "link_unlinked", coreAcct, "xbox", c.xuid); err != nil {
			t.Fatal(err)
		}
		if _, code := w.macs(c.machineKey); code != krb.ErrCPrincipalUnknown && code != krb.ErrClientRevoked {
			t.Fatalf("MACS after unlink: %d", code)
		}
		if _, code := w.signIn(c, s.accountK, s.userKey, 20); code == 0 {
			t.Fatal("sign-in after unlink")
		}
		if _, _, code := w.tgs(s.userTGT, gamertag, 0); code == 0 {
			t.Fatal("TGS issued after unlink with an earlier TGT")
		}
		if _, admitted := w.sgInit(s.svc, s.svcKey, gamertag); admitted {
			t.Fatal("gateway admitted an earlier ticket after unlink")
		}
	})
	t.Run("credential revoked stops the device only", func(t *testing.T) {
		w := newWorld(t)
		c := w.provision(consoleKey())
		if err := w.acct.EmitAndProcess(context.Background(), "credential_revoked", coreAcct, "xbox", ""); err != nil {
			t.Fatal(err)
		}
		if _, code := w.macs(c.machineKey); code != krb.ErrClientRevoked {
			t.Fatalf("MACS after credential revoke: %d", code)
		}
		if _, err := w.authC.DeviceKey(context.Background(), machineID); !errors.Is(err, xbaccountapi.ErrDenied) {
			t.Fatalf("device key still released: %v", err)
		}
	})
	t.Run("ban stops everything", func(t *testing.T) {
		w := newWorld(t)
		c := w.provision(consoleKey())
		s := w.fullSignIn(c)
		if err := w.acct.EmitAndProcess(context.Background(), "account_banned", coreAcct, "", ""); err != nil {
			t.Fatal(err)
		}
		if _, admitted := w.sgInit(s.svc, s.svcKey, gamertag); admitted {
			t.Fatal("gateway admitted a banned user")
		}
	})
}

func TestUnlinkedAndUnprovisioned(t *testing.T) {
	t.Run("never provisioned", func(t *testing.T) {
		w := newWorld(t)
		if _, code := w.macs(consoleKey()); code != krb.ErrCPrincipalUnknown {
			t.Fatalf("code %d", code)
		}
	})
	t.Run("core link gone before any event arrives", func(t *testing.T) {
		w := newWorld(t)
		c := w.provision(consoleKey())
		s := w.fullSignIn(c)
		if err := w.acct.RevokeLinkInCore(context.Background(), c.xuid); err != nil {
			t.Fatal(err)
		}
		if _, code := w.macs(c.machineKey); code == 0 {
			t.Fatal("MACS with unlinked account")
		}
		if _, admitted := w.sgInit(s.svc, s.svcKey, gamertag); admitted {
			t.Fatal("gateway admitted an unlinked user")
		}
	})
}

func TestWrongKeys(t *testing.T) {
	w := newWorld(t)
	c := w.provision(consoleKey())
	other := xbcrypto.Key{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9}
	if _, code := w.macs(other); code != krb.ErrPreauthFailed {
		t.Fatalf("MACS with another machine key: %d", code)
	}
	s := w.fullSignIn(c)
	// Wrong user key, wrong machine account key, and a compound-keyed request
	// that omits the machine ticket all fail pre-authentication.
	if _, code := w.signIn(c, s.accountK, other, 30); code != krb.ErrPreauthFailed {
		t.Fatalf("wrong user key: %d", code)
	}
	if _, code := w.signIn(c, other, s.userKey, 32); code != krb.ErrPreauthFailed {
		t.Fatalf("wrong machine account key: %d", code)
	}
	if _, code := w.as(gamertag, xbcrypto.CompoundKey(s.userKey, other), 34, nil); code != krb.ErrPreauthFailed {
		t.Fatalf("compound-sealed request without the machine ticket: %d", code)
	}
	// A ticket whose session key the console does not hold cannot authenticate to the gateway.
	if _, admitted := w.sgInit(s.svc, other, gamertag); admitted {
		t.Fatal("gateway admitted an init authenticated with the wrong session key")
	}
}

// The order a real console uses (observed 2026-10-16): user AS alone, then the
// machine account AS with the user's TGT as compound identity, then TGS and the
// SG init. The ticket's client name is the machine account's; the init's
// authenticator must carry the same name for the gateway to admit it.
func TestRealConsoleOrderToGatewayAdmission(t *testing.T) {
	w := newWorld(t)
	c := w.provision(consoleKey())
	blob, code := w.macs(c.machineKey)
	if code != 0 {
		t.Fatalf("MACS error %d", code)
	}
	var mk, uk xbcrypto.Key
	copy(mk[:], blob[68:])
	ublob, err := w.kdc.UserAccountBlob(context.Background(), c.xuid)
	if err != nil {
		t.Fatal(err)
	}
	copy(uk[:], ublob[68:])
	var xuid uint64
	for i, b := range ublob[:8] {
		xuid |= uint64(b) << (8 * i)
	}
	userTGT, code := w.as(gamertag, uk, 20, nil)
	if code != 0 {
		t.Fatalf("user AS error %d", code)
	}
	compound := xbcrypto.CompoundKey(mk, userTGT.session)
	machTGT, code := w.as("SN."+serial, compound, 21, wrapSeq(userTGT.ticket.Marshal()))
	if code != 0 {
		t.Fatalf("machine AS with user compound error %d", code)
	}
	svc, svcKey, code := w.tgs(machTGT, "SN."+serial, xuid)
	if code != 0 {
		t.Fatalf("TGS error %d", code)
	}
	reply, admitted := w.sgInit(svc, svcKey, "SN."+serial)
	if reply == nil || !admitted {
		t.Fatal("gateway rejected the machine+user ticket with a matching authenticator name")
	}
}
