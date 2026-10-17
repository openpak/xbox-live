// SPDX-License-Identifier: AGPL-3.0-only

// Package e2e drives two Xbox-linked accounts through the whole social path:
// the console's Alive messages enter through a real mTLS xbfeature stream (as
// from the gateway) into svc1, which publishes presence to a fake account core;
// friend operations, invitations and the event poller work on the same core.
package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"openpak/xb-live/internal/xbaccountapi"
	"openpak/xb-live/internal/xbfeature"
	"openpak/xb-live/services/xb-social/internal/coretest"
	"openpak/xb-live/services/xb-social/internal/social"
	"openpak/xb-live/services/xb-social/internal/svc1"
)

const (
	xAlice = uint64(0x0009000000000001)
	xBob   = uint64(0x0009000000000002)
	title  = uint32(0x4d530004)
)

func hexid(x uint64) string { return fmt.Sprintf("%016x", x) }

type resolver struct{ c *coretest.Core }

func (r resolver) ResolveUser(_ context.Context, xuid string) (xbaccountapi.Principal, error) {
	for _, a := range []string{"alice", "bob"} {
		if l, ok := r.c.LinkOf(a); ok && l.Subject == xuid {
			if r.c.Banned(a) {
				return xbaccountapi.Principal{}, &xbaccountapi.DeniedError{}
			}
			return xbaccountapi.Principal{Kind: xbaccountapi.KindUser, PrincipalID: xuid, CoreAccountID: a, Status: xbaccountapi.StatusActive}, nil
		}
	}
	return xbaccountapi.Principal{}, xbaccountapi.ErrNotFound // unlinked: not admitted
}
func (resolver) ResolveDevice(context.Context, string) (xbaccountapi.Principal, error) {
	return xbaccountapi.Principal{}, xbaccountapi.ErrNotFound
}
func (resolver) ResolveGamertag(context.Context, string) (xbaccountapi.Principal, error) {
	return xbaccountapi.Principal{}, xbaccountapi.ErrNotFound
}

type pki struct {
	ca    *x509.Certificate
	key   *ecdsa.PrivateKey
	pool  *x509.CertPool
	count int64
}

func newPKI() *pki {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	ca, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &pki{ca: ca, key: k, pool: pool}
}

func (p *pki) leaf(uri string) tls.Certificate {
	p.count++
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse(uri)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(p.count + 1), Subject: pkix.Name{CommonName: "leaf"}, URIs: []*url.URL{u},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, p.ca, &k.PublicKey, p.key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

type world struct {
	t      *testing.T
	core   *coretest.Core
	soc    *social.Service
	pres   *social.Presences
	hub    *social.Hub
	poller *social.Poller
	cc     *grpc.ClientConn
}

func newWorld(t *testing.T) *world {
	c := coretest.New()
	for _, n := range []string{"alice", "bob"} {
		c.AddAccount(n, n)
	}
	c.LinkXbox("alice", hexid(xAlice), "Alice")
	c.LinkXbox("bob", hexid(xBob), "Bob")
	pres := &social.Presences{Core: c, Now: c.Now}
	soc := &social.Service{Core: c, Resolver: resolver{c}, Presence: pres, Now: c.Now}
	hub := &social.Hub{}
	w := &world{t: t, core: c, soc: soc, pres: pres, hub: hub,
		poller: &social.Poller{Core: c, Cursor: social.FileCursor{Path: t.TempDir() + "/cursor"}, Hub: hub, Presence: pres}}

	p := newPKI()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{p.leaf("spiffe://openpak/xb-social")},
		ClientCAs: p.pool, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13})))
	xbfeature.Register(g, &svc1.Server{Social: soc, Presence: pres, Now: c.Now})
	go g.Serve(lis)
	t.Cleanup(g.Stop)
	w.cc, err = grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{p.leaf(xbfeature.GatewayID)}, RootCAs: p.pool, ServerName: "localhost", MinVersion: tls.VersionTLS13})))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.cc.Close() })
	return w
}

// alive sends one Alive as the console of xuid would, through the gateway-style
// stream, and returns the HTTP status line and the reply body.
func (w *world) alive(xuid uint64, account string, gen uint64, titleID uint32) (string, []byte) {
	w.t.Helper()
	got := make(chan []byte, 8)
	closed := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := xbfeature.Open(ctx, w.cc, xbfeature.Info{PrincipalID: hexid(xuid), CoreAccountID: account, XUID: xuid, ServiceID: 1, Generation: gen},
		func(b []byte) error { got <- b; return nil }, func() { close(closed) })
	if err != nil {
		return "refused: " + err.Error(), nil
	}
	defer st.Close()
	msg := make([]byte, 32+120+9)
	binary.LittleEndian.PutUint32(msg[0:], 1025)
	binary.LittleEndian.PutUint32(msg[4:], 129)
	binary.LittleEndian.PutUint32(msg[8:], 1)
	binary.LittleEndian.PutUint64(msg[32:], xuid)
	binary.LittleEndian.PutUint16(msg[40:], 9)
	binary.LittleEndian.PutUint32(msg[32+86:], titleID)
	copy(msg[32+120:], "monocasa")
	req := fmt.Sprintf("POST /xpnfront/xpresence.srf HTTP/1.0\r\nContent-type: xon/1\r\nContent-Length: %d\r\n\r\n", len(msg))
	if err := st.Send(append([]byte(req), msg...)); err != nil {
		w.t.Fatal(err)
	}
	var all []byte
	for {
		select {
		case b := <-got:
			all = append(all, b...)
		case <-closed:
			head, body, _ := strings.Cut(string(all), "\r\n\r\n")
			return strings.SplitN(head, "\r\n", 2)[0], []byte(body)
		case <-ctx.Done():
			w.t.Fatal("no response")
		}
	}
}

func (w *world) tick(d time.Duration) {
	for ; d > 0; d -= 10 * time.Second {
		w.core.Advance(min(d, 10*time.Second))
		w.pres.Tick(context.Background())
	}
}

func TestFriendsPresenceInvitationAndNegatives(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	a, b := hexid(xAlice), hexid(xBob)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	// The poller starts at the stream head, then follows from its cursor.
	if _, err := w.poller.Step(ctx); err != nil {
		t.Fatal(err)
	}
	bobNotes := w.hub.Subscribe("bob")
	aliceNotes := w.hub.Subscribe("alice")

	// 1. Friend request -> accept.
	if o, err := w.soc.SendFriendRequest(ctx, a, "", b); err != nil || o != social.Requested {
		t.Fatal(o, err)
	}
	if _, err := w.poller.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if n := <-bobNotes.C; n.Kind != social.NoticeFriendRequested || n.Subject != "alice" {
		t.Fatalf("bob notice %+v", n)
	}
	r, _ := w.soc.Roster(ctx, b, "")
	if len(r.Incoming) != 1 || r.Incoming[0].XUID != a || r.Incoming[0].Gamertag != "Alice" {
		t.Fatalf("incoming %+v", r.Incoming)
	}
	must(w.soc.AcceptFriendRequest(ctx, b, "", a))
	w.poller.Step(ctx)
	if n := <-aliceNotes.C; n.Kind != social.NoticeFriendAccepted {
		t.Fatalf("alice notice %+v", n)
	}
	ra, _ := w.soc.Roster(ctx, a, "")
	if len(ra.Friends) != 1 || ra.Friends[0].XUID != b || ra.Friends[0].Presence.State != "offline" {
		t.Fatalf("alice friends %+v", ra.Friends)
	}

	// 2. Alice's console comes online in a title: Bob sees it; Alice reply carries her buddy list entry for Bob.
	if code, body := w.alive(xAlice, "alice", 1, title); code != "HTTP/1.0 200 OK" || len(body) != 48+8+2+1+len("Bob") || !strings.HasSuffix(string(body), "Bob") {
		t.Fatalf("alice alive: %q (%d bytes)", code, len(body))
	}
	rb, _ := w.soc.Roster(ctx, b, "")
	if f := rb.Friends[0]; f.XUID != a || f.Presence.State != "online" || f.Presence.TitleID != social.TitleKey(title) {
		t.Fatalf("bob sees %+v", f)
	}
	// Bob's Alive reply announces nothing it cannot encode, but is a real 200.
	if code, _ := w.alive(xBob, "bob", 1, title); code != "HTTP/1.0 200 OK" {
		t.Fatal(code)
	}

	// 3. Invitation Alice -> Bob, delivered once, then accepted.
	must(w.soc.SendInvite(ctx, a, "", b, title, []byte("lobby-7"), 0))
	w.poller.Step(ctx)
	if n := <-bobNotes.C; n.Kind != social.NoticeInvitation {
		t.Fatalf("invitation notice %+v", n)
	}
	var got []social.Invite
	if n, err := w.soc.PollInvites(ctx, b, "", func(in []social.Invite) error { got = append(got, in...); return nil }); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if got[0].From.XUID != a || string(got[0].Payload) != "lobby-7" {
		t.Fatalf("invite %+v", got[0])
	}
	w.tick(61 * time.Second)
	if n, _ := w.soc.PollInvites(ctx, b, "", func([]social.Invite) error { t.Fatal("redelivered"); return nil }); n != 0 {
		t.Fatal("redelivered")
	}
	if in, err := w.soc.AcceptInvite(ctx, b, "", got[0].ID); err != nil || in.TitleID != social.TitleKey(title) {
		t.Fatal(in, err)
	}

	// 4. Negatives. Bob blocks Alice: friendship gone, no invitations either way.
	must(w.soc.Block(ctx, b, "", a))
	if r, _ := w.soc.Roster(ctx, a, ""); len(r.Friends) != 0 {
		t.Fatalf("alice still lists bob: %+v", r.Friends)
	}
	if err := w.soc.SendInvite(ctx, a, "", b, title, []byte("x"), 0); err == nil {
		t.Fatal("blocked user could invite")
	}
	must(w.soc.Unblock(ctx, b, "", a))
	// Ban Alice: presence ends via the event stream, and her console is refused.
	w.core.Ban("alice")
	w.poller.Step(ctx)
	for n := range aliceNotes.C { // earlier notices (the block's friend_removed) come first
		if n.Kind == social.NoticeRevoked {
			break
		}
	}
	if _, ok := w.pres.Current("alice"); ok || len(w.core.Sessions("alice")) != 0 {
		t.Fatal("banned user still online")
	}
	if code, _ := w.alive(xAlice, "alice", 2, title); !strings.HasPrefix(code, "HTTP/1.0 403") {
		t.Fatalf("banned alive: %q", code)
	}
	// Unlink Bob: refused, and his presence goes.
	w.core.Unlink("bob", "xbox")
	w.poller.Step(ctx)
	if len(w.core.Sessions("bob")) != 0 {
		t.Fatal("unlinked user still online")
	}
	if code, _ := w.alive(xBob, "bob", 2, title); !strings.HasPrefix(code, "HTTP/1.0 403") {
		t.Fatalf("unlinked alive: %q", code)
	}
	// A request to an unlinked user looks like an unknown user.
	if _, err := w.soc.SendFriendRequest(ctx, a, "", b); err == nil {
		t.Fatal("banned viewer could send")
	}
}

func TestConcurrentConnectionsOnePresence(t *testing.T) {
	w := newWorld(t)
	var wg sync.WaitGroup
	for g := uint64(1); g <= 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.alive(xAlice, "alice", g, title)
		}()
	}
	wg.Wait()
	if s := w.core.Sessions("alice"); len(s) != 1 {
		t.Fatalf("sessions %v", s)
	}
}
