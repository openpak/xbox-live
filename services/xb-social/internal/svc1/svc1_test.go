// SPDX-License-Identifier: AGPL-3.0-only

package svc1

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"testing"

	"openpak/xb-live/internal/xbaccountapi"
	"openpak/xb-live/internal/xbfeature"
	"openpak/xb-live/services/xb-social/internal/core"
	"openpak/xb-live/services/xb-social/internal/coretest"
	"openpak/xb-live/services/xb-social/internal/social"
)

// Vectors from the Xombie presence codec tests (libs/xblive/src/service/presence.rs).
const (
	aliveHex = "e90300002f000000010000000a000064" + "00010000010000000000000000000000" +
		"3292446c907409000b00414c09000000" + "00000000000005000000000000000000" + "0000000000006d6f6e6f6361736100"
	xAlice = uint64(0x000974906c449232)
	xBob   = "0009000000000002"
)

func aliveFor(t *testing.T, buddyVer, blockVer uint32) []byte {
	b, err := hex.DecodeString(aliveHex)
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint32(b[presenceHeader+14:], buddyVer)
	binary.LittleEndian.PutUint32(b[presenceHeader+18:], blockVer)
	return b
}

func alive2(xuid uint64, title uint32) []byte {
	b := make([]byte, presenceHeader+alive2Body+9)
	binary.LittleEndian.PutUint32(b[0:], 0x401)
	binary.LittleEndian.PutUint32(b[4:], 0x81)
	binary.LittleEndian.PutUint32(b[8:], 1)
	binary.LittleEndian.PutUint64(b[presenceHeader:], xuid)
	binary.LittleEndian.PutUint16(b[presenceHeader+8:], 9)
	binary.LittleEndian.PutUint32(b[presenceHeader+86:], title)
	copy(b[presenceHeader+alive2Body:], "monocasa")
	return b
}

type resolver struct{ c *coretest.Core }

func (r resolver) ResolveUser(_ context.Context, xuid string) (xbaccountapi.Principal, error) {
	for _, a := range []string{"alice", "bob", "carol", "dave"} {
		if l, ok := r.c.LinkOf(a); ok && l.Subject == xuid {
			if r.c.Banned(a) {
				return xbaccountapi.Principal{}, &xbaccountapi.DeniedError{}
			}
			return xbaccountapi.Principal{Kind: xbaccountapi.KindUser, PrincipalID: xuid, CoreAccountID: a, Status: xbaccountapi.StatusActive}, nil
		}
	}
	return xbaccountapi.Principal{}, xbaccountapi.ErrNotFound
}
func (resolver) ResolveDevice(context.Context, string) (xbaccountapi.Principal, error) {
	return xbaccountapi.Principal{}, xbaccountapi.ErrNotFound
}
func (resolver) ResolveGamertag(context.Context, string) (xbaccountapi.Principal, error) {
	return xbaccountapi.Principal{}, xbaccountapi.ErrNotFound
}

type conn struct {
	in  [][]byte
	out []byte
}

func (c *conn) Recv() ([]byte, error) {
	if len(c.in) == 0 {
		return nil, io.EOF
	}
	b := c.in[0]
	c.in = c.in[1:]
	return b, nil
}
func (c *conn) Send(b []byte) error { c.out = append(c.out, b...); return nil }

type env struct {
	c   *coretest.Core
	srv *Server
}

func newEnv(t *testing.T) *env {
	c := coretest.New()
	c.AddAccount("alice", "alice")
	c.AddAccount("bob", "bob")
	c.LinkXbox("alice", fmt.Sprintf("%016x", xAlice), "monocasa")
	c.LinkXbox("bob", xBob, "Bob")
	p := &social.Presences{Core: c, Now: c.Now}
	s := &social.Service{Core: c, Resolver: resolver{c}, Presence: p, Now: c.Now}
	return &env{c, &Server{Social: s, Presence: p, Now: c.Now}}
}

func info(xuid uint64) xbfeature.Info {
	return xbfeature.Info{PrincipalID: fmt.Sprintf("%016x", xuid), CoreAccountID: "alice", XUID: xuid, ServiceID: 1, Generation: 1}
}

func (e *env) do(t *testing.T, inf xbfeature.Info, ct string, body []byte) (code string, reply []byte) {
	t.Helper()
	return e.doPath(t, "/xpnfront/xpresence.srf", inf, ct, body)
}

func (e *env) doPath(t *testing.T, path string, inf xbfeature.Info, ct string, body []byte) (code string, reply []byte) {
	t.Helper()
	req := fmt.Sprintf("POST "+path+" HTTP/1.0\r\nContent-type: %s\r\nContent-Length: %d\r\n\r\n", ct, len(body))
	c := &conn{in: [][]byte{append([]byte(req), body...)}}
	e.srv.Serve(context.Background(), inf, c)
	head, b, _ := strings.Cut(string(c.out), "\r\n\r\n")
	lines := strings.SplitN(head, "\r\n", 2)
	if len(lines) == 2 {
		for _, l := range strings.Split(lines[1], "\r\n") {
			if v, ok := strings.CutPrefix(l, "X-Err: "); ok {
				return lines[0] + " X-Err:" + v, []byte(b)
			}
		}
	}
	return lines[0], []byte(b)
}

func versions(b []byte) (buddyV uint32, nb uint16, blockV uint32, nl uint16) {
	return binary.LittleEndian.Uint32(b[presenceHeader+4:]), binary.LittleEndian.Uint16(b[presenceHeader+8:]),
		binary.LittleEndian.Uint32(b[presenceHeader+10:]), binary.LittleEndian.Uint16(b[presenceHeader+14:])
}

func TestAlivePublishesPresenceAndEmptyRoster(t *testing.T) {
	e := newEnv(t)
	in := aliveFor(t, 0, 0)
	code, out := e.do(t, info(xAlice), "xon/1", in)
	if code != "HTTP/1.0 200 OK X-Err:0" || len(out) != 48 || binary.LittleEndian.Uint32(out) != 1101 || binary.LittleEndian.Uint32(out[4:]) != 16 ||
		string(out[8:32]) != string(in[8:32]) {
		t.Fatalf("%q % x", code, out)
	}
	if v, nb, bv, nl := versions(out); v != 0 || nb != 0 || bv != 0 || nl != 0 {
		t.Fatalf("empty roster: %d %d %d %d", v, nb, bv, nl)
	}
	if got := e.c.Sessions("alice"); len(got) != 1 || got[0] != "xbox/4c41000b" {
		t.Fatalf("published %v", got)
	}
}

func TestAlive2PublishesDashboardAsTitleless(t *testing.T) {
	e := newEnv(t)
	code, _ := e.do(t, info(xAlice), "xon/1", alive2(xAlice, 0xfffe0000))
	if code != "HTTP/1.0 200 OK X-Err:0" {
		t.Fatal(code)
	}
	if got := e.c.Sessions("alice"); len(got) != 1 || got[0] != "xbox/" {
		t.Fatalf("published %v", got)
	}
}

func TestAliveReplyReflectsRealRoster(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a := fmt.Sprintf("%016x", xAlice)
	if _, err := e.srv.Social.SendFriendRequest(ctx, xBob, "", a); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.Social.AcceptFriendRequest(ctx, a, "", xBob); err != nil {
		t.Fatal(err)
	}
	r, _ := e.srv.Social.Roster(ctx, a, "")

	// Out-of-date console: version, count and the entry (xuid, name_len, status, name).
	_, out := e.do(t, info(xAlice), "xon/1", aliveFor(t, 0, 0))
	v, nb, _, _ := versions(out)
	entry := binary.LittleEndian.AppendUint64(nil, 0x0009000000000002)
	entry = binary.LittleEndian.AppendUint16(entry, 3)
	entry = append(entry, 0)
	entry = append(entry, "Bob"...)
	if v != r.BuddyVersion || v == 0 || nb != 1 || string(out[presenceHeader+16:]) != string(entry) ||
		binary.LittleEndian.Uint32(out[4:]) != uint32(16+len(entry)) {
		t.Fatalf("v=%d nb=%d % x", v, nb, out)
	}
	// Console already holding our version: never the equal-version skip path;
	// it gets the neighbouring version and the full list again.
	_, out = e.do(t, info(xAlice), "xon/1", aliveFor(t, r.BuddyVersion, 0))
	if v2, nb, _, _ := versions(out); v2 != r.BuddyVersion+1 || nb != 1 || string(out[presenceHeader+16:]) != string(entry) {
		t.Fatalf("held version: %d %d", v2, nb)
	}
	// ...and again when it holds the neighbouring one.
	_, out = e.do(t, info(xAlice), "xon/1", aliveFor(t, r.BuddyVersion+1, 0))
	if v2, nb, _, _ := versions(out); v2 != r.BuddyVersion || nb != 1 {
		t.Fatalf("alternate: %d %d", v2, nb)
	}
	// An empty roster with an empty console stays the plain stub reply.
	// The console's 0xffffffff stamp (held list, forced resend) gets the full list.
	_, out = e.do(t, info(xAlice), "xon/1", aliveFor(t, 0xffffffff, 0))
	if _, nb, _, _ := versions(out); nb != 1 {
		t.Fatalf("forced resend: %d", nb)
	}
}

func TestAliveRequestsBlocksAndStatus(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a := fmt.Sprintf("%016x", xAlice)
	e.c.AddAccount("carol", "carol")
	e.c.LinkXbox("carol", "0009000000000003", "Carol")
	e.c.AddAccount("dave", "dave")
	e.c.LinkXbox("dave", "0009000000000004", "Dave")
	e.srv.Social.SendFriendRequest(ctx, xBob, "", a)               // bob -> alice: received
	e.srv.Social.SendFriendRequest(ctx, a, "", "0009000000000003") // alice -> carol: sent
	if err := e.srv.Social.Block(ctx, a, "", "0009000000000004"); err != nil {
		t.Fatal(err)
	}
	_, out := e.do(t, info(xAlice), "xon/1", aliveFor(t, 0, 0))
	_, nb, _, nl := versions(out)
	p := out[presenceHeader+16:]
	// bob: received (status 2), carol: sent (status 1), then dave's block entry.
	if nb != 2 || nl != 1 || p[10] != statusRequestReceived || string(p[11:14]) != "Bob" ||
		p[14+8+2] != statusRequestSent || binary.LittleEndian.Uint64(p[len(p)-8:]) != 0x0009000000000004 {
		t.Fatalf("nb=%d nl=%d % x", nb, nl, p)
	}
}

func TestMultipleAliveInOnePost(t *testing.T) {
	e := newEnv(t)
	one := aliveFor(t, 0, 0)
	b := append([]byte(nil), one...)
	binary.LittleEndian.PutUint32(b[8:], 77) // second message, different seq
	code, out := e.do(t, info(xAlice), "xon/1", append(append([]byte(nil), one...), b...))
	if code != "HTTP/1.0 200 OK X-Err:0" || len(out) != 96 || binary.LittleEndian.Uint32(out[8:]) != 1 || binary.LittleEndian.Uint32(out[48+8:]) != 77 {
		t.Fatalf("%q %d", code, len(out))
	}
	// A message for another user in the same POST cannot be answered honestly.
	other := alive2(xBob2, 0xfffe0000)
	if code, _ := e.do(t, info(xAlice), "xon/1", append(append([]byte(nil), one...), other...)); !strings.HasPrefix(code, "HTTP/1.0 400") {
		t.Fatalf("foreign user accepted: %q", code)
	}
}

const xBob2 = uint64(2)

func TestAliveRejections(t *testing.T) {
	e := newEnv(t)
	alive := aliveFor(t, 0, 0)
	cases := map[string]struct {
		inf  xbfeature.Info
		ct   string
		body []byte
		want string
	}{
		"xuid mismatch": {info(5), "xon/1", alive, "400"},
		"no user":       {xbfeature.Info{ServiceID: 1}, "xon/1", alive, "403"},
		"truncated":     {info(xAlice), "xon/1", alive[:len(alive)-1], "400"},
		"content type":  {info(xAlice), "xon/5", alive, "400"},
		"unknown type": {info(xAlice), "xon/1", func() []byte {
			b := append([]byte(nil), alive...)
			binary.LittleEndian.PutUint32(b, 1999)
			return b
		}(), "501"},
		"unknown account": {func() xbfeature.Info { i := info(7); return i }(), "xon/1", alive, "400"},
	}
	for name, c := range cases {
		code, _ := e.do(t, c.inf, c.ct, c.body)
		if !strings.HasPrefix(code, "HTTP/1.0 "+c.want) {
			t.Errorf("%s: %q want %s", name, code, c.want)
		}
	}
	if len(e.c.Sessions("alice")) != 0 {
		t.Fatalf("rejected requests published presence: %v", e.c.Sessions("alice"))
	}
	// Gateway account must agree with the resolver.
	bad := info(xAlice)
	bad.CoreAccountID = "bob"
	if code, _ := e.do(t, bad, "xon/1", alive); !strings.HasPrefix(code, "HTTP/1.0 403") {
		t.Errorf("account mismatch: %q", code)
	}
	// Banned user: 403, nothing published.
	e.c.Ban("alice")
	if code, _ := e.do(t, info(xAlice), "xon/1", alive); !strings.HasPrefix(code, "HTTP/1.0 403") {
		t.Errorf("banned: %q", code)
	}
	if len(e.c.Sessions("alice")) != 0 {
		t.Fatal("banned user published")
	}
}

func TestBackendDownIs503AndSupersededIs409(t *testing.T) {
	e := newEnv(t)
	alive := aliveFor(t, 0, 0)
	e.c.Fail = func(op string) error {
		if op == "ListFriends" {
			return fmt.Errorf("down")
		}
		return nil
	}
	if code, _ := e.do(t, info(xAlice), "xon/1", alive); !strings.HasPrefix(code, "HTTP/1.0 503") {
		t.Fatalf("%q", code)
	}
	e.c.Fail = nil
	newer := info(xAlice)
	newer.Generation = 9
	if code, _ := e.do(t, newer, "xon/1", alive); !strings.HasPrefix(code, "HTTP/1.0 200") {
		t.Fatalf("%q", code)
	}
	if code, _ := e.do(t, info(xAlice), "xon/1", alive); !strings.HasPrefix(code, "HTTP/1.0 409") {
		t.Fatalf("older generation: %q", code)
	}
}

type msgs struct{ got uint32 }

func (m *msgs) Handle(_ context.Context, _ Call, typ uint32, _ [presenceHeader]byte, _ []byte) ([]byte, error) {
	m.got = typ
	return []byte("ok"), nil
}

func TestMessagesPlugin(t *testing.T) {
	e := newEnv(t)
	m := &msgs{}
	e.srv.Messages = m
	b := aliveFor(t, 0, 0)
	binary.LittleEndian.PutUint32(b, 1999)
	code, out := e.do(t, info(xAlice), "xon/1", b)
	if !strings.HasPrefix(code, "HTTP/1.0 200") || m.got != 1999 || string(out) != "ok" {
		t.Fatalf("%q %d %q", code, m.got, out)
	}
	e.c.Ban("alice")
	if code, _ := e.do(t, info(xAlice), "xon/1", b); !strings.HasPrefix(code, "HTTP/1.0 403") {
		t.Fatalf("banned plug-in call: %q", code)
	}
}

type other struct{ called bool }

func (o *other) Serve(context.Context, xbfeature.Info, xbfeature.Conn) error {
	o.called = true
	return nil
}

func TestServiceRouting(t *testing.T) {
	e := newEnv(t)
	o := &other{}
	e.srv.Others = map[uint32]xbfeature.Handler{7: o}
	i := info(xAlice)
	i.ServiceID = 7
	if err := e.srv.Serve(context.Background(), i, &conn{}); err != nil || !o.called {
		t.Fatalf("others: %v %v", err, o.called)
	}
	i.ServiceID = 8
	if err := e.srv.Serve(context.Background(), i, &conn{}); err == nil { // honest: stream refused
		t.Fatal("unimplemented service id served")
	}
}

func TestOfflineOnClose(t *testing.T) {
	e := newEnv(t)
	e.srv.OfflineOnClose = true
	e.do(t, info(xAlice), "xon/1", aliveFor(t, 0, 0))
	if len(e.c.Sessions("alice")) != 0 {
		t.Fatalf("still online after close: %v", e.c.Sessions("alice"))
	}
}

// A presence-refresh failure must never fail the Alive: the console still gets
// its lists. Covers core answering NotFound / FailedPrecondition / Unavailable
// on the session calls, and a lease left by another connection generation.
func TestAliveSurvivesPresenceFailures(t *testing.T) {
	alive := aliveFor(t, 0, 0)
	for _, op := range []string{"RegisterSession", "Heartbeat", "ExpireSession"} {
		for name, ferr := range map[string]error{"unavailable": core.ErrUnavailable, "notfound": core.ErrNotFound, "conflict": core.ErrConflict} {
			e := newEnv(t)
			// First Alive in one title creates a lease; then core starts failing and the title changes.
			e.do(t, info(xAlice), "xon/1", alive2(xAlice, 0x4d530001))
			e.c.Fail = func(o string) error {
				if o == op {
					return ferr
				}
				return nil
			}
			code, out := e.do(t, info(xAlice), "xon/1", alive)
			if code != "HTTP/1.0 200 OK X-Err:0" || len(out) < 48 {
				t.Errorf("%s/%s: %q", op, name, code)
			}
			// Same title again (the Heartbeat path).
			code, _ = e.do(t, info(xAlice), "xon/1", alive2(xAlice, 0x4d530001))
			if code != "HTTP/1.0 200 OK X-Err:0" {
				t.Errorf("%s/%s same title: %q", op, name, code)
			}
		}
	}
}

func TestAliveTakesOverLeaseFromAnotherGeneration(t *testing.T) {
	e := newEnv(t)
	// Another connection (older generation) left a live lease for the same title.
	old := info(xAlice)
	old.Generation = 1
	e.do(t, old, "xon/1", alive2(xAlice, 0x4d530001))
	e.c.Advance(60e9)
	newer := info(xAlice)
	newer.Generation = 2
	if code, _ := e.do(t, newer, "xon/1", alive2(xAlice, 0x4d530001)); code != "HTTP/1.0 200 OK X-Err:0" {
		t.Fatalf("takeover: %q", code)
	}
	if got := e.c.Sessions("alice"); len(got) != 1 || got[0] != "xbox/4d530001" {
		t.Fatalf("sessions %v", got)
	}
	// A foreign seeded session in the same title (other namespace) coexists.
	e.c.AddForeignSession("alice", "switch", "4d530001")
	if code, _ := e.do(t, newer, "xon/1", alive2(xAlice, 0x4d530001)); code != "HTTP/1.0 200 OK X-Err:0" {
		t.Fatalf("with foreign session: %q", code)
	}
}

func TestAliveWithoutInvitationInbox(t *testing.T) {
	e := newEnv(t)
	e.c.Fail = func(o string) error {
		if o == "ListInvitations" {
			return core.ErrUnavailable // e.g. an older core without the call
		}
		return nil
	}
	if code, _ := e.do(t, info(xAlice), "xon/1", aliveFor(t, 0, 0)); code != "HTTP/1.0 200 OK X-Err:0" {
		t.Fatalf("%q", code)
	}
}
