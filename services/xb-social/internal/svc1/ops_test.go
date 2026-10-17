// SPDX-License-Identifier: AGPL-3.0-only

package svc1

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"openpak/xb-live/internal/xbfeature"
)

const (
	bobX = uint64(0x0009000000000002)
	ttl  = uint32(0x4d530004)
)

// msg builds a header (type, len, seq, 20 byte SG address) plus body.
func msg(typ uint32, seq uint32, parts ...any) []byte {
	var body []byte
	for _, p := range parts {
		switch v := p.(type) {
		case uint64:
			body = binary.LittleEndian.AppendUint64(body, v)
		case uint32:
			body = binary.LittleEndian.AppendUint32(body, v)
		case uint16:
			body = binary.LittleEndian.AppendUint16(body, v)
		case []byte:
			body = append(body, v...)
		}
	}
	h := make([]byte, presenceHeader)
	binary.LittleEndian.PutUint32(h[0:], typ)
	binary.LittleEndian.PutUint32(h[4:], uint32(len(body)))
	binary.LittleEndian.PutUint32(h[8:], seq)
	h[12] = 0xaa
	return append(h, body...)
}

func infoFor(xuid uint64, account string) xbfeature.Info {
	return xbfeature.Info{PrincipalID: fmt.Sprintf("%016x", xuid), CoreAccountID: account, XUID: xuid, ServiceID: 1, Generation: 1}
}

func (e *env) op(t *testing.T, xuid uint64, account string, m []byte) string {
	t.Helper()
	code, _ := e.do(t, infoFor(xuid, account), "xon/1", m)
	return code
}

const ok = "HTTP/1.0 200 OK X-Err:0"

func TestFriendOperations(t *testing.T) {
	e := newEnv(t)
	a, b := xAlice, bobX
	if c := e.op(t, a, "alice", msg(opFriendRequest, 1, a, b, uint16(0))); c != ok {
		t.Fatalf("request %q", c)
	}
	if c := e.op(t, a, "alice", msg(opFriendRequest, 1, a, a, uint16(0))); !strings.HasSuffix(c, "X-Err:8015200a") {
		t.Fatalf("self %q", c)
	}
	if c := e.op(t, a, "alice", msg(opFriendRequest, 1, a, uint64(0x0009ffffffffffff), uint16(0))); !strings.HasSuffix(c, "X-Err:80152008") {
		t.Fatalf("unknown %q", c)
	}
	// Bob declines, then asks, and Alice accepts (0x3ef with 0).
	if c := e.op(t, b, "bob", msg(opDecline, 1, b, a)); c != ok {
		t.Fatalf("decline %q", c)
	}
	if c := e.op(t, b, "bob", msg(opDecline, 1, b, a)); !strings.HasSuffix(c, "X-Err:80152008") {
		t.Fatalf("decline twice %q", c)
	}
	e.op(t, b, "bob", msg(opFriendRequest, 1, b, a, uint16(0)))
	if c := e.op(t, a, "alice", msg(opAcceptBlock, 1, a, b, uint32(0))); c != ok {
		t.Fatalf("accept %q", c)
	}
	if c := e.op(t, a, "alice", msg(opFriendRequest, 1, a, b, uint16(0))); !strings.HasSuffix(c, "X-Err:80152007") {
		t.Fatalf("already friends %q", c)
	}
	// Remove, then cancel an own pending request with the same message.
	if c := e.op(t, a, "alice", msg(opRemove, 1, a, b)); c != ok {
		t.Fatalf("remove %q", c)
	}
	e.op(t, a, "alice", msg(opFriendRequest, 1, a, b, uint16(0)))
	if c := e.op(t, a, "alice", msg(opRemove, 1, a, b)); c != ok {
		t.Fatalf("cancel %q", c)
	}
	// Block (0x3ef with 1).
	if c := e.op(t, a, "alice", msg(opAcceptBlock, 1, a, b, uint32(1))); c != ok {
		t.Fatalf("block %q", c)
	}
	r, _ := e.srv.Social.Roster(context.Background(), fmt.Sprintf("%016x", a), "")
	if len(r.Blocked) != 1 {
		t.Fatalf("blocks %+v", r.Blocked)
	}
	// Bad shapes and impersonation are rejected before any effect.
	if c := e.op(t, a, "alice", msg(opFriendRequest, 1, a, b)); !strings.HasPrefix(c, "HTTP/1.0 400") {
		t.Fatalf("short %q", c)
	}
	if c := e.op(t, a, "alice", msg(opRemove, 1, b, a)); !strings.HasPrefix(c, "HTTP/1.0 400") {
		t.Fatalf("sender is not the connection user: %q", c)
	}
	if c := e.op(t, a, "alice", msg(opAcceptBlock, 1, a, b, uint32(7))); !strings.HasPrefix(c, "HTTP/1.0 400") {
		t.Fatalf("bad mode %q", c)
	}
}

func TestInviteOperationsAndNotificationPoll(t *testing.T) {
	e := newEnv(t)
	a, b := xAlice, bobX
	e.op(t, a, "alice", msg(opFriendRequest, 1, a, b, uint16(0)))
	e.op(t, b, "bob", msg(opAcceptBlock, 1, b, a, uint32(0)))
	// Nobody is in a title yet: no presence session.
	if c := e.op(t, a, "alice", msg(opSendInvite, 1, a, uint64(99), uint16(1), b)); !strings.HasSuffix(c, "X-Err:8015200c") {
		t.Fatalf("offline invite %q", c)
	}
	e.do(t, infoFor(a, "alice"), "xon/1", alive2(a, ttl))
	e.do(t, infoFor(b, "bob"), "xon/1", alive2(b, ttl))
	const session = uint64(0xabcdef0123)
	if c := e.op(t, a, "alice", msg(opSendInvite, 1, a, session, uint16(1), b)); c != ok {
		t.Fatalf("invite %q", c)
	}
	poll := func(xuid uint64, account string, kind uint16) []byte {
		t.Helper()
		m := msg(msgNotifyPoll, 5, xuid, kind, uint32(0), uint16(0x14), uint32(0x800))
		code, out := e.doPath(t, "/xpnfront/xnotification.srf", infoFor(xuid, account), "xon/1", m)
		if code != ok || len(out) < 0x3e {
			t.Fatalf("poll %q %d", code, len(out))
		}
		if int(binary.LittleEndian.Uint32(out[4:]))+0x20 != len(out) || binary.LittleEndian.Uint64(out[0x20:]) != xuid ||
			binary.LittleEndian.Uint16(out[0x28:]) != kind || binary.LittleEndian.Uint32(out[0x8:]) != 5 {
			t.Fatalf("poll header % x", out[:0x3e])
		}
		return out
	}
	// Kind 3: one record, inviter, session, title, FILETIME.
	out := poll(b, "bob", 3)
	if n := binary.LittleEndian.Uint16(out[0x34:]); n != 1 {
		t.Fatalf("records %d", n)
	}
	rec := out[0x3e:]
	body := rec[6:]
	if binary.LittleEndian.Uint16(rec[4:]) != inviteRecBody || len(rec) != 6+inviteRecBody ||
		binary.LittleEndian.Uint64(body) != a || binary.LittleEndian.Uint64(body[8:]) != session || binary.LittleEndian.Uint32(body[0x10:]) != ttl ||
		binary.LittleEndian.Uint64(body[0x14:]) < filetimeUnixEpoch {
		t.Fatalf("invite record % x", rec)
	}
	// Delivered once.
	for range 7 { // the keepalive runs every 10 s in production
		e.c.Advance(10e9)
		e.srv.Presence.Tick(context.Background())
	}
	if out := poll(b, "bob", 3); binary.LittleEndian.Uint16(out[0x34:]) != 0 {
		t.Fatal("invitation delivered twice")
	}
	// Bob accepts; Alice's kind-4 poll shows the answer once.
	if c := e.op(t, b, "bob", msg(opAnswerInvite, 1, b, a, session, uint16(1))); c != ok {
		t.Fatalf("answer %q", c)
	}
	if c := e.op(t, b, "bob", msg(opAnswerInvite, 1, b, a, uint64(1), uint16(1))); !strings.HasSuffix(c, "X-Err:80152008") {
		t.Fatalf("unknown invite %q", c)
	}
	out = poll(a, "alice", 4)
	rec = out[0x3e:]
	if binary.LittleEndian.Uint16(out[0x34:]) != 1 || binary.LittleEndian.Uint64(rec[6:]) != b || binary.LittleEndian.Uint16(rec[6+0x18:]) != 1 {
		t.Fatalf("answer record % x", rec)
	}
	if binary.LittleEndian.Uint16(poll(a, "alice", 4)[0x34:]) != 0 {
		t.Fatal("answer delivered twice")
	}
	// Kind 2: Alice sees Bob online in the title; kinds 0: the confirmed friend.
	out = poll(a, "alice", 2)
	rec = out[0x3e:]
	if binary.LittleEndian.Uint16(out[0x34:]) != 1 || binary.LittleEndian.Uint64(rec[6:]) != b || binary.LittleEndian.Uint32(rec[6+8:]) != ttl ||
		binary.LittleEndian.Uint32(rec[6+0xc:])&flagOnline == 0 || binary.LittleEndian.Uint16(rec[4:]) != presRecBody {
		t.Fatalf("presence record % x", rec)
	}
	out = poll(a, "alice", 0)
	rec = out[0x3e:]
	if binary.LittleEndian.Uint16(out[0x34:]) != 1 || binary.LittleEndian.Uint64(rec[6+4:]) != b || binary.LittleEndian.Uint16(rec[6+0xc:]) != opListConfirmed ||
		string(rec[6+0x14:]) != "Bob" || binary.LittleEndian.Uint16(rec[6+0x12:]) != 3 {
		t.Fatalf("list record % x", rec)
	}
	// Poll shape rules.
	bad := msg(msgNotifyPoll, 5, b, uint16(0), uint32(0), uint16(0x14), uint32(0x800)) // wrong user
	if code, _ := e.doPath(t, "/xpnfront/xnotification.srf", infoFor(a, "alice"), "xon/1", bad); !strings.HasPrefix(code, "HTTP/1.0 400") {
		t.Fatalf("foreign poll %q", code)
	}
}

// Pins the exact AliveReply bytes for a roster of one friend (xbtest2, status 0),
// one received request (xbtest3, status 2) and no blocks, and checks them with
// an independent re-implementation of the console's parser (decompile of the
// dashboard's list reader: 11-byte entry header, name_len <= 16, status 0/1/2,
// xuid and first name byte non-zero, <= 100 entries, payload ends the message).
func TestAliveReplyBytesMatchConsoleParser(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.c.AddAccount("carol", "carol")
	e.c.LinkXbox("carol", "00090243645ad44d", "xbtest3")
	e.c.AddAccount("dave", "dave")
	e.c.LinkXbox("dave", "00095feff338cc25", "xbtest2")
	a := fmt.Sprintf("%016x", xAlice)
	e.srv.Social.SendFriendRequest(ctx, "00095feff338cc25", "", a)
	e.srv.Social.AcceptFriendRequest(ctx, a, "", "00095feff338cc25")
	e.srv.Social.SendFriendRequest(ctx, "00090243645ad44d", "", a)
	code, out := e.do(t, info(xAlice), "xon/1", aliveFor(t, 0, 0))
	if code != "HTTP/1.0 200 OK X-Err:0" {
		t.Fatal(code)
	}
	t.Logf("AliveReply hex: %x", out)
	if binary.LittleEndian.Uint32(out[4:]) != uint32(len(out)-presenceHeader) {
		t.Fatal("length field")
	}
	if int32(binary.LittleEndian.Uint32(out[presenceHeader:])) != 0 {
		t.Fatal("HR")
	}
	ver := binary.LittleEndian.Uint32(out[presenceHeader+4:])
	n := int(binary.LittleEndian.Uint16(out[presenceHeader+8:]))
	if ver == 0xffffffff || ver == 0xfffffffe || ver == 0 || n != 2 || n > 100 {
		t.Fatalf("version %d count %d", ver, n)
	}
	p := out[presenceHeader+16:]
	want := []struct {
		x    uint64
		name string
		st   byte
	}{{0x00095feff338cc25, "xbtest2", 0}, {0x00090243645ad44d, "xbtest3", 2}}
	for i := 0; i < n; i++ {
		if len(p) < 11 {
			t.Fatal("short entry header")
		}
		x, l, st := binary.LittleEndian.Uint64(p), int(binary.LittleEndian.Uint16(p[8:])), p[10]
		if x == 0 || l < 1 || l > 16 || st > 2 || len(p) < 11+l || p[11] == 0 {
			t.Fatalf("entry %d rejected by console rules: % x", i, p)
		}
		if x != want[i].x || string(p[11:11+l]) != want[i].name || st != want[i].st {
			t.Fatalf("entry %d: %x %q %d", i, x, p[11:11+l], st)
		}
		p = p[11+l:]
	}
	if len(p) != 0 || binary.LittleEndian.Uint16(out[presenceHeader+14:]) != 0 {
		t.Fatalf("trailing % x", p)
	}
}

func TestStubModes(t *testing.T) {
	in := aliveFor(t, 0, 0)
	e := newEnv(t)
	e.srv.Stub = true
	code, out := e.do(t, info(xAlice), "xon/1", in)
	want := append(append([]byte(nil), 0x4d, 4, 0, 0, 0x10, 0, 0, 0), in[8:32]...)
	want = append(want, make([]byte, 16)...)
	if code != "HTTP/1.0 200 OK X-Err:0" || string(out) != string(want) {
		t.Fatalf("%q % x", code, out)
	}
	if len(e.c.Calls) != 0 || len(e.c.Sessions("alice")) != 0 {
		t.Fatalf("stub mode touched core: %v", e.c.Calls)
	}
	e = newEnv(t)
	e.srv.StubWork = true
	code, out = e.do(t, info(xAlice), "xon/1", in)
	if code != "HTTP/1.0 200 OK X-Err:0" || string(out) != string(want) || len(e.c.Sessions("alice")) != 1 {
		t.Fatalf("stubwork: %q % x %v", code, out, e.c.Sessions("alice"))
	}
}
