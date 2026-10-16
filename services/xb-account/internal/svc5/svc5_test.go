// SPDX-License-Identifier: AGPL-3.0-only

package svc5

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"openpak/xb-live/internal/xbfeature"
	"openpak/xb-live/services/xb-account/internal/store"
)

const (
	machineA = "000000ce0d452f69"
	machineB = "0000001cbe991a14"
)

type memConn struct {
	mu  sync.Mutex
	in  [][]byte
	out bytes.Buffer
}

func (c *memConn) Recv() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.in) == 0 {
		return nil, io.EOF
	}
	b := c.in[0]
	c.in = c.in[1:]
	return b, nil
}
func (c *memConn) Send(b []byte) error { c.out.Write(b); return nil }

func newServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "x.db"), bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return &Server{Names: db}, db
}

func body(machine uint64, locale byte, want uint16, name string) []byte {
	b := binary.LittleEndian.AppendUint64(nil, machine)
	b = append(b, locale)
	b = binary.LittleEndian.AppendUint16(b, want)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(name)))
	return append(b, name...)
}

// do sends one HTTP/1.0 request through Serve and returns the raw response.
func do(t *testing.T, s *Server, info xbfeature.Info, method, path, ctype string, b []byte) string {
	t.Helper()
	req := method + " " + path + " HTTP/1.0\r\nUser-Agent: 5/1.00.5849\r\n"
	if ctype != "" {
		req += "Content-type: " + ctype + "\r\n"
	}
	req += "Content-Length: " + itoa(len(b)) + "\r\n\r\n" + string(b)
	c := &memConn{in: [][]byte{[]byte(req)}}
	if err := s.Serve(context.Background(), info, c); err != nil {
		t.Fatal(err)
	}
	return c.out.String()
}

func itoa(n int) string { return strconv.Itoa(n) }

var infoA = xbfeature.Info{PrincipalID: machineA, CoreAccountID: "acct1", XUID: 0xce0d452f69, ServiceID: 5}

func names(t *testing.T, resp string) []string {
	t.Helper()
	_, b, _ := strings.Cut(resp, "\r\n\r\n")
	raw := []byte(b)
	n := int(binary.LittleEndian.Uint16(raw))
	raw = raw[2:]
	var out []string
	for i := 0; i < n; i++ {
		l := int(binary.LittleEndian.Uint16(raw))
		out = append(out, string(raw[2:2+l]))
		raw = raw[2+l:]
	}
	if len(raw) != 0 {
		t.Fatalf("trailing bytes %x", raw)
	}
	return out
}

func TestObservedRequestIsAvailableAndHeld(t *testing.T) {
	s, db := newServer(t)
	// Bytes observed from the dashboard: machine id 0xce0d452f69 (LE), locale 103, 5 suggestions, "abc".
	raw := []byte{0x69, 0x2f, 0x45, 0x0d, 0xce, 0, 0, 0, 0x67, 0x05, 0x00, 0x03, 0x00, 'a', 'b', 'c'}
	got := do(t, s, infoA, "POST", "/xuacs/reservename.ashx", "xon/5", raw)
	want := "HTTP/1.0 200 OK\r\nX-Err: 0\r\nContent-Type: application/octet-stream\r\nContent-Length: 2\r\n\r\n\x00\x00"
	if got != want {
		t.Fatalf("got %q", got)
	}
	r, err := db.GetReservation(context.Background(), "acct1")
	if err != nil || r.Gamertag != "abc" || r.MachineID != machineA {
		t.Fatalf("hold = %+v %v", r, err)
	}
}

func TestTakenReturnsRealFreeAlternatives(t *testing.T) {
	s, db := newServer(t)
	ctx := context.Background()
	if _, err := db.ReserveName(ctx, machineB, "acct2", "Master Chief", time.Minute, false); err != nil {
		t.Fatal(err)
	}
	resp := do(t, s, infoA, "POST", "/xuacs/reservename.ashx", "xon/5", body(0xce0d452f69, 103, 5, "master chief"))
	if !strings.HasPrefix(resp, "HTTP/1.0 200 OK\r\nX-Err: 0\r\n") {
		t.Fatalf("resp %q", resp)
	}
	alts := names(t, resp)
	if len(alts) != 5 {
		t.Fatalf("alternatives %v", alts)
	}
	for _, a := range alts {
		if !ValidName(a) || strings.EqualFold(a, "master chief") {
			t.Fatalf("bad alternative %q", a)
		}
		if free, _ := db.NameAvailable(ctx, a, "acct1"); !free {
			t.Fatalf("alternative %q not free", a)
		}
	}
	if _, err := db.GetReservation(ctx, "acct1"); err == nil {
		t.Fatal("a taken name must not create a hold")
	}
}

func TestTakenWithoutSuggestionBudgetIsExplicitError(t *testing.T) {
	s, db := newServer(t)
	if _, err := db.ReserveName(context.Background(), machineB, "acct2", "Taken", time.Minute, false); err != nil {
		t.Fatal(err)
	}
	resp := do(t, s, infoA, "POST", "/xuacs/reservename.ashx", "xon/5", body(0xce0d452f69, 103, 0, "Taken"))
	if !strings.HasPrefix(resp, "HTTP/1.0 200 OK\r\nX-Err: 80154000\r\n") || !strings.HasSuffix(resp, "\r\n\r\n") {
		t.Fatalf("resp %q", resp)
	}
}

func TestCommittedAliasAndOwnHold(t *testing.T) {
	s, db := newServer(t)
	ctx := context.Background()
	p := store.Provision{ID: "p1", CoreAccountID: "acct2", MachineID: machineB, XUID: "0009aaaaaaaaaaaa", LinkID: "l1", Gamertag: "RealPlayer", ProofMAC: []byte{1}, ProofSealed: []byte{2}}
	if err := db.CommitProvision(ctx, p); err != nil {
		t.Fatal(err)
	}
	resp := do(t, s, infoA, "POST", "/xuacs/reservename.ashx", "xon/5", body(0xce0d452f69, 103, 5, "REALPLAYER"))
	if len(names(t, resp)) == 0 {
		t.Fatalf("committed alias must be taken: %q", resp)
	}
	// Re-reserving the same name from the same account is fine, and replaces its hold.
	do(t, s, infoA, "POST", "/xuacs/reservename.ashx", "xon/5", body(0xce0d452f69, 103, 5, "First One"))
	resp = do(t, s, infoA, "POST", "/xuacs/reservename.ashx", "xon/5", body(0xce0d452f69, 103, 5, "First One"))
	if len(names(t, resp)) != 0 {
		t.Fatalf("own hold must stay available: %q", resp)
	}
	do(t, s, infoA, "POST", "/xuacs/reservename.ashx", "xon/5", body(0xce0d452f69, 103, 5, "Second One"))
	if r, _ := db.GetReservation(ctx, "acct1"); r.Gamertag != "Second One" {
		t.Fatalf("hold = %+v", r)
	}
	if free, _ := db.NameAvailable(ctx, "First One", "acct3"); !free {
		t.Fatal("replaced hold must be released")
	}
}

func TestHoldExpires(t *testing.T) {
	_, db := newServer(t)
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	db.SetClock(func() time.Time { return now })
	if _, err := db.ReserveName(ctx, machineB, "acct2", "Brief", time.Minute, false); err != nil {
		t.Fatal(err)
	}
	if free, _ := db.NameAvailable(ctx, "brief", "acct1"); free {
		t.Fatal("held name must be unavailable")
	}
	now = now.Add(2 * time.Minute)
	if free, _ := db.NameAvailable(ctx, "brief", "acct1"); !free {
		t.Fatal("expired hold must free the name")
	}
}

func TestInvalidNames(t *testing.T) {
	s, _ := newServer(t)
	for _, n := range []string{"1abc", "", "a b c d e f g h i", "Sixteen Chars Ok", "ab!", "a  b", " abc", "abc ", "café", "_x"} {
		resp := do(t, s, infoA, "POST", "/xuacs/reservename.ashx", "xon/5", body(0xce0d452f69, 103, 5, n))
		if !strings.HasPrefix(resp, "HTTP/1.0 200 OK\r\nX-Err: 80154002\r\n") {
			t.Errorf("%q: %q", n, resp)
		}
	}
	for _, n := range []string{"A", "abc", "Player One", "Fifteen Chars 1", "x1"} {
		if !ValidName(n) {
			t.Errorf("%q should be valid", n)
		}
	}
}

func TestRequestRejections(t *testing.T) {
	s, _ := newServer(t)
	good := body(0xce0d452f69, 103, 5, "abc")
	cases := []struct {
		name, method, path, ctype string
		info                      xbfeature.Info
		body                      []byte
		line                      string
	}{
		{"machine mismatch", "POST", "/xuacs/reservename.ashx", "xon/5", infoA, body(0x1234, 103, 5, "abc"), "HTTP/1.0 400"},
		{"zero machine", "POST", "/xuacs/reservename.ashx", "xon/5", infoA, body(0, 103, 5, "abc"), "HTTP/1.0 400"},
		{"short", "POST", "/xuacs/reservename.ashx", "xon/5", infoA, good[:10], "HTTP/1.0 400"},
		{"length lies", "POST", "/xuacs/reservename.ashx", "xon/5", infoA, append(append([]byte{}, good...), 'x'), "HTTP/1.0 400"},
		{"wrong content type", "POST", "/xuacs/reservename.ashx", "xon/b", infoA, good, "HTTP/1.0 400"},
		{"get", "GET", "/xuacs/reservename.ashx", "xon/5", infoA, nil, "HTTP/1.0 405"},
		{"not a device session", "POST", "/xuacs/reservename.ashx", "xon/5", xbfeature.Info{PrincipalID: "0009d941ad372efd", CoreAccountID: "a", XUID: 1}, good, "HTTP/1.0 403"},
		{"no account", "POST", "/xuacs/reservename.ashx", "xon/5", xbfeature.Info{PrincipalID: machineA, XUID: 1}, good, "HTTP/1.0 403"},
		{"not implemented", "POST", "/xuacs/createowneracct.ashx", "xon/5", infoA, good, "HTTP/1.0 501"},
		{"unknown path", "POST", "/other", "xon/5", infoA, good, "HTTP/1.0 404"},
	}
	for _, c := range cases {
		got := do(t, s, c.info, c.method, c.path, c.ctype, c.body)
		if !strings.HasPrefix(got, c.line) || strings.Contains(got, "X-Err") {
			t.Errorf("%s: %q", c.name, got)
		}
	}
}

func TestRateLimit(t *testing.T) {
	s, _ := newServer(t)
	now := time.Unix(1_800_000_000, 0)
	s.Now = func() time.Time { return now }
	req := body(0xce0d452f69, 103, 5, "abc")
	for i := 0; i < burst; i++ {
		if got := do(t, s, infoA, "POST", "/xuacs/reservename.ashx", "xon/5", req); !strings.HasPrefix(got, "HTTP/1.0 200") {
			t.Fatalf("request %d: %q", i, got)
		}
	}
	if got := do(t, s, infoA, "POST", "/xuacs/reservename.ashx", "xon/5", req); !strings.HasPrefix(got, "HTTP/1.0 429") {
		t.Fatalf("over budget: %q", got)
	}
	now = now.Add(10 * time.Second)
	if got := do(t, s, infoA, "POST", "/xuacs/reservename.ashx", "xon/5", req); !strings.HasPrefix(got, "HTTP/1.0 200") {
		t.Fatalf("after refill: %q", got)
	}
}

func TestAllowOwnerIsExplicit(t *testing.T) {
	s, db := newServer(t)
	p := store.Provision{ID: "p1", CoreAccountID: "acct1", MachineID: machineA, XUID: "0009aaaaaaaaaaaa", LinkID: "l1", Gamertag: "Owner", ProofMAC: []byte{1}, ProofSealed: []byte{2}}
	if err := db.CommitProvision(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	s.AllowOwner = true
	got := do(t, s, infoA, "POST", "/xuacs/reservename.ashx", "xon/5", body(0xce0d452f69, 103, 5, "Another"))
	if !strings.HasPrefix(got, "HTTP/1.0 200 OK\r\nX-Err: 0\r\n") || len(names(t, got)) != 0 {
		t.Fatalf("%q", got)
	}
}

func TestAccountWithUserIsRefused(t *testing.T) {
	s, db := newServer(t)
	p := store.Provision{ID: "p1", CoreAccountID: "acct1", MachineID: machineA, XUID: "0009aaaaaaaaaaaa", LinkID: "l1", Gamertag: "Owner", ProofMAC: []byte{1}, ProofSealed: []byte{2}}
	if err := db.CommitProvision(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	got := do(t, s, infoA, "POST", "/xuacs/reservename.ashx", "xon/5", body(0xce0d452f69, 103, 5, "Another"))
	if !strings.HasPrefix(got, "HTTP/1.0 200 OK\r\nX-Err: 8015400a\r\n") {
		t.Fatalf("%q", got)
	}
}
