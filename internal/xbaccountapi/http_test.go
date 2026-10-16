// SPDX-License-Identifier: AGPL-3.0-only

package xbaccountapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

const (
	xuid = "0009000000000001"
	mach = "00aa00bb00cc00dd"
)

type fake struct {
	mu   sync.Mutex
	revs []Revocation
}

func (f *fake) ResolveUser(_ context.Context, id string) (Principal, error) {
	switch id {
	case xuid:
		return Principal{KindUser, id, "acct", StatusActive}, nil
	case "0009000000000002":
		return Principal{}, &DeniedError{Principal{KindUser, id, "acct", StatusBanned}}
	case "0009000000000003":
		return Principal{}, ErrNotFound
	}
	return Principal{}, ErrUnavailable
}
func (f *fake) ResolveGamertag(ctx context.Context, tag string) (Principal, error) {
	switch tag {
	case "Player One":
		return f.ResolveUser(ctx, xuid)
	case "Banned One":
		return f.ResolveUser(ctx, "0009000000000002")
	case "Nobody":
		return Principal{}, ErrNotFound
	}
	return Principal{}, ErrUnavailable
}
func (f *fake) ResolveDevice(_ context.Context, id string) (Principal, error) {
	if id == mach {
		return Principal{KindDevice, id, "acct", StatusActive}, nil
	}
	return Principal{}, &DeniedError{Principal{KindDevice, id, "acct", StatusUnlinked}}
}
func (f *fake) Poll(_ context.Context, after uint64, limit int, _ time.Duration) ([]Revocation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Revocation
	for _, r := range f.revs {
		if r.Seq > after && len(out) < limit {
			out = append(out, r)
		}
	}
	return out, nil
}

func newClient(t *testing.T, f *fake, wrap func(http.Handler) http.Handler) *Client {
	t.Helper()
	var h http.Handler = Handler(f, f)
	if wrap != nil {
		h = wrap(h)
	}
	s := httptest.NewTLSServer(h)
	t.Cleanup(s.Close)
	return &Client{Base: s.URL, HTTP: s.Client()}
}

func TestResolveContract(t *testing.T) {
	c := newClient(t, &fake{}, nil)
	ctx := context.Background()
	p, err := c.ResolveUser(ctx, xuid)
	if err != nil || p.Status != StatusActive || p.Kind != KindUser {
		t.Fatalf("%+v %v", p, err)
	}
	_, err = c.ResolveUser(ctx, "0009000000000002")
	var d *DeniedError
	if !errors.As(err, &d) || !errors.Is(err, ErrDenied) || d.Principal.Status != StatusBanned {
		t.Fatalf("denied: %v", err)
	}
	if _, err := c.ResolveUser(ctx, "0009000000000003"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("%v", err)
	}
	if _, err := c.ResolveUser(ctx, "0009000000000004"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("%v", err)
	}
	if _, err := c.ResolveUser(ctx, "bad"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("%v", err)
	}
	if p, err := c.ResolveDevice(ctx, mach); err != nil || p.Kind != KindDevice {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := c.ResolveDevice(ctx, "1111111111111111"); !errors.Is(err, ErrDenied) {
		t.Fatalf("%v", err)
	}
}

func TestResolveGamertagContract(t *testing.T) {
	c := newClient(t, &fake{}, nil)
	ctx := context.Background()
	p, err := c.ResolveGamertag(ctx, "Player One") // space must survive path escaping
	if err != nil || p.PrincipalID != xuid || p.Kind != KindUser {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := c.ResolveGamertag(ctx, "Banned One"); !errors.Is(err, ErrDenied) {
		t.Fatalf("%v", err)
	}
	if _, err := c.ResolveGamertag(ctx, "Nobody"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("%v", err)
	}
	for _, bad := range []string{"", "a/b", " lead", "sixteen chars!!!", "x<y"} {
		if _, err := c.ResolveGamertag(ctx, bad); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
}

func TestClientNeverTreatsGarbageAsSuccess(t *testing.T) {
	for name, body := range map[string]string{
		"wrong id":     `{"kind":"user","principal_id":"0009000000000009","core_account_id":"a","status":"active"}`,
		"wrong kind":   `{"kind":"device","principal_id":"` + xuid + `","core_account_id":"a","status":"active"}`,
		"not active":   `{"kind":"user","principal_id":"` + xuid + `","core_account_id":"a","status":"banned"}`,
		"no account":   `{"kind":"user","principal_id":"` + xuid + `","core_account_id":"","status":"active"}`,
		"not json":     `ok`,
		"empty object": `{}`,
	} {
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		c := &Client{Base: s.URL, HTTP: s.Client()}
		if _, err := c.ResolveUser(context.Background(), xuid); err == nil {
			t.Errorf("%s admitted", name)
		}
		s.Close()
	}
	// Server down: deny.
	c := &Client{Base: "https://127.0.0.1:1", HTTP: &http.Client{Timeout: time.Second}}
	if _, err := c.ResolveDevice(context.Background(), mach); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("%v", err)
	}
}

func TestRevocationCursor(t *testing.T) {
	f := &fake{revs: []Revocation{{Seq: 1, EventID: "a", Scope: ScopeAccount, CoreAccountID: "x", Reason: StatusBanned}, {Seq: 2, EventID: "b", Scope: ScopeUser, PrincipalID: xuid, CoreAccountID: "x", Reason: StatusUnlinked}}}
	c := newClient(t, f, nil)
	ctx := context.Background()
	got, err := c.Poll(ctx, 0, 10, 0)
	if err != nil || len(got) != 2 || got[1].PrincipalID != xuid {
		t.Fatalf("%+v %v", got, err)
	}
	got, err = c.Poll(ctx, 1, 10, 0)
	if err != nil || len(got) != 1 || got[0].Seq != 2 {
		t.Fatalf("%+v %v", got, err)
	}
	if got, err = c.Poll(ctx, 2, 10, 0); err != nil || len(got) != 0 {
		t.Fatalf("%+v %v", got, err)
	}
	// A server replaying entries behind the cursor is rejected.
	f.revs = []Revocation{{Seq: 1}, {Seq: 1}}
	if _, err := c.Poll(ctx, 0, 10, 0); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("non-monotonic accepted: %v", err)
	}
	if _, err := c.Poll(ctx, 5, 10, 0); err != nil && !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}

func TestHandlerRejectsBadQuery(t *testing.T) {
	s := httptest.NewServer(Handler(&fake{}, &fake{}))
	defer s.Close()
	for _, q := range []string{"", "?after=x&limit=1", "?after=0&limit=0", "?after=0&limit=5&wait=-1"} {
		resp, err := http.Get(s.URL + "/internal/v1/revocations" + q)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Errorf("%q: %d", q, resp.StatusCode)
		}
	}
}

func TestValidID(t *testing.T) {
	for id, want := range map[string]bool{xuid: true, "0000000000000000": false, "0009000000000A01": false, "short": false, "000900000000000g": false} {
		if ValidID(id) != want {
			t.Errorf("%q", id)
		}
	}
}
