// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"openpak/xb-live/internal/xbenrolapi"
)

const (
	goodKey = "0102030405060708090a0b0c0d0e0f10"
	goodID  = "0000001cbe991a14"
)

type fake struct {
	enrolErr, pollErr error
	got               []xbenrolapi.EnrolRequest
	status            string
}

func (f *fake) Enrol(_ context.Context, r xbenrolapi.EnrolRequest) (xbenrolapi.EnrolResponse, error) {
	f.got = append(f.got, r)
	if f.enrolErr != nil {
		return xbenrolapi.EnrolResponse{}, f.enrolErr
	}
	return xbenrolapi.EnrolResponse{PairingCode: "ABCD2345", PollToken: strings.Repeat("t", 43), ExpiresUnix: 1_800_000_600}, nil
}

func (f *fake) Poll(_ context.Context, tok string) (xbenrolapi.PollResponse, error) {
	if f.pollErr != nil {
		return xbenrolapi.PollResponse{}, f.pollErr
	}
	return xbenrolapi.PollResponse{Status: f.status, ExpiresUnix: 1_800_000_600}, nil
}

func do(h http.Handler, method, path, body, remote string, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = remote
	if method == "POST" {
		r.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func body(id, key string) string {
	return `{"machineID":"` + id + `","machineKey":"` + key + `","clientInfo":"tool 1.0"}`
}

func TestEnrolAndPoll(t *testing.T) {
	f := &fake{status: "pending"}
	h := New(Config{Backend: f}).Handler()
	w := do(h, "POST", "/v1/enrol", body("123456789012", strings.ToUpper(goodKey)), "198.51.100.7:1000")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"pairingCode":"ABCD2345"`) || !strings.Contains(w.Body.String(), `"expiresAt":"2027-01-15T08:10:00Z"`) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), goodKey) || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("response leaks the key or is cacheable")
	}
	if len(f.got) != 1 || f.got[0].MachineID != goodID || f.got[0].MachineKey != goodKey {
		t.Fatalf("backend saw %+v (serial must become the 16-hex machine ID, key lowercase)", f.got)
	}
	w = do(h, "GET", "/v1/enrol/"+strings.Repeat("t", 43), "", "198.51.100.7:1000")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"pending"`) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	f.status = "weird"
	if w := do(h, "GET", "/v1/enrol/"+strings.Repeat("t", 43), "", "198.51.100.7:1000"); w.Code != 502 {
		t.Fatalf("unknown backend status passed through: %d", w.Code)
	}
}

func TestRejectsBadInput(t *testing.T) {
	f := &fake{}
	h := New(Config{Backend: f}).Handler()
	for _, b := range []string{
		"", "nope", `{"machineID":"` + goodID + `"}`, body(goodID, "zz"), body(goodID, strings.Repeat("0", 32)), body(goodID, strings.Repeat("f", 32)),
		body("0009000000000001", goodKey), body("12345678901", goodKey), body(goodID, goodKey+"00"),
		`{"machineID":"` + goodID + `","machineKey":"` + goodKey + `","extra":1}`,
		body(goodID, goodKey) + body(goodID, goodKey),
		`{"machineID":"` + goodID + `","machineKey":"` + goodKey + `","clientInfo":"` + strings.Repeat("a", 3000) + `"}`,
		`{"machineID":"` + goodID + `","machineKey":"` + goodKey + `","clientInfo":"bad\u0000"}`,
	} {
		w := do(h, "POST", "/v1/enrol", b, "198.51.100.7:1")
		if w.Code != 400 {
			t.Errorf("%.50q: %d", b, w.Code)
		}
		h = New(Config{Backend: f}).Handler() // fresh limits per case
	}
	if len(f.got) != 0 {
		t.Fatal("invalid input reached xb-account")
	}
	if w := do(h, "POST", "/v1/enrol", body(goodID, goodKey), "198.51.100.7:1", "Content-Type", "text/plain"); w.Code != 415 {
		t.Fatalf("content type: %d", w.Code)
	}
	for _, tok := range []string{"short", strings.Repeat("a", 200), "ab/cd" + strings.Repeat("a", 20), strings.Repeat("a", 20) + "%00"} {
		if w := do(h, "GET", "/v1/enrol/"+tok, "", "198.51.100.7:1"); w.Code != 404 && w.Code != 301 {
			t.Errorf("token %.20q: %d", tok, w.Code)
		}
	}
	// Only the two routes exist.
	for _, c := range [][2]string{{"GET", "/v1/enrol"}, {"POST", "/v1/enrol/abc"}, {"GET", "/internal/v1/enrolments"}, {"POST", "/v1/approve"}, {"GET", "/"}} {
		if w := do(h, c[0], c[1], "", "198.51.100.7:1"); w.Code != 404 && w.Code != 405 {
			t.Errorf("%v: %d", c, w.Code)
		}
	}
}

func TestRateLimits(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { return now }
	f := &fake{}
	h := New(Config{Backend: f, Now: clock}).Handler()
	// Per IP: 10 per hour regardless of machine.
	for i := 0; i < 10; i++ {
		id := "00000000000000" + string(rune('1'+i/10)) + string(rune('0'+i%10))
		if w := do(h, "POST", "/v1/enrol", body(id, goodKey), "198.51.100.7:1"); w.Code != 200 {
			t.Fatalf("request %d: %d %s", i, w.Code, w.Body.String())
		}
	}
	w := do(h, "POST", "/v1/enrol", body(goodID, goodKey), "198.51.100.7:2")
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("ip limit: %d", w.Code)
	}
	if w := do(h, "POST", "/v1/enrol", body(goodID, goodKey), "198.51.100.8:2"); w.Code != 200 {
		t.Fatalf("other ip: %d", w.Code)
	}
	now = now.Add(61 * time.Minute)
	if w := do(h, "POST", "/v1/enrol", body(goodID, goodKey), "198.51.100.7:2"); w.Code != 200 {
		t.Fatalf("after window: %d", w.Code)
	}
	// Per machine: 6 per 10 minutes across many IPs.
	h = New(Config{Backend: f, Now: clock}).Handler()
	var last int
	for i := 0; i < 8; i++ {
		last = do(h, "POST", "/v1/enrol", body(goodID, goodKey), "203.0.113."+string(rune('1'+i))+":1").Code
	}
	if last != 429 {
		t.Fatalf("machine limit: %d", last)
	}
	// Poll limit.
	h = New(Config{Backend: f, Now: clock}).Handler()
	f.status = "pending"
	for i := 0; i < 120; i++ {
		do(h, "GET", "/v1/enrol/"+strings.Repeat("t", 43), "", "198.51.100.9:1")
	}
	if w := do(h, "GET", "/v1/enrol/"+strings.Repeat("t", 43), "", "198.51.100.9:1"); w.Code != 429 {
		t.Fatalf("poll limit: %d", w.Code)
	}
}

func TestBackendErrorsAreClosedSet(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
		code string
	}{
		{&xbenrolapi.Error{Status: 409, Code: xbenrolapi.CodeMachineActive}, 409, "machine_already_enrolled"},
		{&xbenrolapi.Error{Status: 429, Code: xbenrolapi.CodeRateLimited}, 429, "rate_limited"},
		{&xbenrolapi.Error{Status: 404, Code: xbenrolapi.CodeNotFound}, 404, "not_found"},
		{&xbenrolapi.Error{Status: 403, Code: xbenrolapi.CodeNotEligible}, 503, "unavailable"}, // never forwarded
		{&xbenrolapi.Error{Status: 500, Code: "stack trace here"}, 503, "unavailable"},
		{xbenrolapi.ErrUnavailable, 503, "unavailable"},
	} {
		f := &fake{enrolErr: tc.err}
		w := do(New(Config{Backend: f}).Handler(), "POST", "/v1/enrol", body(goodID, goodKey), "198.51.100.7:1")
		if w.Code != tc.want || !strings.Contains(w.Body.String(), `"`+tc.code+`"`) {
			t.Errorf("%v: %d %s", tc.err, w.Code, w.Body.String())
		}
	}
}

func TestClientIP(t *testing.T) {
	s := New(Config{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})
	for _, tc := range []struct{ remote, xff, want string }{
		{"198.51.100.7:1", "1.2.3.4", "198.51.100.7"},          // untrusted peer: header ignored
		{"10.1.1.1:1", "203.0.113.9", "203.0.113.9"},           // trusted proxy
		{"10.1.1.1:1", "6.6.6.6, 203.0.113.9", "203.0.113.9"},  // client-supplied prefix ignored
		{"10.1.1.1:1", "203.0.113.9, 10.2.2.2", "203.0.113.9"}, // chained proxies
		{"10.1.1.1:1", "garbage", "10.1.1.1"},
		{"10.1.1.1:1", "", "10.1.1.1"},
		{"10.1.1.1:1", "2001:db8:1:2:3:4:5:6", "2001:db8:1:2::"}, // IPv6 collapsed to /64
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.remote
		if tc.xff != "" {
			r.Header.Set("X-Forwarded-For", tc.xff)
		}
		if got := s.ClientIP(r); got != tc.want {
			t.Errorf("%v: got %s", tc, got)
		}
	}
}
