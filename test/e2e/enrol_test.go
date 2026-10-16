// SPDX-License-Identifier: AGPL-3.0-only

package e2e

// Device-pairing enrolment end to end: the console tool talks to the real
// xb-enroll handler (public HTTP), which calls xb-account over mutual TLS
// (fake account core); the website side approves with the xb-provisioner
// identity. The new device must then pass MACS in xb-auth, and after the
// dashboard signup (subscription code) the full native sign-in chain.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"openpak/xb-live/internal/krb"
	"openpak/xb-live/internal/xbcrypto"
	account "openpak/xb-live/services/xb-account/testkit"
	enroll "openpak/xb-live/services/xb-enroll/testkit"
)

// enrolWorld adds the public xb-enroll front (serving real HTTP) to a world.
type enrolWorld struct {
	*world
	pub *httptest.Server
}

func newEnrolWorld(t *testing.T) *enrolWorld {
	t.Helper()
	w := newWorld(t)
	pub := httptest.NewServer(enroll.Handler(w.base, w.p.client(t, account.Enroll)))
	t.Cleanup(pub.Close)
	w.acct.AddActiveAccount("core-account-2")
	return &enrolWorld{w, pub}
}

func (e *enrolWorld) call(method, url string, in any, out any) int {
	e.t.Helper()
	var rd io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, url, rd)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode == 200 {
		if err := json.Unmarshal(data, out); err != nil {
			e.t.Fatalf("%s: %v", data, err)
		}
	}
	if bytes.Contains(data, []byte(hex.EncodeToString(func() []byte { k := consoleKey(); return k[:] }()))) {
		e.t.Fatal("machine key echoed in a response")
	}
	return resp.StatusCode
}

type enrolled struct {
	PairingCode string `json:"pairingCode"`
	PollToken   string `json:"pollToken"`
	ExpiresAt   string `json:"expiresAt"`
}

// register is the console tool: POST /v1/enrol with the EEPROM serial and key.
func (e *enrolWorld) register(serialOrID string) (int, enrolled) {
	k := consoleKey()
	var out enrolled
	code := e.call("POST", e.pub.URL+"/v1/enrol", map[string]string{"machineID": serialOrID,
		"machineKey": hex.EncodeToString(k[:]), "clientInfo": "e2e tool"}, &out)
	return code, out
}

func (e *enrolWorld) pollStatus(token string) string {
	var out struct{ Status string }
	if code := e.call("GET", e.pub.URL+"/v1/enrol/"+token, nil, &out); code != 200 {
		return "http-" + http.StatusText(code)
	}
	return out.Status
}

// web is the website side (xb-provisioner identity; 2FA happened upstream).
func (e *enrolWorld) web(path, acct, code string) (int, string) {
	st, body := e.post(e.prov, "/internal/v1/enrolments/"+path, map[string]string{"core_account_id": acct, "pairing_code": code})
	return st, string(body)
}

func TestEnrolApproveThenMACSAndSignup(t *testing.T) {
	e := newEnrolWorld(t)
	code, r := e.register(serial) // the 12-digit serial form is accepted
	if code != 200 || len(r.PairingCode) != 8 {
		t.Fatalf("enrol %d %+v", code, r)
	}
	if _, errc := e.macs(consoleKey()); errc != krb.ErrCPrincipalUnknown {
		t.Fatalf("MACS before approval must fail as unknown principal: %d", errc)
	}
	if s := e.pollStatus(r.PollToken); s != "pending" {
		t.Fatalf("poll %q", s)
	}
	st, body := e.web("preview", coreAcct, strings.ToLower(r.PairingCode))
	if st != 200 || !strings.Contains(body, `"machine_id_suffix":"1a14"`) || strings.Contains(body, machineID) {
		t.Fatalf("preview %d %s", st, body)
	}
	if st, body := e.web("approve", coreAcct, r.PairingCode); st != 200 || !strings.Contains(body, `"approved"`) {
		t.Fatalf("approve %d %s", st, body)
	}
	if s := e.pollStatus(r.PollToken); s != "approved" {
		t.Fatalf("poll after approve %q", s)
	}
	// The enrolled device authenticates against xb-auth (device linked, no gamertag yet).
	blob, errc := e.macs(consoleKey())
	if errc != 0 || len(blob) == 0 {
		t.Fatalf("MACS after approval: %d", errc)
	}
	if _, errc := e.macs(xbcrypto.Key{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9}); errc != krb.ErrPreauthFailed {
		t.Fatalf("MACS with another machine key: %d", errc)
	}
	// Dashboard signup: subscription code issued by the website, consumed once.
	st, bb := e.post(e.prov, "/internal/v1/vouchers", map[string]string{"core_account_id": coreAcct, "machine_id": machineID})
	body = string(bb)
	var v struct {
		Code string `json:"code"`
	}
	json.Unmarshal([]byte(body), &v)
	if st != 200 || len(strings.ReplaceAll(v.Code, "-", "")) != 25 {
		t.Fatalf("voucher %d %s", st, body)
	}
	su, err := e.acct.Enrol.CompleteSignup(context.Background(), machineID, strings.ToLower(v.Code), gamertag)
	if err != nil {
		t.Fatalf("signup: %v", err)
	}
	s := e.fullSignIn(console{machineKey: consoleKey(), xuid: su.XUID})
	if reply, admitted := e.sgInit(s.svc, s.svcKey, gamertag); reply == nil || !admitted {
		t.Fatal("gateway did not admit the user created through enrolment + signup")
	}
	if _, err := e.acct.Enrol.CompleteSignup(context.Background(), machineID, v.Code, "Someone Else"); err == nil {
		t.Fatal("subscription code reused")
	}
}

func TestEnrolNegatives(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		e := newEnrolWorld(t)
		_, r := e.register(machineID)
		e.acct.Advance(11 * time.Minute)
		if s := e.pollStatus(r.PollToken); s != "expired" {
			t.Fatalf("poll %q", s)
		}
		if st, _ := e.web("approve", coreAcct, r.PairingCode); st != 404 {
			t.Fatalf("approve expired: %d", st)
		}
		if _, errc := e.macs(consoleKey()); errc != krb.ErrCPrincipalUnknown {
			t.Fatalf("MACS: %d", errc)
		}
	})
	t.Run("reused and wrong code", func(t *testing.T) {
		e := newEnrolWorld(t)
		_, r := e.register(machineID)
		if st, _ := e.web("approve", coreAcct, "AAAAAAAA"); st != 404 {
			t.Fatalf("wrong code: %d", st)
		}
		if st, _ := e.web("approve", coreAcct, r.PairingCode); st != 200 {
			t.Fatalf("approve: %d", st)
		}
		// Another account presenting the used code learns nothing.
		if st, body := e.web("approve", "core-account-2", r.PairingCode); st != 404 || strings.Contains(body, coreAcct) {
			t.Fatalf("reuse by another account: %d %s", st, body)
		}
		if st, _ := e.web("preview", "core-account-2", r.PairingCode); st != 404 {
			t.Fatalf("preview of a claimed code: %d", st)
		}
	})
	t.Run("already active machine ID", func(t *testing.T) {
		e := newEnrolWorld(t)
		_, r := e.register(machineID)
		e.web("approve", coreAcct, r.PairingCode)
		if code, _ := e.register(machineID); code != 409 {
			t.Fatalf("re-enrol of an active machine: %d", code)
		}
	})
	t.Run("rate limits", func(t *testing.T) {
		e := newEnrolWorld(t)
		var last int
		for i := 0; i < 8 && last != 429; i++ {
			last, _ = e.register(machineID)
		}
		if last != 429 {
			t.Fatalf("per-machine limit never hit: %d", last)
		}
		e2 := newEnrolWorld(t)
		_, r := e2.register(machineID)
		for i := 0; i < 5; i++ {
			e2.web("approve", coreAcct, "AAAAAAAA")
		}
		if st, _ := e2.web("approve", coreAcct, r.PairingCode); st != 429 {
			t.Fatalf("guess limit: %d", st)
		}
	})
	t.Run("malformed input", func(t *testing.T) {
		e := newEnrolWorld(t)
		for _, in := range []map[string]string{
			{"machineID": "0009000000000001", "machineKey": "0102030405060708090a0b0c0d0e0f10"},
			{"machineID": machineID, "machineKey": "00000000000000000000000000000000"},
			{"machineID": machineID, "machineKey": "short"},
		} {
			if code := e.call("POST", e.pub.URL+"/v1/enrol", in, nil); code != 400 {
				t.Errorf("%v: %d", in, code)
			}
		}
	})
	t.Run("front cannot reach account or approval routes", func(t *testing.T) {
		e := newEnrolWorld(t)
		front := e.p.client(t, account.Enroll)
		for _, path := range []string{"/internal/v1/enrolments/approve", "/internal/v1/vouchers", "/internal/v1/provisions"} {
			b, _ := json.Marshal(map[string]string{"core_account_id": coreAcct})
			resp, err := front.Post(e.base+path, "application/json", bytes.NewReader(b))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != 403 {
				t.Errorf("%s: %d", path, resp.StatusCode)
			}
		}
	})
	t.Run("unlinked after approval and before signup", func(t *testing.T) {
		e := newEnrolWorld(t)
		_, r := e.register(machineID)
		e.web("approve", coreAcct, r.PairingCode)
		if _, errc := e.macs(consoleKey()); errc != 0 {
			t.Fatalf("MACS: %d", errc)
		}
		// The website/core unlinks the reserved link (subject = the device's XUID).
		d := e.acct.DeviceXUID(t, machineID)
		if err := e.acct.EmitAndProcess(context.Background(), "link_unlinked", coreAcct, "xbox", d); err != nil {
			t.Fatal(err)
		}
		if _, errc := e.macs(consoleKey()); errc == 0 {
			t.Fatal("MACS succeeded after unlink")
		}
		// And the same machine can pair again afterwards.
		if code, _ := e.register(machineID); code != 200 {
			t.Fatalf("re-enrol after unlink: %d", code)
		}
	})
	t.Run("core link revoked before the event arrives", func(t *testing.T) {
		e := newEnrolWorld(t)
		_, r := e.register(machineID)
		e.web("approve", coreAcct, r.PairingCode)
		if err := e.acct.RevokeLinkInCore(context.Background(), e.acct.DeviceXUID(t, machineID)); err != nil {
			t.Fatal(err)
		}
		if _, errc := e.macs(consoleKey()); errc == 0 {
			t.Fatal("MACS succeeded with the core link gone")
		}
	})
	t.Run("ban stops an enrolled device", func(t *testing.T) {
		e := newEnrolWorld(t)
		_, r := e.register(machineID)
		e.web("approve", coreAcct, r.PairingCode)
		if err := e.acct.EmitAndProcess(context.Background(), "account_banned", coreAcct, "", ""); err != nil {
			t.Fatal(err)
		}
		if _, errc := e.macs(consoleKey()); errc == 0 {
			t.Fatal("MACS succeeded for a banned account")
		}
	})
}
