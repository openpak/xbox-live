// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"openpak/xb-live/services/xb-account/internal/enrol"
	"openpak/xb-live/services/xb-account/internal/voucher"
)

func request(method, path, body, uri string, verified bool) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if uri != "" {
		u, _ := url.Parse(uri)
		st := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{URIs: []*url.URL{u}}}}
		if verified {
			st.VerifiedChains = [][]*x509.Certificate{{}}
		}
		r.TLS = st
	}
	return r
}

func TestRoutesAuthorizePerCaller(t *testing.T) {
	h := Handler(nil, nil, nil, nil) // authorization must reject before any backend is touched
	for _, tc := range []tcase{
		{"GET", "/internal/v1/users/0009000000000001", "", "spiffe://openpak/xb-provisioner", true, 403},
		{"GET", "/internal/v1/devices/00aa00bb00cc00dd", "", "spiffe://openpak/x360-auth", true, 403},
		{"GET", "/internal/v1/devices/0000001cbe991a14/key", "", "spiffe://openpak/xb-gateway", true, 403}, // keys: xb-auth only
		{"GET", "/internal/v1/devices/0000001cbe991a14/key", "", "spiffe://openpak/xb-provisioner", true, 403},
		{"GET", "/internal/v1/revocations?after=0&limit=1", "", "spiffe://openpak/xb-social", true, 403},
		{"GET", "/internal/v1/revocations?after=0&limit=1", "", "spiffe://openpak/xb-gateway", false, 403}, // unverified chain
		{"GET", "/internal/v1/users/0009000000000001", "", "", false, 403},                                 // no TLS at all
		{"POST", "/internal/v1/provisions", "{}", "spiffe://openpak/xb-auth", true, 403},                   // only the web approval side begins
		{"POST", "/internal/v1/provisions", "{}", "spiffe://openpak/xb-gateway", true, 403},
		{"POST", "/internal/v1/provisions/finalize", "{}", "spiffe://openpak/xb-gateway", true, 403},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(tc.method, tc.path, tc.body, tc.uri, tc.verified))
		if w.Code != tc.want {
			t.Errorf("%s %s as %q: %d want %d", tc.method, tc.path, tc.uri, w.Code, tc.want)
		}
	}
}

type tcase struct {
	method, path string
	body, uri    string
	verified     bool
	want         int
}

func TestMalformedProvisioningBodies(t *testing.T) {
	h := Handler(nil, nil, nil, nil)
	for _, body := range []string{"", "not json", `{"unknown":1}`, `{"core_account_id":"a"} {}`} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request("POST", "/internal/v1/provisions", body, Provisioner, true))
		if w.Code != 400 {
			t.Errorf("%q: %d", body, w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request("POST", "/internal/v1/provisions/finalize", `{"proof":"!!!"}`, Auth, true))
	if w.Code != 400 {
		t.Errorf("bad base64: %d", w.Code)
	}
}

func TestEnrolmentRoutesAuthorizePerCaller(t *testing.T) {
	h := HandlerFull(nil, nil, nil, nil, &enrol.Service{}, &voucher.Service{})
	for _, tc := range []tcase{
		// The public front reaches only its two routes.
		{"POST", "/internal/v1/enrolments/approve", "{}", Enroll, true, 403},
		{"POST", "/internal/v1/enrolments/preview", "{}", Enroll, true, 403},
		{"POST", "/internal/v1/vouchers", "{}", Enroll, true, 403},
		{"POST", "/internal/v1/accounts/xbox", "{}", Enroll, true, 403},
		{"POST", "/internal/v1/provisions", "{}", Enroll, true, 403},
		{"GET", "/internal/v1/devices/0000001cbe991a14/key", "", Enroll, true, 403},
		{"GET", "/internal/v1/users/0009000000000001", "", Enroll, true, 403},
		{"GET", "/internal/v1/revocations?after=0", "", Enroll, true, 403},
		// The web side cannot register enrolments or poll as a console.
		{"POST", "/internal/v1/enrolments", "{}", Provisioner, true, 403},
		{"POST", "/internal/v1/enrolments/poll", "{}", Provisioner, true, 403},
		{"POST", "/internal/v1/enrolments/approve", "{}", Auth, true, 403},
		{"POST", "/internal/v1/enrolments/approve", "{}", Gateway, true, 403},
		{"POST", "/internal/v1/vouchers", "{}", Gateway, true, 403},
		{"POST", "/internal/v1/enrolments/approve", "{}", Provisioner, false, 403}, // unverified chain
		{"POST", "/internal/v1/enrolments", "{}", "", false, 403},                  // no TLS
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(tc.method, tc.path, tc.body, tc.uri, tc.verified))
		if w.Code != tc.want {
			t.Errorf("%s %s as %q: %d want %d", tc.method, tc.path, tc.uri, w.Code, tc.want)
		}
	}
}

func TestEnrolmentMalformedBodies(t *testing.T) {
	h := HandlerFull(nil, nil, nil, nil, &enrol.Service{}, &voucher.Service{})
	big := `{"machine_id":"` + strings.Repeat("a", 5000) + `"}`
	for _, body := range []string{"", "x", `{"unknown":1}`, `{"machine_id":"0000001cbe991a14","machine_key":"00000000000000000000000000000000"}`,
		`{"machine_id":"0000001cbe991a14","machine_key":"zz"}`, `{"machine_id":"0009000000000001","machine_key":"0102030405060708090a0b0c0d0e0f10"}`,
		`{} {}`, big} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request("POST", "/internal/v1/enrolments", body, Enroll, true))
		if w.Code != 400 || !strings.Contains(w.Body.String(), `"error":"invalid_request"`) {
			t.Errorf("%.40q: %d %s", body, w.Code, w.Body.String())
		}
	}
}
