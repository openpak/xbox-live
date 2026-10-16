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
	h := Handler(nil, nil, nil) // authorization must reject before any backend is touched
	for _, tc := range []tcase{
		{"GET", "/internal/v1/users/0009000000000001", "", "spiffe://openpak/xb-provisioner", true, 403},
		{"GET", "/internal/v1/devices/00aa00bb00cc00dd", "", "spiffe://openpak/x360-auth", true, 403},
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
	h := Handler(nil, nil, nil)
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
