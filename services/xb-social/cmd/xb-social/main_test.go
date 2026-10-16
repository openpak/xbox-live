// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"openpak/xb-live/services/xb-social/internal/friends"
)

func TestOnlyGatewayMayReadFriends(t *testing.T) {
	h := Handler(&friends.Service{})
	for uri, want := range map[string]int{"spiffe://openpak/xb-auth": 403, "spiffe://openpak/xb-account": 403, "": 403} {
		r := httptest.NewRequest("GET", "/internal/v1/friends?viewer=0009000000000001", nil)
		if uri != "" {
			u, _ := url.Parse(uri)
			r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{}}, PeerCertificates: []*x509.Certificate{{URIs: []*url.URL{u}}}}
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("%q: %d", uri, w.Code)
		}
	}
	_ = http.StatusOK
}
