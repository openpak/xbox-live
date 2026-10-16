// SPDX-License-Identifier: AGPL-3.0-only

// Package testkit exposes the xb-enroll handler to test/e2e (which sits
// outside this service's internal/ tree). Test support only.
package testkit

import (
	"net/http"

	"openpak/xb-live/internal/xbenrolapi"
	"openpak/xb-live/services/xb-enroll/internal/server"
)

// Handler is the public xb-enroll handler talking to xb-account at base over
// httpc, which must carry the spiffe://openpak/xb-enroll client identity.
func Handler(base string, httpc *http.Client) http.Handler {
	return server.New(server.Config{Backend: &xbenrolapi.Client{Base: base, HTTP: httpc}}).Handler()
}
