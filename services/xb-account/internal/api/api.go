// SPDX-License-Identifier: AGPL-3.0-only

// Package api is xb-account's HTTP surface beyond the legacy gamertag lookup:
// the xbaccountapi contract (resolve + revocations) and provisioning. Every
// route authorizes the mTLS peer's SPIFFE URI SAN individually.
package api

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"openpak/xb-live/internal/xbaccountapi"
	"openpak/xb-live/services/xb-account/internal/enrol"
	"openpak/xb-live/services/xb-account/internal/provision"
	"openpak/xb-live/services/xb-account/internal/voucher"
)

const (
	Auth        = "spiffe://openpak/xb-auth"
	Gateway     = "spiffe://openpak/xb-gateway"
	Provisioner = "spiffe://openpak/xb-provisioner" // web approval side
	Enroll      = "spiffe://openpak/xb-enroll"      // public device-pairing front; two routes only
)

// Peer reports whether the verified TLS peer carries one of the allowed URIs.
func Peer(s *tls.ConnectionState, allowed ...string) bool {
	if s == nil || len(s.VerifiedChains) == 0 || len(s.PeerCertificates) == 0 {
		return false
	}
	for _, u := range s.PeerCertificates[0].URIs {
		for _, a := range allowed {
			if u.String() == a {
				return true
			}
		}
	}
	return false
}

// Only restricts h to peers presenting one of the allowed SPIFFE URIs.
func Only(h http.Handler, allowed ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !Peer(r.TLS, allowed...) {
			http.Error(w, "forbidden", 403)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// Handler mounts the contract (auth, gateway) and provisioning routes.
func Handler(res xbaccountapi.Resolver, rev xbaccountapi.Revocations, keys xbaccountapi.DeviceKeys, prov *provision.Provisioner) http.Handler {
	return HandlerFull(res, rev, keys, prov, nil, nil)
}

// HandlerFull is Handler plus the device-pairing enrolment and subscription
// code routes (see enrol.go); either may be nil to leave its routes unmounted.
func HandlerFull(res xbaccountapi.Resolver, rev xbaccountapi.Revocations, keys xbaccountapi.DeviceKeys, prov *provision.Provisioner, enr *enrol.Service, vch *voucher.Service) http.Handler {
	mux := http.NewServeMux()
	if enr != nil {
		mountEnrol(mux, enr)
	}
	if vch != nil {
		mountVoucher(mux, vch)
	}
	// Device proof material goes to xb-auth only, never the gateway.
	mux.Handle("GET /internal/v1/devices/{id}/key", Only(xbaccountapi.KeyHandler(keys), Auth))
	mux.Handle("/internal/v1/users/", Only(xbaccountapi.Handler(res, rev), Auth, Gateway))
	mux.Handle("/internal/v1/gamertags/", Only(xbaccountapi.Handler(res, rev), Auth, Gateway))
	mux.Handle("/internal/v1/devices/", Only(xbaccountapi.Handler(res, rev), Auth, Gateway))
	mux.Handle("/internal/v1/revocations", Only(xbaccountapi.Handler(res, rev), Auth, Gateway))
	mux.Handle("POST /internal/v1/provisions", Only(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			CoreAccountID string `json:"core_account_id"`
			MachineID     string `json:"machine_id"`
			Challenge     string `json:"challenge"`
		}
		if !decode(w, r, &req) {
			return
		}
		token, exp, err := prov.Begin(r.Context(), provision.BeginRequest{CoreAccountID: req.CoreAccountID, MachineID: req.MachineID, Challenge: req.Challenge})
		if err != nil {
			fail(w, err)
			return
		}
		reply(w, map[string]any{"token": token, "expires_unix": exp.Unix()})
	}), Provisioner))
	mux.Handle("POST /internal/v1/provisions/finalize", Only(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Token     string `json:"token"`
			MachineID string `json:"machine_id"`
			Challenge string `json:"challenge"`
			Gamertag  string `json:"gamertag"`
			Proof     string `json:"proof"` // base64 device proof secret
		}
		if !decode(w, r, &req) {
			return
		}
		proof, err := base64.StdEncoding.DecodeString(req.Proof)
		if err != nil {
			http.Error(w, "invalid request", 400)
			return
		}
		res, err := prov.Finalize(r.Context(), provision.FinalizeRequest{Token: req.Token, MachineID: req.MachineID, Challenge: req.Challenge, Gamertag: req.Gamertag, Proof: proof})
		if err != nil {
			fail(w, err)
			return
		}
		reply(w, map[string]string{"xuid": res.XUID, "gamertag": res.Gamertag, "machine_id": res.MachineID, "core_account_id": res.CoreAccountID})
	}), Auth, Provisioner))
	return mux
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		http.Error(w, "invalid request", 400)
		return false
	}
	return true
}

func reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, err error) {
	// Messages are generic: token validity and account state are not an oracle.
	switch {
	case errors.Is(err, provision.ErrInvalid):
		http.Error(w, "invalid request", 400)
	case errors.Is(err, provision.ErrToken), errors.Is(err, provision.ErrExpired):
		http.Error(w, "token invalid", 403)
	case errors.Is(err, provision.ErrAccount):
		http.Error(w, "account not eligible", 403)
	case errors.Is(err, provision.ErrAlreadyLinked), errors.Is(err, provision.ErrDeviceBound),
		errors.Is(err, provision.ErrGamertagTaken), errors.Is(err, provision.ErrUsed):
		http.Error(w, "conflict", 409)
	case errors.Is(err, provision.ErrFailed):
		http.Error(w, "provisioning failed", 422)
	default:
		http.Error(w, "unavailable", 503)
	}
}
