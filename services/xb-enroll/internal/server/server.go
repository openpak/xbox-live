// SPDX-License-Identifier: AGPL-3.0-only

// Package server is the public face of device-pairing enrolment. It exposes
// exactly two business routes and keeps no state beyond rate-limit counters:
//
//	POST /v1/enrol           {machineID, machineKey, clientInfo?} -> {pairingCode, expiresAt, pollToken}
//	GET  /v1/enrol/{token}   -> {status: pending|approved|expired, expiresAt}
//
// (plus GET /healthz for the container probe, which touches nothing). All
// validation is repeated by xb-account, which owns the state. Machine keys are
// never logged and never echoed. The listener is plain HTTP: TLS is terminated
// by the reverse proxy in front of it.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"openpak/xb-live/internal/ratelimit"
	"openpak/xb-live/internal/xbenrolapi"
)

// Backend is xb-account's enrolment surface (xbenrolapi.Client).
type Backend interface {
	Enrol(ctx context.Context, r xbenrolapi.EnrolRequest) (xbenrolapi.EnrolResponse, error)
	Poll(ctx context.Context, token string) (xbenrolapi.PollResponse, error)
}

type Config struct {
	Backend Backend
	// TrustedProxies are the reverse proxies whose X-Forwarded-For is honoured
	// (the rightmost entry that is not itself a trusted proxy is the client).
	// Empty: X-Forwarded-For is ignored and the TCP peer is the client.
	TrustedProxies []netip.Prefix
	Now            func() time.Time
}

type Server struct {
	cfg                                   Config
	enrolIP, enrolMachine, enrolAll, poll *ratelimit.Window
}

func New(cfg Config) *Server {
	s := &Server{cfg: cfg,
		enrolIP:      ratelimit.New(10, time.Hour),
		enrolMachine: ratelimit.New(6, 10*time.Minute),
		enrolAll:     ratelimit.New(300, time.Minute),
		poll:         ratelimit.New(120, time.Minute)}
	for _, w := range []*ratelimit.Window{s.enrolIP, s.enrolMachine, s.enrolAll, s.poll} {
		w.Now = cfg.Now
	}
	return s
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enrol", s.enrol)
	mux.HandleFunc("GET /v1/enrol/{token}", s.status)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	return mux
}

// ClientIP returns the rate-limit identity of the caller: the address, with
// IPv6 collapsed to its /64.
func (s *Server) ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return "unknown"
	}
	addr = addr.Unmap()
	trusted := func(a netip.Addr) bool {
		for _, p := range s.cfg.TrustedProxies {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	if trusted(addr) {
		parts := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
		for i := len(parts) - 1; i >= 0; i-- {
			a, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
			if err != nil {
				break // garbage: fall back to the proxy's own address
			}
			a = a.Unmap()
			addr = a
			if !trusted(a) {
				break
			}
		}
	}
	if addr.Is6() {
		p, _ := addr.Prefix(64)
		return p.Addr().String()
	}
	return addr.String()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, code string) {
	if status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "600")
	}
	writeJSON(w, status, xbenrolapi.ErrorBody{Error: code})
}

type enrolBody struct {
	MachineID  string `json:"machineID"`
	MachineKey string `json:"machineKey"`
	ClientInfo string `json:"clientInfo"`
}

func (s *Server) enrol(w http.ResponseWriter, r *http.Request) {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(ct), "application/json") {
		fail(w, http.StatusUnsupportedMediaType, xbenrolapi.CodeInvalidRequest)
		return
	}
	// Limit before reading or validating anything.
	if !s.enrolIP.Allow(s.ClientIP(r)) || !s.enrolAll.Allow("all") {
		fail(w, http.StatusTooManyRequests, xbenrolapi.CodeRateLimited)
		return
	}
	var in enrolBody
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, xbenrolapi.MaxBody))
	d.DisallowUnknownFields()
	if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF {
		fail(w, http.StatusBadRequest, xbenrolapi.CodeInvalidRequest)
		return
	}
	id, ok1 := xbenrolapi.ParseMachineID(in.MachineID)
	_, ok2 := xbenrolapi.ParseMachineKey(in.MachineKey)
	info, ok3 := xbenrolapi.CleanClientInfo(in.ClientInfo)
	if !ok1 || !ok2 || !ok3 {
		fail(w, http.StatusBadRequest, xbenrolapi.CodeInvalidRequest)
		return
	}
	if !s.enrolMachine.Allow(id) {
		fail(w, http.StatusTooManyRequests, xbenrolapi.CodeRateLimited)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	res, err := s.cfg.Backend.Enrol(ctx, xbenrolapi.EnrolRequest{MachineID: id, MachineKey: strings.ToLower(in.MachineKey), ClientInfo: info})
	if err != nil {
		backendFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"pairingCode": res.PairingCode, "pollToken": res.PollToken,
		"expiresAt": time.Unix(res.ExpiresUnix, 0).UTC().Format(time.RFC3339)})
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	if !s.poll.Allow(s.ClientIP(r)) {
		fail(w, http.StatusTooManyRequests, xbenrolapi.CodeRateLimited)
		return
	}
	tok := r.PathValue("token")
	if len(tok) < 16 || len(tok) > xbenrolapi.MaxTokenLen || strings.Trim(tok, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
		fail(w, http.StatusNotFound, xbenrolapi.CodeNotFound)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	res, err := s.cfg.Backend.Poll(ctx, tok)
	if err != nil {
		backendFail(w, err)
		return
	}
	switch res.Status {
	case xbenrolapi.StatusPending, xbenrolapi.StatusApproved, xbenrolapi.StatusExpired:
	default:
		fail(w, http.StatusBadGateway, xbenrolapi.CodeUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": res.Status, "expiresAt": time.Unix(res.ExpiresUnix, 0).UTC().Format(time.RFC3339)})
}

// backendFail maps xb-account's answer to the closed set a console may see.
func backendFail(w http.ResponseWriter, err error) {
	var e *xbenrolapi.Error
	if errors.As(err, &e) {
		switch e.Code {
		case xbenrolapi.CodeInvalidRequest:
			fail(w, http.StatusBadRequest, e.Code)
			return
		case xbenrolapi.CodeMachineActive:
			fail(w, http.StatusConflict, e.Code)
			return
		case xbenrolapi.CodeRateLimited:
			fail(w, http.StatusTooManyRequests, e.Code)
			return
		case xbenrolapi.CodeNotFound:
			fail(w, http.StatusNotFound, e.Code)
			return
		}
	}
	fail(w, http.StatusServiceUnavailable, xbenrolapi.CodeUnavailable)
}
