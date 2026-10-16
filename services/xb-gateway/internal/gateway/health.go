// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"time"
)

// Health separates three questions an operator asks, because answering "yes"
// to the first does not answer the others:
//
//   - listener: is the UDP socket bound and being read (process liveness)?
//   - dependencies: can the gateway currently verify tickets, resolve accounts
//     and reach feature backends (readiness)?
//   - e2e: has a real native client completed a handshake recently? This is
//     observed, not probed; "never" means no console has proven the path yet.
type Health struct {
	Listener     string            `json:"listener"`
	Ready        bool              `json:"ready"`
	Dependencies map[string]string `json:"dependencies"`
	Backends     map[string]string `json:"backends"`
	E2E          E2EHealth         `json:"e2e"`
	Sessions     int               `json:"sessions"`
}
type E2EHealth struct {
	LastHandshakeUnix int64  `json:"last_handshake_unix"`
	State             string `json:"state"`
}

func depState(c any, configured bool, ctx context.Context) string {
	if !configured {
		return "unconfigured"
	}
	if ch, ok := c.(Checker); ok {
		if err := ch.Check(ctx); err != nil {
			return "unavailable"
		}
		return "ok"
	}
	return "ok (no active check)"
}

func (s *Server) Health(ctx context.Context) Health {
	h := Health{Listener: "down", Dependencies: map[string]string{}, Backends: map[string]string{}, Sessions: s.SessionCount()}
	if s.listening.Load() {
		h.Listener = "listening"
	}
	h.Dependencies["ticket_verifier"] = depState(s.verifier, s.verifier != nil, ctx)
	h.Dependencies["directory"] = depState(s.dir, s.dir != nil, ctx)
	ids := make([]int, 0, len(s.backends))
	for id := range s.backends {
		ids = append(ids, int(id))
	}
	sort.Ints(ids)
	for _, id := range ids {
		h.Backends[strconv.Itoa(id)] = depState(s.backends[uint32(id)], true, ctx)
	}
	// Feature backends being down degrades features natively (unavailable); it
	// does not make the gateway unready.
	h.Ready = h.Listener == "listening" && h.Dependencies["ticket_verifier"][:2] == "ok" && h.Dependencies["directory"][:2] == "ok"
	h.E2E = E2EHealth{State: "never"}
	if t := s.lastHandshake.Load(); t != 0 {
		h.E2E = E2EHealth{LastHandshakeUnix: t, State: "observed"}
	}
	return h
}

// HealthHandler serves /livez, /readyz and /healthz (JSON) plus /metricsz counters.
func (s *Server) HealthHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/livez", func(w http.ResponseWriter, r *http.Request) {
		if !s.listening.Load() {
			http.Error(w, "listener down", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if !s.Health(ctx).Ready {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ready\n"))
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		h := s.Health(ctx)
		w.Header().Set("Content-Type", "application/json")
		if !h.Ready {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		json.NewEncoder(w).Encode(h)
	})
	mux.HandleFunc("/metricsz", func(w http.ResponseWriter, r *http.Request) {
		st := &s.stats
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]uint64{
			"datagrams": st.datagrams.Load(), "init_accepted": st.initAccepted.Load(), "init_rejected": st.initRejected.Load(),
			"init_rate_limited": st.initRateLimited.Load(), "init_busy": st.initBusy.Load(), "auth_drops": st.authDrops.Load(),
			"replay_drops": st.replayDrops.Load(), "rate_drops": st.rateDrops.Load(), "unauthorized_port": st.unauthorizedPort.Load(),
			"service_unavailable": st.unavailable.Load(), "backend_errors": st.backendErrors.Load(), "malformed": st.malformed.Load(),
			"unknown_session": st.unknownSession.Load(),
		})
	})
	return mux
}
