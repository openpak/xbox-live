// SPDX-License-Identifier: AGPL-3.0-only

package xbaccountapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	MaxWait  = 25 * time.Second
	MaxLimit = 500
)

type deniedBody struct {
	Principal Principal `json:"principal"`
}

// Handler serves the contract. Authorization of callers (mTLS peer identity)
// is the embedding server's job; mount it behind that check.
func Handler(r Resolver, rev Revocations) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /internal/v1/users/{id}", func(w http.ResponseWriter, req *http.Request) {
		resolve(w, req, r.ResolveUser)
	})
	mux.HandleFunc("GET /internal/v1/gamertags/{tag}", func(w http.ResponseWriter, req *http.Request) {
		resolve(w, req, r.ResolveGamertag)
	})
	mux.HandleFunc("GET /internal/v1/devices/{id}", func(w http.ResponseWriter, req *http.Request) {
		resolve(w, req, r.ResolveDevice)
	})
	mux.HandleFunc("GET /internal/v1/revocations", func(w http.ResponseWriter, req *http.Request) {
		q := req.URL.Query()
		after, e1 := strconv.ParseUint(q.Get("after"), 10, 64)
		limit, e2 := strconv.Atoi(q.Get("limit"))
		waitSec := 0
		var e3 error
		if v := q.Get("wait"); v != "" {
			waitSec, e3 = strconv.Atoi(v)
		}
		if e1 != nil || e2 != nil || e3 != nil || limit < 1 || waitSec < 0 {
			http.Error(w, "invalid request", 400)
			return
		}
		limit = min(limit, MaxLimit)
		wait := min(time.Duration(waitSec)*time.Second, MaxWait)
		out, err := rev.Poll(req.Context(), after, limit, wait)
		if err != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		if out == nil {
			out = []Revocation{}
		}
		writeJSON(w, 200, out)
	})
	return mux
}

func resolve(w http.ResponseWriter, req *http.Request, f func(context.Context, string) (Principal, error)) {
	key := req.PathValue("id")
	if key == "" {
		key = req.PathValue("tag")
	}
	p, err := f(req.Context(), key)
	var denied *DeniedError
	switch {
	case err == nil:
		writeJSON(w, 200, p)
	case errors.As(err, &denied):
		writeJSON(w, 403, deniedBody{denied.Principal})
	case errors.Is(err, ErrInvalid):
		http.Error(w, "invalid identifier", 400)
	case errors.Is(err, ErrNotFound):
		http.Error(w, "not found", 404)
	default:
		http.Error(w, "unavailable", 503)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// Client implements Resolver and Revocations over HTTP. Supply an
// http.Client whose transport carries the caller's mTLS configuration.
type Client struct {
	Base string // https://host:port
	HTTP *http.Client
}

var _ Resolver = (*Client)(nil)
var _ Revocations = (*Client)(nil)

func (c *Client) get(ctx context.Context, path string, out any) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.Base+path, nil)
	if err != nil {
		return 0, nil, ErrUnavailable
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, ErrUnavailable
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, nil, ErrUnavailable
	}
	return resp.StatusCode, body, nil
}

func (c *Client) resolve(ctx context.Context, kind Kind, seg, id string) (Principal, error) {
	if seg == "gamertags" && !ValidGamertag(id) || seg != "gamertags" && !ValidID(id) {
		return Principal{}, ErrInvalid
	}
	code, body, err := c.get(ctx, "/internal/v1/"+seg+"/"+url.PathEscape(id), nil)
	if err != nil {
		return Principal{}, err
	}
	switch code {
	case 200:
		var p Principal
		// A success must be a well-formed active principal for this id.
		if json.Unmarshal(body, &p) != nil || p.Kind != kind || (seg != "gamertags" && p.PrincipalID != id || seg == "gamertags" && !ValidID(p.PrincipalID)) || p.CoreAccountID == "" || p.Status != StatusActive {
			return Principal{}, ErrUnavailable
		}
		return p, nil
	case 403:
		var d deniedBody
		if json.Unmarshal(body, &d) != nil || !d.Principal.Status.Valid() || d.Principal.Status == StatusActive {
			return Principal{}, ErrUnavailable
		}
		return Principal{}, &DeniedError{d.Principal}
	case 404:
		return Principal{}, ErrNotFound
	case 400:
		return Principal{}, ErrInvalid
	}
	return Principal{}, ErrUnavailable
}

func (c *Client) ResolveUser(ctx context.Context, xuid string) (Principal, error) {
	return c.resolve(ctx, KindUser, "users", xuid)
}
func (c *Client) ResolveGamertag(ctx context.Context, tag string) (Principal, error) {
	return c.resolve(ctx, KindUser, "gamertags", tag)
}
func (c *Client) ResolveDevice(ctx context.Context, id string) (Principal, error) {
	return c.resolve(ctx, KindDevice, "devices", id)
}

func (c *Client) Poll(ctx context.Context, after uint64, limit int, wait time.Duration) ([]Revocation, error) {
	q := url.Values{"after": {strconv.FormatUint(after, 10)}, "limit": {strconv.Itoa(limit)}, "wait": {strconv.Itoa(int(wait / time.Second))}}
	code, body, err := c.get(ctx, "/internal/v1/revocations?"+q.Encode(), nil)
	if err != nil || code != 200 {
		return nil, ErrUnavailable
	}
	var out []Revocation
	if json.Unmarshal(body, &out) != nil {
		return nil, ErrUnavailable
	}
	last := after
	for _, r := range out {
		if r.Seq <= last { // enforce strictly increasing, never replaying behind the cursor
			return nil, ErrUnavailable
		}
		last = r.Seq
	}
	return out, nil
}
