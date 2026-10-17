// SPDX-License-Identifier: AGPL-3.0-only

// Package svc5 serves native service 5 (account signup requests) to the
// gateway over internal/xbfeature streams. The console speaks plain HTTP/1.0
// on its security-gateway TCP connection, e.g.
//
//	POST /xuacs/reservename.ashx HTTP/1.0
//	Content-type: xon/5
//
// The wire format is documented in workspace docs/xbox/account-service-protocol.md
// (facts from static analysis of the dashboard and from captures). Only
// reservename is implemented; every other service-5 path answers 501 and never
// a made-up success. No account, user or link is created here: reservename
// only checks availability against xb-account's own alias state and holds the
// name for a short time.
package svc5

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"openpak/xb-live/internal/xbaccountapi"
	"openpak/xb-live/internal/xbfeature"
	"openpak/xb-live/services/xb-account/internal/store"
)

// Native status values the dashboard maps to its own messages (HRESULT table of
// the dashboard, see the protocol document).
const (
	errNameTaken     = 0x80154000 // "The Gamertag you have chosen is unavailable."
	errInvalidName   = 0x80154002 // "...must begin with a letter (a-z, A-Z)."
	errAccountClosed = 0x8015400a // account operation blocked
)

const (
	// HoldTTL is how long a reserved name is kept for the signup that asked.
	HoldTTL = 15 * time.Minute
	// MaxSuggestions is the most alternatives the client's response buffer holds.
	MaxSuggestions = 5
	maxBody        = 4096
	reserveHeader  = 8 + 1 + 2 + 2 // machine id, locale, suggestion count, name length
)

// Names is the slice of xb-account state reservename needs (store.Store).
type Names interface {
	ReserveName(ctx context.Context, machineID, account, gamertag string, ttl time.Duration, allowOwner bool) (store.Reservation, error)
	NameAvailable(ctx context.Context, gamertag, account string) (bool, error)
}

// Server implements xbfeature.Handler for service 5.
type Server struct {
	Names Names
	// Vouchers, Signups and AccountBlob enable verifyvoucher(getoffer),
	// OfferingDetailsNoUser and createowneracct. Without them those paths stay 501.
	Vouchers    VoucherChecker
	Signups     Signups
	AccountBlob func(xuid uint64) ([]byte, error)
	// AllowOwner skips the one-user-per-account refusal. TEST DEPLOYMENTS ONLY:
	// it lets a console whose account already owns a gamertag exercise the
	// name screens. Nothing is created either way.
	AllowOwner bool
	Now        func() time.Time // tests
	// Rand supplies suggestion digits; crypto/rand when nil.
	Rand io.Reader

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// Per-console request budget: names are public, but an unbounded reservename is
// an availability oracle.
const (
	burst      = 20
	refillSecs = 3.0
)

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) allow(machine string) bool {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.buckets == nil {
		s.buckets = map[string]*bucket{}
	}
	b := s.buckets[machine]
	if b == nil {
		if len(s.buckets) > 4096 { // bounded: forget idle consoles
			for k, v := range s.buckets {
				if now.Sub(v.last) > time.Minute {
					delete(s.buckets, k)
				}
			}
		}
		b = &bucket{tokens: burst, last: now}
		s.buckets[machine] = b
	}
	b.tokens = min(burst, b.tokens+now.Sub(b.last).Seconds()/refillSecs)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type connReader struct {
	c   xbfeature.Conn
	buf []byte
}

func (r *connReader) Read(p []byte) (int, error) {
	for len(r.buf) == 0 {
		b, err := r.c.Recv()
		if err != nil {
			return 0, err
		}
		r.buf = b
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

// Serve handles requests until the console closes. HTTP/1.0 requests (what the
// dashboard sends) get a single response and a close.
func (s *Server) Serve(ctx context.Context, info xbfeature.Info, c xbfeature.Conn) error {
	br := bufio.NewReaderSize(&connReader{c: c}, 8<<10)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return respond(c, 400, 0, nil)
		}
		body, err := io.ReadAll(io.LimitReader(req.Body, maxBody+1))
		req.Body.Close()
		if err != nil || len(body) > maxBody {
			return respond(c, 413, 0, nil)
		}
		resp := s.handle(ctx, info, req, body)
		closeConn := req.Close || req.ProtoMajor == 1 && req.ProtoMinor == 0 || resp.code >= 400
		if err := resp.write(c); err != nil || closeConn {
			return err
		}
	}
}

type response struct {
	code   int
	xerr   uint32
	hasErr bool
	body   []byte
}

func (r response) write(c xbfeature.Conn) error {
	if r.hasErr {
		return respond(c, r.code, r.xerr, r.body)
	}
	return respond(c, r.code, 0, r.body)
}

// respond writes an HTTP/1.0 response. A 200 always carries an explicit X-Err
// (hexadecimal HRESULT, 0 = success): the dashboard reads the request status
// from that header and from the HTTP status only when it is 400 or more.
func respond(c xbfeature.Conn, code int, xerr uint32, body []byte) error {
	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/1.0 %d %s\r\n", code, http.StatusText(code))
	if code == 200 {
		fmt.Fprintf(&b, "X-Err: %x\r\nContent-Type: application/octet-stream\r\n", xerr)
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n", len(body))
	b.Write(body)
	out := b.Bytes()
	for len(out) > 0 {
		n := min(len(out), 16<<10)
		if err := c.Send(out[:n]); err != nil {
			return err
		}
		out = out[n:]
	}
	return nil
}

func status(code int) response { return response{code: code} }

func xerr(code uint32) response { return response{code: 200, xerr: code, hasErr: true} }

func (s *Server) handle(ctx context.Context, info xbfeature.Info, req *http.Request, body []byte) response {
	path := strings.ToLower(req.URL.Path)
	if !strings.HasSuffix(path, ".ashx") && path != "/xpnfront/xpresence.srf" {
		return status(404)
	}
	switch {
	case strings.HasPrefix(path, "/xuacs/"):
		if req.Header.Get("Content-Type") != "xon/5" {
			return status(400)
		}
	case path == "/xpnfront/xpresence.srf":
		if req.Header.Get("Content-Type") != "xon/1" {
			return status(400)
		}
		if req.Method != http.MethodPost {
			return status(405)
		}
		// Presence belongs to a signed-in user: identity is the gateway-bound XUID.
		if info.XUID == 0 || info.ServiceID != 1 {
			return status(403)
		}
		if !s.allow("u" + fmt.Sprint(info.XUID)) {
			return status(429)
		}
		return s.presence(ctx, info, body)
	case path == "/xbos/offeringdetailsnouser.ashx":
		if req.Header.Get("Content-Type") != "xon/4" {
			return status(400)
		}
	default:
		return status(404)
	}
	handler := s.route(path)
	if handler == nil {
		return status(501) // known requests that are not implemented yet
	}
	if req.Method != http.MethodPost {
		return status(405)
	}
	// Only a provisioned console may ask. The gateway bound this identity from
	// the validated ticket; the machine id inside the body is only compared.
	if !xbaccountapi.ValidMachineID(info.PrincipalID) || info.CoreAccountID == "" {
		return status(403)
	}
	if !s.allow(info.PrincipalID) {
		return status(429)
	}
	resp := handler(ctx, info, body)
	if resp.code == 400 {
		// Shape only, never content: helps match the client's real framing.
		n := -1
		if len(body) >= 3 {
			n = int(binary.LittleEndian.Uint16(body[1:3]))
		}
		log.Printf("svc5 400: path=%s body_len=%d b0=%d u16_at_1=%d", path, len(body), firstByte(body), n)
	}
	return resp
}

func firstByte(b []byte) int {
	if len(b) == 0 {
		return -1
	}
	return int(b[0])
}

type handlerFunc func(ctx context.Context, info xbfeature.Info, body []byte) response

// route returns the implementation of an implemented path, nil otherwise.
func (s *Server) route(path string) handlerFunc {
	switch path {
	case "/xuacs/reservename.ashx":
		return s.reserveName
	case "/xuacs/verifyvoucher.ashx", "/xuacs/verifyvouchergetoffer.ashx":
		if s.Vouchers != nil {
			return s.verifyVoucher
		}
	case "/xuacs/createowneracct.ashx":
		if s.Signups != nil && s.AccountBlob != nil {
			return s.createOwner
		}
	case "/xbos/offeringdetailsnouser.ashx":
		if s.Vouchers != nil {
			return s.offeringDetails
		}
	}
	return nil
}

// parseReserve decodes the request body: machine id (8 bytes, little endian),
// locale code (1), requested suggestion count (u16 LE), name length (u16 LE),
// name (UTF-8). The length must account for every byte.
func parseReserve(body []byte) (machine string, locale byte, want int, name string, ok bool) {
	if len(body) < reserveHeader {
		return "", 0, 0, "", false
	}
	n := int(binary.LittleEndian.Uint16(body[11:13]))
	if len(body) != reserveHeader+n {
		return "", 0, 0, "", false
	}
	id := binary.LittleEndian.Uint64(body[0:8])
	machine, valid := xbaccountapi.MachineID(id)
	if !valid {
		return "", 0, 0, "", false
	}
	return machine, body[8], int(binary.LittleEndian.Uint16(body[9:11])), string(body[13:]), true
}

// ValidName applies the signup name rules known from the dashboard: it must
// begin with an ASCII letter (client text ERR_INVALID_USER and its own check
// for friend names), have at most 15 characters (the client's buffer is 16
// including the terminator and the reply reader accepts 1-16 bytes), and use
// only letters, digits and single inner spaces (the character set beyond the
// first letter is NOT confirmed from the client binary).
func ValidName(v string) bool {
	if !xbaccountapi.ValidGamertag(v) {
		return false
	}
	if c := v[0]; !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
		return false
	}
	return !strings.Contains(v, "  ")
}

func (s *Server) reserveName(ctx context.Context, info xbfeature.Info, body []byte) response {
	machine, _, want, name, ok := parseReserve(body)
	if !ok || machine != info.PrincipalID {
		return status(400)
	}
	if !ValidName(name) {
		return xerr(errInvalidName)
	}
	_, err := s.Names.ReserveName(ctx, info.PrincipalID, info.CoreAccountID, name, HoldTTL, s.AllowOwner)
	switch {
	case err == nil:
		return response{code: 200, hasErr: true, body: encodeNames(nil)}
	case errors.Is(err, store.ErrAccountHasUser):
		return xerr(errAccountClosed)
	case errors.Is(err, store.ErrNameTaken):
		// Unavailable. The client treats an empty list as success, so a taken
		// name is only ever answered with real, currently free alternatives or
		// with the explicit "unavailable" status.
		alts := s.suggest(ctx, info.CoreAccountID, name, min(want, MaxSuggestions))
		if len(alts) == 0 {
			return xerr(errNameTaken)
		}
		return response{code: 200, hasErr: true, body: encodeNames(alts)}
	default:
		log.Printf("svc5 reservename: store error")
		return status(503)
	}
}

// suggest returns up to n free names derived from base, each checked now
// against real state (advisory: not held).
func (s *Server) suggest(ctx context.Context, account, base string, n int) []string {
	if n <= 0 {
		return nil
	}
	stem := strings.TrimRight(base, "0123456789 ")
	if stem == "" {
		stem = base[:1]
	}
	var out []string
	seen := map[string]bool{strings.ToLower(base): true}
	for try := 0; try < 40 && len(out) < n; try++ {
		digits := 2 + try/10 // 2..5 digits
		limit := big.NewInt(1)
		for i := 0; i < digits; i++ {
			limit.Mul(limit, big.NewInt(10))
		}
		r := s.Rand
		if r == nil {
			r = rand.Reader
		}
		v, err := rand.Int(r, limit)
		if err != nil {
			return out
		}
		cand := fmt.Sprintf("%s%0*d", stem[:min(len(stem), 15-digits)], digits, v.Int64())
		if seen[strings.ToLower(cand)] || !ValidName(cand) {
			continue
		}
		seen[strings.ToLower(cand)] = true
		free, err := s.Names.NameAvailable(ctx, cand, account)
		if err != nil {
			return out
		}
		if free {
			out = append(out, cand)
		}
	}
	return out
}

// encodeNames builds the reply body: u16 LE count, then per name u16 LE length
// and the UTF-8 bytes.
func encodeNames(names []string) []byte {
	b := binary.LittleEndian.AppendUint16(nil, uint16(len(names)))
	for _, n := range names {
		b = binary.LittleEndian.AppendUint16(b, uint16(len(n)))
		b = append(b, n...)
	}
	return b
}
