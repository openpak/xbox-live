// SPDX-License-Identifier: AGPL-3.0-only

// Package svc1 serves native service 1 (Presence) to the gateway over
// internal/xbfeature streams: POST /xpnfront/xpresence.srf, Content-type
// xon/1. The Alive/Alive2 layouts come from the Xombie codec (libs/xblive/src/
// service/presence.rs, vectors mirrored in svc1_test.go): a 32-byte header
// (type u32, len u32, seq u32, SG address 20 bytes), then the message and the
// NUL-terminated account name; the answer is AliveReply (1101) echoing seq and
// SG address.
//
// Alive is the console's heartbeat. It is real here: the signed-in user is the
// gateway-bound XUID (never the one in the message, which must merely agree),
// presence is published to account core as an "xbox" session lease, and the
// reply's list versions and counts come from the user's real roster.
//
// What this package does not know is how buddy and block entries are encoded
// after the reply header, nor any message other than Alive/Alive2: those are
// the job of the Lists and Messages plug-ins, supplied once the wire is
// documented (docs/xbox/social-protocol.md). Without a plug-in a message type
// is answered 501 and a non-empty list is not announced (version 0, no
// entries) rather than invented.
package svc1

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"openpak/xb-live/internal/xbfeature"
	"openpak/xb-live/services/xb-social/internal/social"
)

const (
	msgAlive      = 1001
	msgAlive2     = 1025
	msgAliveReply = 0x44d

	presenceHeader = 32
	aliveBody      = 38 // XUID 8, title 4, name len 2, buddy ver 4, block ver 4, state 4, match id 8, nick len 2, title stuff len 2
	alive2Body     = 120
	maxBody        = 4096
)

// Call is the connection context the gateway bound plus the viewer in the form
// the domain layer takes.
type Call struct {
	Info xbfeature.Info
	XUID string // 16 lowercase hex
}

// Lists encodes the buddy and block entries that follow an AliveReply header.
// sendBuddies/sendBlocks say which lists the console is out of date on (its
// version differs). It returns the bytes to append and the counts to put in
// the header; the counts must match the entries it wrote.
type Lists interface {
	AliveLists(r *social.Roster, sendBuddies, sendBlocks bool) (data []byte, buddies, blocks uint16, err error)
}

// Messages handles presence-service message types other than Alive/Alive2
// (friend operations, invitations, notifications) once their wire format is
// known. ErrUnsupported (or any unknown type) is answered 501.
type Messages interface {
	Handle(ctx context.Context, c Call, msgType uint32, header [presenceHeader]byte, body []byte) (reply []byte, err error)
}

var ErrUnsupported = errors.New("svc1: message type not supported")

// Server implements xbfeature.Handler. Service ids it does not own are passed
// to Others, or refused (the stream closes and the gateway answers "unavailable").
type Server struct {
	Social   *social.Service
	Presence *social.Presences
	Lists    Lists    // optional
	Messages Messages // optional
	// TTL is how long one Alive keeps the user online (default social.DefaultTTL).
	TTL time.Duration
	// OfflineOnClose ends presence when the console's connection closes, for
	// transports that keep one connection per sign-in. Leave false for
	// per-request HTTP/1.0 connections, which close after every reply.
	OfflineOnClose bool
	Others         map[uint32]xbfeature.Handler
	// RosterMode narrows what AliveReply carries, to find which entry kind a
	// console rejects: "" or "all", "empty", "friends", "requests" (friends
	// omitted), "blocks". Debug aid only.
	RosterMode string
	// Stub answers every Alive with an empty AliveReply immediately: no core
	// call, no presence, exactly what the xb-account stub did. StubWork does
	// the admission, presence publish and roster load first and then discards
	// the result for the same empty reply. StubDelay waits before replying.
	// Bisect aids only.
	Stub, StubWork bool
	StubDelay      time.Duration
	// DebugHex logs every AliveReply as hex (XUIDs and gamertags only).
	DebugHex bool
	Now      func() time.Time

	mu      sync.Mutex
	buckets map[uint64]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

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

func (s *Server) allow(xuid uint64) bool {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.buckets == nil {
		s.buckets = map[uint64]*bucket{}
	}
	b := s.buckets[xuid]
	if b == nil {
		if len(s.buckets) > 4096 {
			for k, v := range s.buckets {
				if now.Sub(v.last) > time.Minute {
					delete(s.buckets, k)
				}
			}
		}
		b = &bucket{tokens: burst, last: now}
		s.buckets[xuid] = b
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

var errNoBackend = errors.New("svc1: service id not served here")

// Serve handles one console connection.
func (s *Server) Serve(ctx context.Context, info xbfeature.Info, c xbfeature.Conn) error {
	if h := s.Others[info.ServiceID]; h != nil {
		return h.Serve(ctx, info, c)
	}
	if info.ServiceID != 1 {
		return errNoBackend
	}
	if s.OfflineOnClose && info.CoreAccountID != "" {
		defer func() {
			// The context may be cancelled by the close that got us here.
			dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			defer cancel()
			if err := s.Presence.Disconnect(dctx, info.CoreAccountID, info.Generation); err != nil {
				log.Printf("svc1: disconnect: %v", err)
			}
		}()
	}
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
		res := s.handle(ctx, info, req, body)
		closeConn := req.Close || req.ProtoMajor == 1 && req.ProtoMinor == 0 || res.code >= 400
		if err := respond(c, res.code, res.xerr, res.body); err != nil || closeConn {
			return err
		}
	}
}

// respond writes an HTTP/1.0 response. A 200 always carries an explicit X-Err
// (hexadecimal HRESULT, 0 = success), which is how the dashboard learns the
// outcome of an operation whose reply body it does not parse.
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

type result struct {
	code int
	xerr uint32
	body []byte
}

func status(code int) result { return result{code: code} }

// Service 1 paths: presence and operations on xpresence.srf, the notification
// poll on xnotification.srf (docs/xbox/social-protocol.md section 0).
const (
	pathPresence     = "/xpnfront/xpresence.srf"
	pathNotification = "/xpnfront/xnotification.srf"
)

func (s *Server) handle(ctx context.Context, info xbfeature.Info, req *http.Request, body []byte) result {
	path := strings.ToLower(req.URL.Path)
	if path != pathPresence && path != pathNotification {
		return status(404)
	}
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
	if !s.allow(info.XUID) {
		return status(429)
	}
	call := Call{Info: info, XUID: fmt.Sprintf("%016x", info.XUID)}
	var res result
	var err error
	if path == pathNotification {
		res, err = s.notification(ctx, call, body)
	} else {
		res, err = s.presence(ctx, call, body)
	}
	switch {
	case err == nil:
		res.code = 200
		return res
	case errors.Is(err, errBad):
		return status(400)
	case errors.Is(err, social.ErrDenied):
		return status(403)
	case errors.Is(err, social.ErrSuperseded):
		return status(409)
	case errors.Is(err, ErrUnsupported):
		return status(501)
	}
	log.Printf("svc1: unavailable: %v", err)
	return status(503)
}

var errBad = errors.New("svc1: malformed message")

// splitMessages cuts a body into header+payload messages. n is the most
// messages accepted (the client packs up to 4, one per local user).
func splitMessages(body []byte, n int) ([][]byte, error) {
	var out [][]byte
	for len(body) > 0 {
		if len(body) < presenceHeader || len(out) >= n {
			return nil, errBad
		}
		l := presenceHeader + int(binary.LittleEndian.Uint32(body[4:8]))
		if l < presenceHeader || l > len(body) {
			return nil, errBad
		}
		out = append(out, body[:l])
		body = body[l:]
	}
	if len(out) == 0 {
		return nil, errBad
	}
	return out, nil
}

// parseAlive decodes Alive/Alive2. It returns the title id and the versions
// the console currently holds. The account name must be consistent and its
// XUID must be the connection's.
func parseAlive(typ uint32, msg []byte, wantXUID uint64) (title, buddyVer, blockVer uint32, err error) {
	var xuid uint64
	var nameLen int
	switch typ {
	case msgAlive:
		if len(msg) < aliveBody {
			return 0, 0, 0, errBad
		}
		xuid = binary.LittleEndian.Uint64(msg[0:8])
		title = binary.LittleEndian.Uint32(msg[8:12])
		nameLen = int(binary.LittleEndian.Uint16(msg[12:14]))
		buddyVer = binary.LittleEndian.Uint32(msg[14:18])
		blockVer = binary.LittleEndian.Uint32(msg[18:22])
		// Nickname and title-specific data would follow the fixed part; the
		// client has not been seen sending them and we do not parse them.
		if binary.LittleEndian.Uint16(msg[34:36]) != 0 || binary.LittleEndian.Uint16(msg[36:38]) != 0 {
			return 0, 0, 0, ErrUnsupported
		}
		msg = msg[aliveBody:]
	case msgAlive2:
		if len(msg) < alive2Body {
			return 0, 0, 0, errBad
		}
		xuid = binary.LittleEndian.Uint64(msg[0:8])
		nameLen = int(binary.LittleEndian.Uint16(msg[8:10]))
		buddyVer = binary.LittleEndian.Uint32(msg[70:74])
		blockVer = binary.LittleEndian.Uint32(msg[74:78])
		title = binary.LittleEndian.Uint32(msg[86:90])
		msg = msg[alive2Body:]
	default:
		return 0, 0, 0, ErrUnsupported
	}
	// The name length counts the terminating NUL (Xombie vector: 9 for "monocasa").
	if xuid != wantXUID || nameLen < 1 || len(msg) != nameLen || msg[nameLen-1] != 0 || bytes.IndexByte(msg[:nameLen-1], 0) >= 0 {
		return 0, 0, 0, errBad
	}
	return title, buddyVer, blockVer, nil
}

func (s *Server) presence(ctx context.Context, c Call, body []byte) (result, error) {
	msgs, err := splitMessages(body, 4)
	if err != nil {
		return result{}, err
	}
	typ := binary.LittleEndian.Uint32(msgs[0][0:4])
	if typ == msgAlive || typ == msgAlive2 {
		return s.alive(ctx, c, msgs)
	}
	if len(msgs) != 1 {
		return result{}, errBad
	}
	return s.operation(ctx, c, typ, msgs[0])
}

// alive answers one Alive/Alive2 per message, in order, in one body. Every
// message must be the connection's own user: the gateway authenticates one
// user per stream, and a reply for anybody else cannot be produced honestly.
func (s *Server) alive(ctx context.Context, c Call, msgs [][]byte) (result, error) {
	type parsed struct {
		hdr                   [presenceHeader]byte
		title, buddyV, blockV uint32
	}
	var ps []parsed
	for _, m := range msgs {
		typ := binary.LittleEndian.Uint32(m[0:4])
		if typ != msgAlive && typ != msgAlive2 {
			return result{}, errBad
		}
		title, bv, kv, err := parseAlive(typ, m[presenceHeader:], c.Info.XUID)
		if err != nil {
			return result{}, err
		}
		p := parsed{title: title, buddyV: bv, blockV: kv}
		copy(p.hdr[:], m)
		ps = append(ps, p)
	}
	// The xb-account stub's reply: empty lists, version 0, no core involved.
	stub := func() (result, error) {
		time.Sleep(s.StubDelay)
		var out []byte
		for _, p := range ps {
			r, err := s.aliveReply(p.hdr, &social.Roster{}, p.buddyV, p.blockV)
			if err != nil {
				return result{}, err
			}
			out = append(out, r...)
		}
		log.Printf("svc1: STUB AliveReply bytes=%d delay=%s work=%v", len(out), s.StubDelay, s.StubWork)
		return result{body: out}, nil
	}
	if s.Stub {
		return stub()
	}
	// Admit first (banned/unlinked users publish nothing), then publish, then
	// read the roster the reply describes.
	account, err := s.Social.Actor(ctx, c.XUID, c.Info.CoreAccountID)
	if err != nil {
		return result{}, err
	}
	if err := s.Presence.Publish(ctx, account, c.XUID, social.TitleKey(ps[0].title), c.Info.Generation, s.TTL); err != nil {
		// Presence is best effort: the console still gets its lists. Only a
		// refusal (not admitted, or a newer connection owns the account) ends the Alive.
		if errors.Is(err, social.ErrDenied) || errors.Is(err, social.ErrSuperseded) {
			return result{}, err
		}
		log.Printf("svc1: presence not published (continuing): %v", err)
	}
	roster, err := s.Social.RosterOf(ctx, account)
	if err != nil {
		return result{}, err
	}
	if s.StubWork {
		return stub()
	}
	switch s.RosterMode {
	case "empty":
		roster.Filter(false, false, false)
	case "friends":
		roster.Filter(true, false, false)
	case "requests":
		roster.Filter(false, true, false)
	case "blocks":
		roster.Filter(false, false, true)
	}
	var out []byte
	for _, p := range ps {
		r, err := s.aliveReply(p.hdr, roster, p.buddyV, p.blockV)
		if err != nil {
			return result{}, err
		}
		out = append(out, r...)
		bv, nb, kv, nl := binary.LittleEndian.Uint32(r[presenceHeader+4:]), binary.LittleEndian.Uint16(r[presenceHeader+8:]),
			binary.LittleEndian.Uint32(r[presenceHeader+10:]), binary.LittleEndian.Uint16(r[presenceHeader+14:])
		log.Printf("svc1: AliveReply mode=%q client_versions=%d/%d reply buddies=%d@%d blocks=%d@%d bytes=%d", s.RosterMode, p.buddyV, p.blockV, nb, bv, nl, kv, len(r))
		if s.DebugHex {
			log.Printf("svc1: AliveReply hex=%x", r)
		}
	}
	return result{body: out}, nil
}

// aliveReply builds AliveReply: hr s32 0, buddy version u32, buddies u16,
// block version u32, blocks u16, then the entries (docs/xbox/social-protocol.md
// 1.1). A list whose version the console already holds is not resent.
func (s *Server) aliveReply(hdr [presenceHeader]byte, r *social.Roster, buddyVer, blockVer uint32) ([]byte, error) {
	lists := s.Lists
	if lists == nil {
		lists = WireLists{}
	}
	sendBuddies := r.BuddyVersion != buddyVer
	sendBlocks := r.BlockVersion != blockVer
	data, nb, nl, err := lists.AliveLists(r, sendBuddies, sendBlocks)
	if err != nil {
		return nil, err
	}
	out := make([]byte, presenceHeader+16, presenceHeader+16+len(data))
	binary.LittleEndian.PutUint32(out[0:], msgAliveReply)
	binary.LittleEndian.PutUint32(out[4:], uint32(16+len(data)))
	copy(out[8:presenceHeader], hdr[8:]) // seq + SG address echoed
	binary.LittleEndian.PutUint32(out[presenceHeader+4:], r.BuddyVersion)
	binary.LittleEndian.PutUint16(out[presenceHeader+8:], nb)
	binary.LittleEndian.PutUint32(out[presenceHeader+10:], r.BlockVersion)
	binary.LittleEndian.PutUint16(out[presenceHeader+14:], nl)
	return append(out, data...), nil
}
