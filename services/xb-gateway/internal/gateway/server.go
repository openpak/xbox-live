// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"openpak/xb-live/internal/sgwire"
)

type stats struct {
	datagrams, initAccepted, initRejected, initRateLimited, initBusy atomic.Uint64
	authDrops, replayDrops, rateDrops, unauthorizedPort              atomic.Uint64
	unavailable, backendErrors, malformed, unknownSession            atomic.Uint64
}

// Server is the UDP listener plus session table.
type Server struct {
	cfg      Config
	log      *slog.Logger
	verifier TicketVerifier
	dir      Directory
	backends map[uint32]Backend
	now      func() time.Time
	capture  *capture

	conn    *net.UDPConn
	initSem chan struct{}
	limiter *ipLimiter
	replay  *replayCache
	stats   stats
	gen     atomic.Uint64

	mu       sync.RWMutex
	sessions map[sgwire.SPI]*Session
	perIP    map[netip.Addr]int

	listening     atomic.Bool
	lastHandshake atomic.Int64 // unix seconds of last accepted init
}

// NewServer wires dependencies. A nil verifier or directory is allowed so the
// binary can start and report not-ready; every init is then rejected.
func NewServer(cfg Config, log *slog.Logger, v TicketVerifier, d Directory, backends map[uint32]Backend) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cp, err := newCapture(cfg)
	if err != nil {
		return nil, err
	}
	if cp != nil {
		log.Warn("DEBUG CAPTURE ENABLED: decrypted payloads are written to disk", "dir", cfg.CaptureDir)
	}
	if backends == nil {
		backends = map[uint32]Backend{}
	}
	return &Server{cfg: cfg, log: log, verifier: v, dir: d, backends: backends, now: time.Now, capture: cp,
		initSem: make(chan struct{}, cfg.InitWorkers), limiter: newIPLimiter(cfg.InitRate, cfg.InitBurst, 65536),
		replay:   newReplayCache(2*cfg.ClockSkew, 1<<17),
		sessions: map[sgwire.SPI]*Session{}, perIP: map[netip.Addr]int{}}, nil
}

// Listen binds the UDP socket on the local interface (not the advertised address).
func (s *Server) Listen() error {
	c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(s.cfg.BindAddr))
	if err != nil {
		return err
	}
	s.conn = c
	s.listening.Store(true)
	return nil
}

func (s *Server) Addr() netip.AddrPort { return s.conn.LocalAddr().(*net.UDPAddr).AddrPort() }

// Serve reads datagrams until ctx is cancelled. It never blocks on slow work:
// handshakes run on a bounded worker pool and are dropped when it is full.
func (s *Server) Serve(ctx context.Context) error {
	go func() { <-ctx.Done(); s.conn.Close() }()
	go s.reap(ctx)
	buf := make([]byte, sgwire.MaxDatagram+1)
	for {
		n, peer, err := s.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			s.listening.Store(false)
			s.closeAll()
			s.capture.Close()
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		s.stats.datagrams.Add(1)
		if n > sgwire.MaxDatagram {
			s.stats.malformed.Add(1)
			continue
		}
		peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
		if !peer.Addr().Is4() {
			continue
		}
		pkt := append([]byte(nil), buf[:n]...)
		spi, isInit, ok := sgwire.PeekSPI(pkt)
		switch {
		case !ok:
			s.stats.malformed.Add(1)
		case isInit:
			s.dispatchInit(pkt, peer)
		default:
			s.mu.RLock()
			sess := s.sessions[spi]
			s.mu.RUnlock()
			if sess == nil || sess.peer != peer {
				s.stats.unknownSession.Add(1)
				continue
			}
			sess.handle(pkt, s.now())
		}
	}
}

func (s *Server) dispatchInit(pkt []byte, peer netip.AddrPort) {
	if !s.limiter.Allow(peer.Addr(), s.now()) {
		s.stats.initRateLimited.Add(1)
		return
	}
	select {
	case s.initSem <- struct{}{}:
	default:
		s.stats.initBusy.Add(1)
		return
	}
	go func() {
		defer func() { <-s.initSem }()
		s.handleInit(pkt, peer)
	}()
}

var errReject = errors.New("init rejected")

func (s *Server) reject(reason string) {
	s.stats.initRejected.Add(1)
	s.log.Info("init rejected", "reason", reason)
}

func (s *Server) handleInit(pkt []byte, peer netip.AddrPort) {
	now := s.now()
	init, err := sgwire.ParseInit(pkt)
	if err != nil {
		s.stats.malformed.Add(1)
		return
	}
	replayKey := sha256.Sum256(init.APReq)
	if s.replay.Seen(replayKey, now) {
		// A retransmitted init from the same console re-sends the cached response
		// so a lost reply does not strand it; anything else is a replay.
		if sess := s.sessionForInit(replayKey, peer); sess != nil {
			s.conn.WriteToUDPAddrPort(sess.initResp, peer)
			return
		}
		s.reject("replayed AP-REQ")
		return
	}
	if s.verifier == nil || s.dir == nil {
		s.reject("not configured")
		return
	}
	id, err := s.verifier.VerifyAPReq(init.APReq, now)
	if err != nil || id == nil {
		s.reject("ticket")
		return
	}
	if reason := s.checkIdentity(id, init, now); reason != "" {
		s.reject(reason)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.DirectoryWait)
	defer cancel()
	principal, err := s.dir.ResolveUser(ctx, id.XUID)
	if err != nil || !principal.Active || principal.PrincipalID == "" {
		s.reject("account")
		return
	}
	priv, pub, err := sgwire.GenerateDH(rand.Reader)
	if err != nil {
		s.reject("entropy")
		return
	}
	secret, err := priv.Secret(init.DHPublic[:])
	if err != nil {
		s.reject("dh")
		return
	}
	var gwNonce [8]byte
	if _, err := rand.Read(gwNonce[:]); err != nil {
		s.reject("entropy")
		return
	}
	keys := sgwire.DeriveKeys(id.SessionKey, secret, init.Nonce, gwNonce)

	sess := &Session{srv: s, peer: peer, keys: keys, initKey: replayKey, lastSeen: now,
		conns: map[tcpKey]*tcpConn{}, services: map[uint16]uint32{}, sendSeq: 1,
		bucket:   bucket{tokens: s.cfg.PacketBurst, last: now},
		identity: ConnIdentity{Principal: principal, XUID: id.XUID, TitleID: id.TitleID, Generation: s.gen.Add(1)}}
	for _, m := range id.Services {
		sess.services[m.Port] = m.ID
	}
	life := s.cfg.MaxLifetime
	if until := id.TicketEnd.Sub(now); until < life {
		life = until
	}
	sess.expires = now.Add(life)

	resp := sgwire.InitResponse{ClientSPI: init.SPI, ClientNonce: init.Nonce, GatewayNonce: gwNonce,
		XUID: id.XUID, ClientIP: peer.Addr().As4(), ClientPort: peer.Port(), GatewayDH: pub, GatewayDES: keys.SGToClient.DES,
		TimeoutSecs: uint16(s.cfg.IdleTimeout / time.Second), PulseSecs: 5}

	if !s.replay.Add(replayKey, now) {
		s.reject("replayed AP-REQ")
		return
	}
	if !s.register(sess, &resp) {
		s.reject("capacity")
		return
	}
	out, err := sgwire.BuildInitResponse(resp, id.SessionKey, id.BuildAPRep)
	if err != nil {
		s.unregister(sess)
		s.reject("response")
		return
	}
	sess.initResp = out
	s.stats.initAccepted.Add(1)
	s.lastHandshake.Store(now.Unix())
	s.conn.WriteToUDPAddrPort(out, peer)
}

func (s *Server) sessionForInit(key [32]byte, peer netip.AddrPort) *Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sess := range s.sessions {
		if sess.initKey == key && sess.peer == peer && sess.initResp != nil {
			return sess
		}
	}
	return nil
}

// checkIdentity applies the shared gateway policy to a verified identity.
func (s *Server) checkIdentity(id *Identity, init sgwire.Init, now time.Time) string {
	switch {
	case id.GatewayIP != s.cfg.AdvertiseIP:
		return "ticket targets a different gateway"
	case id.TicketEnd.IsZero() || !now.Before(id.TicketEnd) || now.Before(id.TicketStart) || !id.TicketEnd.After(id.TicketStart):
		return "ticket not currently valid"
	}
	skew := now.Sub(id.AuthTime)
	if skew > s.cfg.ClockSkew || skew < -s.cfg.ClockSkew {
		return "authenticator clock skew"
	}
	if subtle.ConstantTimeCompare(id.Checksum, sgwire.InitChecksum(id.SessionKey, init.SignedParameters)) != 1 {
		return "init checksum"
	}
	if id.BuildAPRep == nil || id.XUID == 0 {
		return "incomplete identity"
	}
	return ""
}

// register allocates an unpredictable SPI and enforces capacity limits.
func (s *Server) register(sess *Session, resp *sgwire.InitResponse) bool {
	ip := sess.peer.Addr()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sessions) >= s.cfg.MaxSessions || s.perIP[ip] >= s.cfg.MaxPerIP {
		return false
	}
	for try := 0; try < 16; try++ {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			return false
		}
		spi := sgwire.SPI{b[0], b[1], b[2]}
		if spi == (sgwire.SPI{}) || s.sessions[spi] != nil {
			continue
		}
		sess.spi = spi
		s.sessions[spi] = sess
		s.perIP[ip]++
		resp.GatewaySPI = spi.U32()
		return true
	}
	return false
}

func (s *Server) unregister(sess *Session) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions[sess.spi] != sess {
		return false
	}
	delete(s.sessions, sess.spi)
	if s.perIP[sess.peer.Addr()]--; s.perIP[sess.peer.Addr()] <= 0 {
		delete(s.perIP, sess.peer.Addr())
	}
	return true
}

// closeSession removes a session, tells the console, and releases its streams.
func (s *Server) closeSession(sess *Session, reason string, notify bool) {
	sess.mu.Lock()
	if sess.closed {
		sess.mu.Unlock()
		return
	}
	sess.closed = true
	if notify {
		if out, err := sgwire.DeleteNotice(deleteNormal); err == nil {
			sess.send(sgwire.OpControl, nil, out)
		}
	}
	for _, c := range sess.conns {
		c.shutdown()
	}
	sess.conns = nil
	sess.keys = sgwire.ConnectionKeys{}
	sess.mu.Unlock()
	s.unregister(sess)
	s.log.Debug("session closed", "reason", reason)
}

func (s *Server) closeAll() {
	s.mu.RLock()
	all := make([]*Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		all = append(all, sess)
	}
	s.mu.RUnlock()
	for _, sess := range all {
		s.closeSession(sess, "shutdown", false)
	}
}

// RevokePrincipal closes every session of a principal (xb-account revocation stream).
func (s *Server) RevokePrincipal(principalID string) int {
	s.mu.RLock()
	var hit []*Session
	for _, sess := range s.sessions {
		if sess.identity.Principal.PrincipalID == principalID {
			hit = append(hit, sess)
		}
	}
	s.mu.RUnlock()
	for _, sess := range hit {
		s.closeSession(sess, "revoked", true)
	}
	return len(hit)
}

// SessionCount reports live sessions.
func (s *Server) SessionCount() int { s.mu.RLock(); defer s.mu.RUnlock(); return len(s.sessions) }

func (s *Server) reap(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sweep()
		}
	}
}

func (s *Server) sweep() {
	now := s.now()
	s.mu.RLock()
	var dead []*Session
	var reasons []string
	for _, sess := range s.sessions {
		sess.mu.Lock()
		idle := now.Sub(sess.lastSeen) > s.cfg.IdleTimeout
		life := !now.Before(sess.expires)
		sess.mu.Unlock()
		if idle || life {
			dead = append(dead, sess)
			reasons = append(reasons, map[bool]string{true: "idle", false: "expired"}[idle])
		}
	}
	s.mu.RUnlock()
	for i, sess := range dead {
		s.closeSession(sess, reasons[i], true)
	}
	s.limiter.Prune(now)
	s.replay.Prune(now)
}
