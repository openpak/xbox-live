// SPDX-License-Identifier: AGPL-3.0-only
package kdc

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"openpak/xb-live/internal/krb"
)

const (
	maxDatagram    = 4096
	retransmitTTL  = 5 * time.Second
	retransmitMax  = 1024
	requestTimeout = 5 * time.Second
)

// Server serves KDC datagrams. The number of requests in flight is bounded so a
// flood cannot create unbounded resolver calls; excess datagrams are dropped.
// A byte-identical datagram from the same peer within five seconds receives the
// cached successful reply (UDP retransmission) instead of a replay error; the
// reply is encrypted for the requester so resending it to anyone leaks nothing.
type Server struct {
	KDC         *KDC
	Conn        net.PacketConn
	MaxInFlight int

	mu    sync.Mutex
	cache map[[32]byte]cached
}

type cached struct {
	reply []byte
	exp   time.Time
}

func (s *Server) lookup(key [32]byte, now time.Time) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.cache[key]; ok && now.Before(c.exp) {
		return c.reply
	}
	return nil
}

func (s *Server) store(key [32]byte, reply []byte, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cache == nil {
		s.cache = map[[32]byte]cached{}
	}
	if len(s.cache) >= retransmitMax {
		for k, c := range s.cache {
			if !now.Before(c.exp) {
				delete(s.cache, k)
			}
		}
		if len(s.cache) >= retransmitMax {
			return
		}
	}
	s.cache[key] = cached{reply, now.Add(retransmitTTL)}
}

// Serve reads until ctx is cancelled or the connection fails.
func (s *Server) Serve(ctx context.Context) error {
	limit := s.MaxInFlight
	if limit <= 0 {
		limit = 64
	}
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	defer wg.Wait()
	go func() { <-ctx.Done(); s.Conn.Close() }()
	buf := make([]byte, maxDatagram+1)
	for {
		n, peer, err := s.Conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if n > maxDatagram {
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			continue
		}
		pkt := append([]byte(nil), buf[:n]...)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			s.serve(ctx, pkt, peer)
		}()
	}
}

func (s *Server) serve(ctx context.Context, pkt []byte, peer net.Addr) {
	now := s.KDC.cfg.Now()
	key := hash([]byte(peer.String()), pkt)
	reply := s.lookup(key, now)
	if reply == nil {
		rctx, cancel := context.WithTimeout(ctx, requestTimeout)
		defer cancel()
		if reply = s.KDC.Handle(rctx, pkt); reply == nil {
			return
		}
		if !krb.IsError(reply) {
			s.store(key, reply, now)
		}
	}
	s.Conn.WriteTo(reply, peer)
}
