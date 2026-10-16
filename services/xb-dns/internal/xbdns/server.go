// SPDX-License-Identifier: AGPL-3.0-only
package xbdns

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Counters are the only record of traffic; no client address or name is kept.
type Counters struct {
	Queries, Answered, NXDomain, Refused, FormErr, Dropped, RateLimited atomic.Uint64
}

// Limiter is a per-source token bucket with a bounded table.
type Limiter struct {
	mu     sync.Mutex
	rate   float64 // tokens per second
	burst  float64
	max    int
	bucket map[netip.Addr]*tb
}
type tb struct {
	tokens float64
	last   time.Time
}

func NewLimiter(rate float64, burst float64, maxSources int) *Limiter {
	return &Limiter{rate: rate, burst: burst, max: maxSources, bucket: map[netip.Addr]*tb{}}
}

func (l *Limiter) Allow(a netip.Addr, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.bucket[a]
	if b == nil {
		if len(l.bucket) >= l.max { // evict idle sources; if none, refuse new ones
			for k, v := range l.bucket {
				if now.Sub(v.last) > 10*time.Second {
					delete(l.bucket, k)
				}
			}
			if len(l.bucket) >= l.max {
				return false
			}
		}
		b = &tb{tokens: l.burst, last: now}
		l.bucket[a] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type Server struct {
	Table Table
	Lim   *Limiter
	C     Counters
}

// Serve reads datagrams until conn is closed.
func (s *Server) Serve(conn net.PacketConn) error {
	buf := make([]byte, MaxQuery+1)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			return err
		}
		s.C.Queries.Add(1)
		if ua, ok := from.(*net.UDPAddr); ok {
			if ip, ok := netip.AddrFromSlice(ua.IP); ok && !s.Lim.Allow(ip.Unmap(), time.Now()) {
				s.C.RateLimited.Add(1)
				continue
			}
		}
		resp, rc, hit := s.Table.Answer(buf[:n])
		switch {
		case resp == nil:
			s.C.Dropped.Add(1)
			continue
		case hit:
			s.C.Answered.Add(1)
		case rc == RcodeNXDomain:
			s.C.NXDomain.Add(1)
		case rc == RcodeRefused:
			s.C.Refused.Add(1)
		case rc == RcodeFormErr || rc == RcodeNotImp:
			s.C.FormErr.Add(1)
		}
		_, _ = conn.WriteTo(resp, from)
	}
}
