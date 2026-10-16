// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"net/netip"
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

func (b *bucket) allow(now time.Time, rate, burst float64) bool {
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = min(burst, b.tokens+elapsed*rate)
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// ipLimiter is a bounded per-source token-bucket table.
type ipLimiter struct {
	mu          sync.Mutex
	rate, burst float64
	max         int
	m           map[netip.Addr]*bucket
}

func newIPLimiter(rate, burst float64, max int) *ipLimiter {
	return &ipLimiter{rate: rate, burst: burst, max: max, m: map[netip.Addr]*bucket{}}
}

func (l *ipLimiter) Allow(ip netip.Addr, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.m[ip]
	if b == nil {
		if len(l.m) >= l.max {
			l.pruneLocked(now)
			if len(l.m) >= l.max {
				return false // table exhausted by distinct sources: fail closed
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.m[ip] = b
	}
	return b.allow(now, l.rate, l.burst)
}

func (l *ipLimiter) pruneLocked(now time.Time) {
	for ip, b := range l.m {
		if now.Sub(b.last) > 30*time.Second {
			delete(l.m, ip)
		}
	}
}
func (l *ipLimiter) Prune(now time.Time) { l.mu.Lock(); l.pruneLocked(now); l.mu.Unlock() }

// replayCache remembers accepted AP-REQs until they can no longer pass the skew check.
type replayCache struct {
	mu  sync.Mutex
	ttl time.Duration
	max int
	m   map[[32]byte]time.Time
}

func newReplayCache(ttl time.Duration, max int) *replayCache {
	return &replayCache{ttl: ttl, max: max, m: map[[32]byte]time.Time{}}
}
func (r *replayCache) Seen(k [32]byte, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	exp, ok := r.m[k]
	return ok && now.Before(exp)
}

// Add reports false if k is already present (replay) or the cache is full.
func (r *replayCache) Add(k [32]byte, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if exp, ok := r.m[k]; ok && now.Before(exp) {
		return false
	}
	if len(r.m) >= r.max {
		r.pruneLocked(now)
		if len(r.m) >= r.max {
			return false
		}
	}
	r.m[k] = now.Add(r.ttl)
	return true
}
func (r *replayCache) pruneLocked(now time.Time) {
	for k, exp := range r.m {
		if !now.Before(exp) {
			delete(r.m, k)
		}
	}
}
func (r *replayCache) Prune(now time.Time) { r.mu.Lock(); r.pruneLocked(now); r.mu.Unlock() }
