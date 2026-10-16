// SPDX-License-Identifier: AGPL-3.0-only
package kdc

import (
	"errors"
	"sync"
	"time"
)

var (
	ErrReplay = errors.New("replayed request")
	ErrFull   = errors.New("replay cache full")
)

// ReplayCache remembers authenticated request digests for at least `ttl`.
// It keeps two generations so memory is bounded by `max` and every entry
// survives at least ttl and at most 2*ttl. When full it refuses new entries
// (fail closed); it never evicts live ones, because eviction would reopen
// replay.
type ReplayCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	max     int
	rotated time.Time
	cur     map[[32]byte]struct{}
	prev    map[[32]byte]struct{}
}

func NewReplayCache(ttl time.Duration, max int) *ReplayCache {
	return &ReplayCache{ttl: ttl, max: max, cur: map[[32]byte]struct{}{}, prev: map[[32]byte]struct{}{}}
}

// CheckAndAdd records key, or returns ErrReplay if it is already present.
func (c *ReplayCache) CheckAndAdd(key [32]byte, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.rotated.IsZero():
		c.rotated = now
	case now.Sub(c.rotated) >= 2*c.ttl:
		c.prev, c.cur, c.rotated = map[[32]byte]struct{}{}, map[[32]byte]struct{}{}, now
	case now.Sub(c.rotated) >= c.ttl:
		c.prev, c.cur, c.rotated = c.cur, map[[32]byte]struct{}{}, now
	}
	if _, ok := c.cur[key]; ok {
		return ErrReplay
	}
	if _, ok := c.prev[key]; ok {
		return ErrReplay
	}
	if len(c.cur)+len(c.prev) >= c.max {
		return ErrFull
	}
	c.cur[key] = struct{}{}
	return nil
}
