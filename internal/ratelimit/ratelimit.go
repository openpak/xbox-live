// SPDX-License-Identifier: AGPL-3.0-only

// Package ratelimit is a small in-memory sliding-window limiter keyed by
// string (client IP, machine ID, account). State is per process and lost on
// restart, which is acceptable for abuse limiting. The key table is bounded:
// when it is full of live keys, new keys are refused (fail closed).
package ratelimit

import (
	"sync"
	"time"
)

const maxKeys = 100000

// Window allows at most Max events per Per for each key.
type Window struct {
	Max int
	Per time.Duration
	Now func() time.Time // tests

	mu sync.Mutex
	m  map[string][]time.Time
}

func New(max int, per time.Duration) *Window { return &Window{Max: max, Per: per} }

func (w *Window) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

// prune drops expired events of key (and empties the key); callers hold mu.
func (w *Window) prune(key string, now time.Time) []time.Time {
	ev := w.m[key]
	i := 0
	for i < len(ev) && !ev[i].After(now.Add(-w.Per)) {
		i++
	}
	ev = ev[i:]
	if len(ev) == 0 {
		delete(w.m, key)
		return nil
	}
	w.m[key] = ev
	return ev
}

func (w *Window) sweep(now time.Time) {
	for k := range w.m {
		w.prune(k, now)
	}
}

// Allow records an event for key and reports whether it is within the limit.
// Denied events are not recorded, so a blocked caller recovers on schedule.
func (w *Window) Allow(key string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	if w.m == nil {
		w.m = map[string][]time.Time{}
	}
	ev := w.prune(key, now)
	if len(ev) >= w.Max {
		return false
	}
	if len(ev) == 0 && len(w.m) >= maxKeys {
		w.sweep(now)
		if len(w.m) >= maxKeys {
			return false
		}
	}
	w.m[key] = append(ev, now)
	return true
}

// Blocked reports whether key is at its limit, without recording anything.
func (w *Window) Blocked(key string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.m == nil {
		return false
	}
	return len(w.prune(key, w.now())) >= w.Max
}

// Hit records an event unconditionally (used for failures after Blocked).
func (w *Window) Hit(key string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.m == nil {
		w.m = map[string][]time.Time{}
	}
	now := w.now()
	ev := w.prune(key, now)
	if len(ev) == 0 && len(w.m) >= maxKeys {
		w.sweep(now)
		if len(w.m) >= maxKeys {
			return
		}
	}
	if len(ev) < 4*w.Max {
		w.m[key] = append(ev, now)
	}
}
