// SPDX-License-Identifier: AGPL-3.0-only

package social

import (
	"context"
	"log"
	"time"
)

// RosterWatcher tells signed-in consoles when their friend list changed in a
// way core announces no event for (a friend renamed their account: the gamertag
// is read live from the core link). It recomputes each online user's roster
// version on an interval and pushes a list-change when it moved.
type RosterWatcher struct {
	Svc      *Service
	Presence *Presences
	Notifier *Notifier

	last map[string]uint32
}

// Pass checks every online user once.
func (w *RosterWatcher) Pass(ctx context.Context) {
	if w.last == nil {
		w.last = map[string]uint32{}
	}
	online := w.Presence.Online()
	for account, xuid := range online {
		r, err := w.Svc.RosterOf(ctx, account)
		if err != nil {
			continue
		}
		old, seen := w.last[xuid]
		w.last[xuid] = r.BuddyVersion
		if seen && old != r.BuddyVersion {
			log.Printf("roster watch: list of %s changed (%d -> %d), pushing", xuid, old, r.BuddyVersion)
			w.Notifier.Apply(Push{XUID: xuid, Bits: PendingList1})
		}
	}
	for x := range w.last {
		found := false
		for _, o := range online {
			if o == x {
				found = true
			}
		}
		if !found {
			delete(w.last, x)
		}
	}
}

// Run calls Pass every interval until ctx ends.
func (w *RosterWatcher) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.Pass(ctx)
		}
	}
}
