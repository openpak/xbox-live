// SPDX-License-Identifier: AGPL-3.0-only

package ratelimit

import (
	"testing"
	"time"
)

func TestWindow(t *testing.T) {
	now := time.Unix(1000, 0)
	w := &Window{Max: 3, Per: time.Minute, Now: func() time.Time { return now }}
	for i := 0; i < 3; i++ {
		if !w.Allow("a") {
			t.Fatal("early deny")
		}
	}
	if w.Allow("a") || !w.Blocked("a") {
		t.Fatal("limit not enforced")
	}
	if !w.Allow("b") {
		t.Fatal("keys must be independent")
	}
	now = now.Add(61 * time.Second)
	if w.Blocked("a") || !w.Allow("a") {
		t.Fatal("window did not slide")
	}
	w.Hit("c")
	w.Hit("c")
	w.Hit("c")
	if !w.Blocked("c") {
		t.Fatal("hits not counted")
	}
}
