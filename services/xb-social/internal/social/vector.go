// SPDX-License-Identifier: AGPL-3.0-only

package social

import (
	"strconv"
	"sync"
	"time"
)

// Notifier keeps, per signed-in console user, the version-vector words the
// console reads to decide whether to poll (docs/xbox/social-protocol.md 2.3).
// Word layout: ver<<8 | index<<2 | (words-1); the console applies a word only
// when its version is higher than the stored one.
//
//	index 0, 2 words: [header, bits]  bits 0x1 list changed, 0x8 invitation, 0x10 answer
//	index 2, 1 word : presence marker, bit 7 set; a newer version means "poll presence"
type Notifier struct {
	// Emit delivers words to the gateway for the user; it must not block.
	Emit func(xuid uint64, words []uint32)

	mu    sync.Mutex
	seq   uint32
	users map[string]*nvec
}

type nvec struct{ verA, verP, bits uint32 }

const (
	vecList   uint32 = 0x1
	vecInvite uint32 = 0x8
	vecAnswer uint32 = 0x10
)

func (n *Notifier) next() uint32 {
	if n.seq == 0 {
		// Versions are 24 bit and must keep growing across restarts: seconds since 2026-09-01.
		n.seq = uint32(time.Now().Unix() - 1788220800)
	}
	n.seq++
	return n.seq & 0xffffff
}

func (n *Notifier) get(xuid string) *nvec {
	if n.users == nil {
		n.users = map[string]*nvec{}
	}
	v := n.users[xuid]
	if v == nil {
		v = &nvec{}
		n.users[xuid] = v
	}
	return v
}

func wordsOf(v *nvec) []uint32 {
	var w []uint32
	if v.verA != 0 {
		w = append(w, v.verA<<8|0<<2|1, v.bits)
	}
	if v.verP != 0 {
		w = append(w, v.verP<<8|0x80|2<<2)
	}
	return w
}

func (n *Notifier) send(xuid string, w []uint32) {
	x, err := strconv.ParseUint(xuid, 16, 64)
	if n.Emit != nil && err == nil && len(w) > 0 {
		n.Emit(x, w)
	}
}

// Apply records a Push (from PushSource) and delivers it.
func (n *Notifier) Apply(p Push) {
	n.mu.Lock()
	v := n.get(p.XUID)
	if p.Bits == PendingPresent {
		v.verP = n.next()
	} else {
		v.verA = n.next()
		v.bits |= map[uint32]uint32{PendingList1: vecList, PendingInvite: vecInvite, PendingAnswer: vecAnswer}[p.Bits]
	}
	w := wordsOf(v)
	n.mu.Unlock()
	n.send(p.XUID, w)
}

// Hello marks presence pending for a user who just signed in so the console polls it once.
func (n *Notifier) Hello(xuid string) { n.Apply(Push{XUID: xuid, Bits: PendingPresent}) }

// Take clears bit (a kind the console just polled) and returns the current words
// to put in the poll reply. The bit is only cleared with a higher version.
func (n *Notifier) Take(xuid string, bit uint32) []uint32 {
	n.mu.Lock()
	defer n.mu.Unlock()
	v := n.get(xuid)
	if bit != 0 && v.bits&bit != 0 {
		v.bits &^= bit
		v.verA = n.next()
	}
	return wordsOf(v)
}

// Forget drops a user's vector (sign-out); a later sign-in starts at a higher version.
func (n *Notifier) Forget(xuid string) {
	n.mu.Lock()
	delete(n.users, xuid)
	n.mu.Unlock()
}

// Bit constants for pollers.
const (
	BitList   = vecList
	BitInvite = vecInvite
	BitAnswer = vecAnswer
)
