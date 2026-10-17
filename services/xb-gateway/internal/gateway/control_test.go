// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"encoding/binary"
	"testing"
	"time"

	"openpak/xb-live/internal/sgwire"
)

func TestDeliverPushSends0x5309(t *testing.T) {
	h := newHarness(t, nil)
	c := h.connect(nil)
	var xuid uint64
	h.srv.mu.RLock()
	for _, s := range h.srv.sessions {
		xuid = s.identity.XUID
	}
	h.srv.mu.RUnlock()
	words := []uint32{0x1234<<8 | 1, 0x9, 0x1235<<8 | 0x88}
	h.srv.deliverPush(xuid, words)
	h.srv.deliverPush(xuid+1, words) // another user: nothing
	var got []sgwire.Chunk
	for i := 0; i < 5 && got == nil; i++ {
		p := c.read(300 * time.Millisecond)
		if p == nil || p.Opcode != sgwire.OpControl {
			continue
		}
		ch, err := sgwire.ParseChunks(p.Payload)
		if err == nil && len(ch) == 1 && ch[0].Tag == sgwire.TagSgPulse && len(ch[0].Data) > 4 {
			got = ch
		}
	}
	if got == nil {
		t.Fatal("no 0x5309 push")
	}
	d := got[0].Data
	if lo, hi := binary.LittleEndian.Uint32(d[4:]), binary.LittleEndian.Uint32(d[8:]); uint64(hi)<<32|uint64(lo) != xuid {
		t.Fatalf("xuid in push %x/%x, want %x", hi, lo, xuid)
	}
	if len(d) != 4+8+4*len(words)+4 || binary.LittleEndian.Uint32(d[12:]) != words[0] || binary.LittleEndian.Uint32(d[len(d)-4:]) != 0 {
		t.Fatalf("push layout %x", d)
	}
}
