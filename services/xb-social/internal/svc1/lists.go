// SPDX-License-Identifier: AGPL-3.0-only

package svc1

import (
	"encoding/binary"
	"log"
	"strconv"

	"openpak/xb-live/services/xb-social/internal/social"
)

// Entry limits and status values of AliveReply payloads (docs/xbox/
// social-protocol.md 1.1). A zero XUID or an empty name makes the console's
// whole logon fail (0x80150007), so such entries are never written.
const (
	maxBuddies = 100
	maxBlocks  = 250

	statusFriend          = 0
	statusRequestSent     = 1
	statusRequestReceived = 2
)

// WireLists is the AliveReply payload encoder: buddy entries (xuid u64,
// name_len u16, status u8, name) then block entries (xuid u64).
type WireLists struct{}

func (WireLists) AliveLists(r *social.Roster, sendBuddies, sendBlocks bool) ([]byte, uint16, uint16, error) {
	var data []byte
	var nb, nl uint16
	if sendBuddies {
		add := func(xuid, name string, status byte) {
			x, err := strconv.ParseUint(xuid, 16, 64)
			if err != nil || x == 0 || len(name) < 1 || len(name) > 16 || nb >= maxBuddies {
				if nb >= maxBuddies {
					log.Printf("svc1: buddy list over %d, truncated", maxBuddies)
				}
				return
			}
			data = binary.LittleEndian.AppendUint64(data, x)
			data = binary.LittleEndian.AppendUint16(data, uint16(len(name)))
			data = append(data, status)
			data = append(data, name...)
			nb++
		}
		for _, f := range r.Friends {
			add(f.XUID, f.Gamertag, statusFriend)
		}
		for _, c := range r.Incoming {
			add(c.XUID, c.Gamertag, statusRequestReceived)
		}
		for _, c := range r.Outgoing {
			add(c.XUID, c.Gamertag, statusRequestSent)
		}
	}
	if sendBlocks {
		for _, c := range r.Blocked {
			x, err := strconv.ParseUint(c.XUID, 16, 64)
			if err != nil || x == 0 || nl >= maxBlocks {
				continue
			}
			data = binary.LittleEndian.AppendUint64(data, x)
			nl++
		}
	}
	return data, nb, nl, nil
}
