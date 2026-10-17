// SPDX-License-Identifier: AGPL-3.0-only

package svc5

import (
	"context"
	"encoding/binary"
	"strings"

	"openpak/xb-live/internal/xbfeature"
)

// Service 1 (Presence): POST /xpnfront/xpresence.srf, Content-type xon/1. The
// body is the native presence message (layouts from the Xombie codec, libs/
// xblive/src/service/presence.rs, whose unit vectors are mirrored in
// presence_test.go): a 32-byte header (type u32, len u32, seq u32, SG address
// 20 bytes) followed by Alive (1001) or Alive2 (1025) and the NUL-terminated
// account name. The reply is AliveReply (1101) echoing seq and SG address.
//
// This answers honestly for what OpenPak has today: no friend or block list is
// kept for native consoles yet, so the reply carries version 0 and zero
// entries (xb-social is the future source), and the console's presence is not
// published anywhere. The signed-in XUID comes from the gateway-bound
// connection and must match the message.
const (
	msgAlive      = 1001
	msgAlive2     = 1025
	msgAliveReply = 1101

	presenceHeader = 32
	aliveBody      = 38 // XUID 8, title 4, name len 2, buddy ver 4, block ver 4, state 4, match id 8, nick len 2, title stuff len 2
	alive2Body     = 120
)

func (s *Server) presence(_ context.Context, info xbfeature.Info, body []byte) response {
	if len(body) < presenceHeader {
		return status(400)
	}
	typ := binary.LittleEndian.Uint32(body[0:4])
	n := int(binary.LittleEndian.Uint32(body[4:8]))
	if n != len(body)-presenceHeader {
		return status(400)
	}
	msg := body[presenceHeader:]
	var xuid uint64
	var nameLen int
	switch typ {
	case msgAlive:
		if len(msg) < aliveBody {
			return status(400)
		}
		xuid = binary.LittleEndian.Uint64(msg[0:8])
		nameLen = int(binary.LittleEndian.Uint16(msg[12:14]))
		// Nickname and title-specific data would follow the fixed part; the
		// client has not been seen sending them and we do not parse them.
		if binary.LittleEndian.Uint16(msg[34:36]) != 0 || binary.LittleEndian.Uint16(msg[36:38]) != 0 {
			return status(501)
		}
		msg = msg[aliveBody:]
	case msgAlive2:
		if len(msg) < alive2Body {
			return status(400)
		}
		xuid = binary.LittleEndian.Uint64(msg[0:8])
		nameLen = int(binary.LittleEndian.Uint16(msg[8:10]))
		msg = msg[alive2Body:]
	default:
		return status(501)
	}
	// The name length counts the terminating NUL (Xombie vector: 9 for "monocasa").
	if info.XUID == 0 || xuid != info.XUID || nameLen < 1 || len(msg) != nameLen || msg[nameLen-1] != 0 || strings.IndexByte(string(msg[:nameLen-1]), 0) >= 0 {
		return status(400)
	}
	// AliveReply: HRESULT 0, buddy list version 0, 0 buddies, block list version 0, 0 blocks.
	out := make([]byte, presenceHeader+16)
	binary.LittleEndian.PutUint32(out[0:], msgAliveReply)
	binary.LittleEndian.PutUint32(out[4:], 16)
	copy(out[8:presenceHeader], body[8:presenceHeader]) // seq + SG address echoed
	return response{code: 200, hasErr: true, body: out}
}
