// SPDX-License-Identifier: AGPL-3.0-only

package svc5

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"openpak/xb-live/internal/xbfeature"
)

// Vectors from the Xombie presence codec tests (libs/xblive/src/service/
// presence.rs), the only public reference for these layouts.
const aliveHex = "e90300002f000000010000000a000064" + "00010000010000000000000000000000" +
	"3292446c907409000b00414c09000000" + "00000000000005000000000000000000" + "0000000000006d6f6e6f6361736100"

// alive2Message builds the Alive2 frame of the Xombie vector: header (type
// 0x401, length 0x81, seq 1, SG address), 120 fixed bytes starting with the
// XUID and the name length 9, then "monocasa\0".
func alive2Message(xuid uint64) []byte {
	b := make([]byte, presenceHeader+alive2Body+9)
	binary.LittleEndian.PutUint32(b[0:], 0x401)
	binary.LittleEndian.PutUint32(b[4:], 0x81)
	binary.LittleEndian.PutUint32(b[8:], 1)
	binary.LittleEndian.PutUint64(b[presenceHeader:], xuid)
	binary.LittleEndian.PutUint16(b[presenceHeader+8:], 9)
	copy(b[presenceHeader+alive2Body:], "monocasa")
	return b
}

func userInfo(xuid uint64) xbfeature.Info {
	return xbfeature.Info{PrincipalID: "0009d941ad372efd", CoreAccountID: "acct1", XUID: xuid, ServiceID: 1}
}

func TestPresenceAliveReplies(t *testing.T) {
	srv, _ := newServer(t)
	alive, _ := hex.DecodeString(aliveHex)
	for name, in := range map[string][]byte{"alive": alive} {
		r := do(t, srv, userInfo(0x000974906c449232), "POST", "/xpnfront/xpresence.srf", "xon/1", in)
		_, b, _ := strings.Cut(r, "\r\n\r\n")
		out := []byte(b)
		if !strings.Contains(r, "X-Err: 0\r\n") || len(out) != 48 ||
			binary.LittleEndian.Uint32(out[0:]) != 1101 || binary.LittleEndian.Uint32(out[4:]) != 16 ||
			string(out[8:32]) != string(in[8:32]) || strings.Count(string(out[32:]), "\x00") != 16 {
			t.Fatalf("%s: %q", name, r)
		}
	}
}

func TestPresenceAlive2Frame(t *testing.T) {
	srv, _ := newServer(t)
	r := do(t, srv, userInfo(0x000974906c449232), "POST", "/xpnfront/xpresence.srf", "xon/1", alive2Message(0x000974906c449232))
	if !strings.Contains(r, "X-Err: 0\r\n") {
		t.Fatal(r)
	}
}

func TestPresenceRejects(t *testing.T) {
	srv, _ := newServer(t)
	alive, _ := hex.DecodeString(aliveHex)
	wrongUser := do(t, srv, userInfo(5), "POST", "/xpnfront/xpresence.srf", "xon/1", alive)
	noUser := do(t, srv, xbfeature.Info{ServiceID: 1}, "POST", "/xpnfront/xpresence.srf", "xon/1", alive)
	badLen := do(t, srv, userInfo(0x000974906c449232), "POST", "/xpnfront/xpresence.srf", "xon/1", alive[:len(alive)-1])
	wrongType := do(t, srv, userInfo(0x000974906c449232), "POST", "/xpnfront/xpresence.srf", "xon/5", alive)
	for n, r := range map[string]string{"user mismatch": wrongUser, "no user": noUser, "short": badLen, "content type": wrongType} {
		if strings.Contains(r, "X-Err: 0") {
			t.Fatalf("%s accepted: %q", n, r)
		}
	}
	if !strings.HasPrefix(noUser, "HTTP/1.0 403") || !strings.HasPrefix(wrongUser, "HTTP/1.0 400") {
		t.Fatalf("%q %q", noUser, wrongUser)
	}
}
