// SPDX-License-Identifier: AGPL-3.0-only

package xbfeature

import (
	"encoding/json"
)

// The control channel is one long-lived stream the gateway opens to a feature
// service with ServiceID = ControlServiceID (and a placeholder XUID, because
// the stream contract requires one). It is not a console connection and the
// gateway keeps no feature state: it only relays.
//
//	service -> gateway: ControlPush frames (JSON): "deliver these state-version
//	                    words to the console signed in as XUID"
//	gateway -> service: ControlEvent frames (JSON): transport facts about SG
//	                    sessions ("alive" while the session is live, "closed" once)
const (
	ControlServiceID = 0x100
	ControlXUID      = 1 // placeholder identity of the control stream
)

// ControlPush asks the gateway to send an SG 0x5309 state-version message.
// Words are the console's per-user version-vector words (docs/xbox/social-protocol.md 2.3).
type ControlPush struct {
	XUID  uint64   `json:"xuid"`
	Words []uint32 `json:"words"`
}

// ControlEvent reports an SG session fact. Account is the core account the
// gateway admitted for the ticket; Generation identifies the SG session.
type ControlEvent struct {
	Type       string `json:"type"` // "alive" | "closed"
	XUID       uint64 `json:"xuid"`
	Account    string `json:"account"`
	Generation uint64 `json:"generation"`
}

func (p ControlPush) Marshal() []byte  { b, _ := json.Marshal(p); return b }
func (e ControlEvent) Marshal() []byte { b, _ := json.Marshal(e); return b }
