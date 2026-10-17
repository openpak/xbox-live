// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"sync"
	"time"

	"openpak/xb-live/internal/sgwire"
	"openpak/xb-live/internal/xbfeature"
)

// presenceServiceID is the service whose sessions are reported as alive/closed:
// the console holds exactly one such session per signed-in user.
const presenceServiceID = 1

const controlAliveEvery = 15 * time.Second

// ControlLink is the gateway's long-lived stream to a feature service (see
// xbfeature.ControlServiceID). The gateway relays only: pushes in, transport
// facts out; it holds no friend or presence state.
type ControlLink struct {
	Backend *GRPCBackend

	mu sync.Mutex
	st *xbfeature.Stream
}

// Send writes one event frame if the link is up.
func (l *ControlLink) Send(ev xbfeature.ControlEvent) {
	l.mu.Lock()
	st := l.st
	l.mu.Unlock()
	if st != nil {
		_ = st.Send(ev.Marshal())
	}
}

// Run keeps the stream open, reconnecting with a delay, until ctx ends.
func (l *ControlLink) Run(ctx context.Context, srv *Server) {
	for ctx.Err() == nil {
		closed := make(chan struct{})
		octx, cancel := context.WithTimeout(ctx, 5*time.Second)
		st, err := xbfeature.Open(octx, l.Backend.conn, xbfeature.Info{XUID: xbfeature.ControlXUID, ServiceID: xbfeature.ControlServiceID},
			func(b []byte) error {
				var p xbfeature.ControlPush
				if json.Unmarshal(b, &p) == nil && p.XUID != 0 {
					srv.deliverPush(p.XUID, p.Words)
				}
				return nil
			}, func() { close(closed) })
		cancel()
		if err == nil {
			l.mu.Lock()
			l.st = st
			l.mu.Unlock()
			srv.log.Info("control link up")
			select {
			case <-closed:
			case <-ctx.Done():
				st.Abort()
			}
			l.mu.Lock()
			l.st = nil
			l.mu.Unlock()
			srv.log.Info("control link down")
		}
		select {
		case <-ctx.Done():
		case <-time.After(3 * time.Second):
		}
	}
}

// deliverPush sends an SG 0x5309 message to every session of the console user.
// Layout (docs/xbox/social-protocol.md 2.3): u32 message version, then one
// entry per user: xuid (two u32), the version words, a zero word.
func (s *Server) deliverPush(xuid uint64, words []uint32) {
	if len(words) == 0 || len(words) > 64 {
		return
	}
	s.mu.RLock()
	var hit []*Session
	for _, sess := range s.sessions {
		if sess.identity.XUID == xuid {
			hit = append(hit, sess)
		}
	}
	s.mu.RUnlock()
	for _, sess := range hit {
		sess.mu.Lock()
		if !sess.closed {
			sess.pushSeq++
			d := binary.LittleEndian.AppendUint32(nil, sess.pushSeq)
			d = binary.LittleEndian.AppendUint32(d, uint32(xuid))
			d = binary.LittleEndian.AppendUint32(d, uint32(xuid>>32))
			for _, w := range words {
				d = binary.LittleEndian.AppendUint32(d, w)
			}
			d = binary.LittleEndian.AppendUint32(d, 0)
			if out, err := sgwire.MarshalChunks([]sgwire.Chunk{{Tag: sgwire.TagSgPulse, Data: d}}); err == nil {
				sess.send(sgwire.OpControl, nil, out)
				s.frameLog("push", "gen", sess.identity.Generation, "words", len(words))
			}
		}
		sess.mu.Unlock()
	}
}

// controlEvent reports a presence-service session fact to the feature service.
func (s *Server) controlEvent(typ string, sess *Session) {
	l := s.control
	if l == nil || sess.identity.XUID == 0 || sess.identity.Principal.CoreAccountID == "" {
		return
	}
	hasPresence := false
	for _, id := range sess.services {
		if id == presenceServiceID {
			hasPresence = true
		}
	}
	if hasPresence {
		l.Send(xbfeature.ControlEvent{Type: typ, XUID: sess.identity.XUID, Account: sess.identity.Principal.CoreAccountID, Generation: sess.identity.Generation})
	}
}

// aliveTick reports every live presence session; called from the sweep.
func (s *Server) aliveTick(now time.Time) {
	if s.control == nil || now.Sub(s.lastAlive) < controlAliveEvery {
		return
	}
	s.lastAlive = now
	s.mu.RLock()
	var live []*Session
	for _, sess := range s.sessions {
		sess.mu.Lock()
		ok := !sess.closed && now.Sub(sess.lastSeen) < 3*controlAliveEvery
		sess.mu.Unlock()
		if ok {
			live = append(live, sess)
		}
	}
	s.mu.RUnlock()
	for _, sess := range live {
		s.controlEvent("alive", sess)
	}
}
