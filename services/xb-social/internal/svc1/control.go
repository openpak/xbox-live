// SPDX-License-Identifier: AGPL-3.0-only

package svc1

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"sync"
	"time"

	"openpak/xb-live/internal/xbfeature"
	"openpak/xb-live/services/xb-social/internal/social"
)

// Control serves the gateway's control stream (xbfeature.ControlServiceID):
// it relays state-version pushes to the gateway and applies the session facts
// the gateway reports (docs/xbox/social-protocol.md 8). Register it in
// Server.Others[xbfeature.ControlServiceID] and set Notifier.Emit to Control.Emit.
type Control struct {
	Presence *social.Presences
	Notifier *social.Notifier
	TTL      time.Duration

	mu    sync.Mutex
	conns map[*ctlConn]struct{}
}

type ctlConn struct {
	mu sync.Mutex
	c  xbfeature.Conn
}

func (c *ctlConn) send(b []byte) error { c.mu.Lock(); defer c.mu.Unlock(); return c.c.Send(b) }

// Emit sends words to every attached gateway. It does not block on a slow one for long.
func (c *Control) Emit(xuid uint64, words []uint32) {
	frame := xbfeature.ControlPush{XUID: xuid, Words: words}.Marshal()
	c.mu.Lock()
	var cs []*ctlConn
	for k := range c.conns {
		cs = append(cs, k)
	}
	c.mu.Unlock()
	for _, k := range cs {
		go func() {
			if err := k.send(frame); err != nil {
				log.Printf("control: push failed: %v", err)
			}
		}()
	}
}

func (c *Control) Serve(ctx context.Context, info xbfeature.Info, conn xbfeature.Conn) error {
	k := &ctlConn{c: conn}
	c.mu.Lock()
	if c.conns == nil {
		c.conns = map[*ctlConn]struct{}{}
	}
	c.conns[k] = struct{}{}
	c.mu.Unlock()
	log.Printf("control: gateway attached")
	defer func() {
		c.mu.Lock()
		delete(c.conns, k)
		c.mu.Unlock()
		log.Printf("control: gateway detached")
	}()
	for {
		raw, err := conn.Recv()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		var ev xbfeature.ControlEvent
		if json.Unmarshal(raw, &ev) != nil || ev.XUID == 0 || ev.Account == "" {
			continue
		}
		switch ev.Type {
		case "alive":
			c.Presence.Touch(ev.Account, ev.Generation, c.TTL)
		case "closed":
			dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			if err := c.Presence.Disconnect(dctx, ev.Account, ev.Generation); err != nil {
				log.Printf("control: disconnect: %v", err)
			}
			cancel()
		}
	}
}
