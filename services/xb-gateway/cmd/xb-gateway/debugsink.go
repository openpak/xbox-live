// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"

	"openpak/xb-live/services/xb-gateway/internal/gateway"
)

// debugSink accepts a connection and discards what the console sends. It
// never sends a reply and exists only behind XBGW_DEBUG_SINK_SERVICES.
type debugSink struct{}

func (debugSink) Open(context.Context, gateway.ConnContext, gateway.Sink) (gateway.Stream, error) {
	return discard{}, nil
}

type discard struct{}

func (discard) Receive([]byte) error { return nil }
func (discard) Close()               {}
