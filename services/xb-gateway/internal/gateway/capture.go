// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// capture records decrypted SG payloads for protocol debugging. It exists only
// when Config.DebugCapture is explicitly enabled and a directory is configured;
// the file is private (0600) and size-capped. Never enable in production.
type capture struct {
	mu   sync.Mutex
	f    *os.File
	left int64
}

func newCapture(c Config) (*capture, error) {
	if !c.DebugCapture {
		return nil, nil
	}
	if err := os.MkdirAll(c.CaptureDir, 0o700); err != nil {
		return nil, err
	}
	name := filepath.Join(c.CaptureDir, "xb-gateway-"+time.Now().UTC().Format("20060102T150405Z")+".cap")
	f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &capture{f: f, left: c.CaptureMax}, nil
}

// record writes: u8 direction, u8 opcode, u32 spi, i64 unix nanos, u32 length, payload.
func (c *capture) record(toClient bool, op byte, spi uint32, payload []byte) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	need := int64(18 + len(payload))
	if c.left < need {
		return
	}
	c.left -= need
	rec := make([]byte, 18, 18+len(payload))
	if toClient {
		rec[0] = 1
	}
	rec[1] = op
	binary.LittleEndian.PutUint32(rec[2:], spi)
	binary.LittleEndian.PutUint64(rec[6:], uint64(time.Now().UnixNano()))
	binary.LittleEndian.PutUint32(rec[14:], uint32(len(payload)))
	c.f.Write(append(rec, payload...))
}

func (c *capture) Close() {
	if c != nil {
		c.f.Close()
	}
}
