package svc1

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"testing"
	"time"

	"openpak/xb-live/internal/xbfeature"
)

type fakeConn struct {
	in   chan []byte
	mu   sync.Mutex
	sent [][]byte
}

func (f *fakeConn) Recv() ([]byte, error) {
	b, ok := <-f.in
	if !ok {
		return nil, io.EOF
	}
	return b, nil
}
func (f *fakeConn) Send(b []byte) error {
	f.mu.Lock()
	f.sent = append(f.sent, b)
	f.mu.Unlock()
	return nil
}

func TestControlRelaysPushes(t *testing.T) {
	c := &Control{}
	fc := &fakeConn{in: make(chan []byte)}
	done := make(chan struct{})
	go func() {
		c.Serve(context.Background(), xbfeature.Info{XUID: 1, ServiceID: xbfeature.ControlServiceID}, fc)
		close(done)
	}()
	for i := 0; i < 50; i++ {
		c.mu.Lock()
		n := len(c.conns)
		c.mu.Unlock()
		if n == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	c.Emit(0x42, []uint32{7, 8})
	for i := 0; i < 50; i++ {
		fc.mu.Lock()
		n := len(fc.sent)
		fc.mu.Unlock()
		if n == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	fc.mu.Lock()
	defer fc.mu.Unlock()
	var p xbfeature.ControlPush
	if len(fc.sent) != 1 || json.Unmarshal(fc.sent[0], &p) != nil || p.XUID != 0x42 || len(p.Words) != 2 || p.Words[1] != 8 {
		t.Fatalf("pushed %q", fc.sent)
	}
	close(fc.in)
	<-done
}
