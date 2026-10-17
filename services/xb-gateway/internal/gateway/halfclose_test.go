// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"context"
	"testing"
	"time"

	"openpak/xb-live/internal/sgwire"
)

// delayedBackend answers a request only after the console half-closed and a
// pause, the way a feature service doing core calls does. delay < 0: never.
type delayedBackend struct{ delay time.Duration }

func (b delayedBackend) Open(_ context.Context, _ ConnContext, sink Sink) (Stream, error) {
	return &delayedStream{b: b, sink: sink}, nil
}

type delayedStream struct {
	b    delayedBackend
	sink Sink
	got  []byte
}

func (s *delayedStream) Receive(d []byte) error { s.got = append(s.got, d...); return nil }
func (s *delayedStream) Close()                 {}
func (s *delayedStream) CloseSend() {
	if s.b.delay < 0 {
		return
	}
	go func() {
		time.Sleep(s.b.delay)
		s.sink.Send(append([]byte("reply:"), s.got...))
		s.sink.Close()
	}()
}

// openConn does the handshake to service 107 and returns the console's next seq
// and the gateway's seq+1.
func openConn(t *testing.T, c *client) (seq, ack uint32) {
	syn := sgwire.TCPHeader{Src: 4000, Dst: 107, Seq: 1000, FlagsAndHeader: 6<<12 | sgwire.TCPSyn, Window: 8192}
	c.tcp(syn, []byte{2, 4, 0x05, 0x18})
	hd, _, ok := c.readTCP(time.Second)
	if !ok || hd.Flags() != sgwire.TCPSyn|sgwire.TCPAck {
		t.Fatalf("no SYN-ACK: %+v", hd)
	}
	c.tcp(sgwire.TCPHeader{Src: 4000, Dst: 107, Seq: 1001, Ack: hd.Seq + 1, FlagsAndHeader: 5<<12 | sgwire.TCPAck}, nil)
	return 1001, hd.Seq + 1
}

func TestConsoleFinIsHalfClose(t *testing.T) {
	h := newHarness(t, nil, func(s *Server) { s.backends[7] = delayedBackend{delay: 80 * time.Millisecond} })
	c := h.connect(nil)
	seq, ack := openConn(t, c)
	// Request and FIN in one segment (HTTP/1.0 client).
	c.tcp(sgwire.TCPHeader{Src: 4000, Dst: 107, Seq: seq, Ack: ack, FlagsAndHeader: 5<<12 | sgwire.TCPAck | sgwire.TCPFin | sgwire.TCPPsh}, []byte("req"))
	var data []byte
	var sawFin, acked bool
	var finSeq uint32
	for i := 0; i < 8 && !sawFin; i++ {
		hd, payload, ok := c.readTCP(time.Second)
		if !ok {
			t.Fatal("connection ended before the reply")
		}
		switch {
		case hd.Flags()&sgwire.TCPFin != 0:
			sawFin, finSeq = true, hd.Seq
			if len(data) == 0 {
				t.Fatal("FIN before the reply: the late reply would be lost")
			}
		case len(payload) > 0:
			if hd.Ack != seq+4 { // 3 data bytes + FIN
				t.Fatalf("data segment acks %d, want %d", hd.Ack, seq+4)
			}
			data = append(data, payload...)
		case hd.Flags() == sgwire.TCPAck && hd.Ack == seq+4:
			acked = true
		}
	}
	if !acked || string(data) != "reply:req" || !sawFin {
		t.Fatalf("acked=%v data=%q fin=%v", acked, data, sawFin)
	}
	if finSeq != ack+uint32(len(data)) {
		t.Fatalf("FIN seq %d, want %d", finSeq, ack+uint32(len(data)))
	}
}

func TestRetransmittedFinIsReAcked(t *testing.T) {
	h := newHarness(t, nil, func(s *Server) { s.backends[7] = delayedBackend{delay: 300 * time.Millisecond} })
	c := h.connect(nil)
	seq, ack := openConn(t, c)
	fin := sgwire.TCPHeader{Src: 4000, Dst: 107, Seq: seq, Ack: ack, FlagsAndHeader: 5<<12 | sgwire.TCPAck | sgwire.TCPFin | sgwire.TCPPsh}
	c.tcp(fin, []byte("req"))
	c.readTCP(time.Second) // the ACK
	c.tcp(fin, []byte("req"))
	hd, _, ok := c.readTCP(time.Second)
	if !ok || hd.Flags() != sgwire.TCPAck || hd.Ack != seq+4 {
		t.Fatalf("retransmitted FIN: %+v ok=%v", hd, ok)
	}
	// Data after the FIN is refused.
	c.tcp(sgwire.TCPHeader{Src: 4000, Dst: 107, Seq: seq + 4, Ack: ack, FlagsAndHeader: 5<<12 | sgwire.TCPAck | sgwire.TCPPsh}, []byte("late"))
	hd, _, ok = c.readTCP(time.Second)
	if !ok || hd.Flags()&sgwire.TCPRst == 0 {
		t.Fatalf("data after FIN: %+v ok=%v", hd, ok)
	}
}

func TestHalfCloseGraceDeadline(t *testing.T) {
	h := newHarness(t, nil, func(s *Server) { s.backends[7] = delayedBackend{delay: -1}; s.halfGrace = 250 * time.Millisecond })
	c := h.connect(nil)
	seq, ack := openConn(t, c)
	c.tcp(sgwire.TCPHeader{Src: 4000, Dst: 107, Seq: seq, Ack: ack, FlagsAndHeader: 5<<12 | sgwire.TCPAck | sgwire.TCPFin | sgwire.TCPPsh}, []byte("req"))
	c.readTCP(time.Second) // ACK
	start := time.Now()
	hd, _, ok := c.readTCP(2 * time.Second)
	if !ok || hd.Flags()&sgwire.TCPFin == 0 {
		t.Fatalf("no FIN at the deadline: %+v ok=%v", hd, ok)
	}
	if time.Since(start) < 150*time.Millisecond {
		t.Fatal("closed before the grace period")
	}
}
