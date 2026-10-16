// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"openpak/xb-live/internal/sgwire"
)

var advertise = netip.MustParseAddr("203.0.113.5")

type fakeVerifier struct {
	mu       sync.Mutex
	identity Identity
	err      error
	calls    int
}

func (f *fakeVerifier) VerifyAPReq(apReq []byte, now time.Time) (*Identity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	id := f.identity
	return &id, nil
}

type fakeDir struct{ p Principal }

func (d fakeDir) ResolveUser(ctx context.Context, xuid uint64) (Principal, error) {
	if !d.p.Active {
		return d.p, nil
	}
	return d.p, nil
}

type echoBackend struct {
	mu      sync.Mutex
	ctxs    []ConnContext
	err     error
	got     chan []byte
	sinkOut Sink
}

func (e *echoBackend) setErr(err error) { e.mu.Lock(); e.err = err; e.mu.Unlock() }

func (e *echoBackend) Open(ctx context.Context, cc ConnContext, sink Sink) (Stream, error) {
	e.mu.Lock()
	if e.err != nil {
		defer e.mu.Unlock()
		return nil, e.err
	}
	e.ctxs = append(e.ctxs, cc)
	e.sinkOut = sink
	e.mu.Unlock()
	return &echoStream{e: e, sink: sink}, nil
}

type echoStream struct {
	e    *echoBackend
	sink Sink
}

func (s *echoStream) Receive(data []byte) error {
	s.e.got <- append([]byte(nil), data...)
	return s.sink.Send(append([]byte("echo:"), data...))
}
func (s *echoStream) Close() {}

type harness struct {
	t        *testing.T
	srv      *Server
	verifier *fakeVerifier
	backend  *echoBackend
	cancel   context.CancelFunc
	done     chan struct{}
	clock    func() time.Time
	mu       sync.Mutex
	offset   time.Duration
}

func newHarness(t *testing.T, mut func(*Config), pre ...func(*Server)) *harness {
	t.Helper()
	cfg := DefaultConfig()
	cfg.BindAddr = netip.MustParseAddrPort("127.0.0.1:0")
	cfg.AdvertiseIP = advertise
	cfg.InitRate, cfg.InitBurst = 1000, 1000
	if mut != nil {
		mut(&cfg)
	}
	h := &harness{t: t, verifier: &fakeVerifier{}, backend: &echoBackend{got: make(chan []byte, 16)}}
	srv, err := NewServer(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), h.verifier,
		fakeDir{Principal{PrincipalID: "00000000000000aa", CoreAccountID: "core-1", Active: true}},
		map[uint32]Backend{7: h.backend})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pre {
		p(srv)
	}
	srv.now = func() time.Time { h.mu.Lock(); defer h.mu.Unlock(); return time.Now().Add(h.offset) }
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.srv, h.cancel, h.done = srv, cancel, make(chan struct{})
	go func() { srv.Serve(ctx); close(h.done) }()
	t.Cleanup(func() { cancel(); <-h.done })
	return h
}

func (h *harness) advance(d time.Duration) { h.mu.Lock(); h.offset += d; h.mu.Unlock() }

type client struct {
	t     *testing.T
	conn  *net.UDPConn
	keys  sgwire.ConnectionKeys
	spi   sgwire.SPI
	seq   uint32
	init  []byte
	reply []byte
}

var sessionKey = [16]byte{9, 8, 7, 6, 5, 4, 3, 2, 1, 1, 2, 3, 4, 5, 6, 7}

func buildInit(t *testing.T, spi uint32) (datagram []byte, priv *sgwire.DHPrivate, nonce [8]byte) {
	priv, pub, err := sgwire.GenerateDH(nil)
	if err != nil {
		t.Fatal(err)
	}
	rand.Read(nonce[:])
	body := binary.LittleEndian.AppendUint16(nil, 0)
	body = binary.LittleEndian.AppendUint16(body, 2)
	body = binary.LittleEndian.AppendUint32(body, spi)
	body = append(body, nonce[:]...)
	body = binary.LittleEndian.AppendUint32(body, 0)
	apreq := make([]byte, 40)
	rand.Read(apreq)
	chunks, err := sgwire.MarshalChunks([]sgwire.Chunk{{Tag: sgwire.TagInit, Data: body}, {Tag: sgwire.TagDH, Data: pub[:]},
		{Tag: sgwire.TagAPReq, Data: apreq}, {Tag: sgwire.TagPadding, Data: make([]byte, 8)}})
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte{0, 0, 0, 0}, chunks...), priv, nonce
}

func (h *harness) identityFor(datagram []byte, now time.Time) Identity {
	init, err := sgwire.ParseInit(datagram)
	if err != nil {
		h.t.Fatal(err)
	}
	return Identity{XUID: 0xaa, TitleID: 0x4d530004, SessionKey: sessionKey, GatewayIP: advertise,
		Services:    []ServiceMapping{{ID: 7, Port: 107}, {ID: 9, Port: 109}},
		TicketStart: now.Add(-time.Hour), TicketEnd: now.Add(time.Hour), AuthTime: now,
		Checksum: sgwire.InitChecksum(sessionKey, init.SignedParameters), KeyID: "k1",
		BuildAPRep: func(sub []byte) ([]byte, error) { return append([]byte("aprep:"), sub[:4]...), nil }}
}

func (h *harness) dial() *net.UDPConn {
	c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(h.srv.Addr()))
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { c.Close() })
	return c
}

func recv(c *net.UDPConn, wait time.Duration) []byte {
	c.SetReadDeadline(time.Now().Add(wait))
	b := make([]byte, 2048)
	n, err := c.Read(b)
	if err != nil {
		return nil
	}
	return b[:n]
}

// connect performs a full native handshake. It returns nil if no response arrives.
func (h *harness) connect(mut func(*Identity)) *client {
	h.t.Helper()
	conn := h.dial()
	datagram, priv, nonce := buildInit(h.t, 0x59a300)
	id := h.identityFor(datagram, time.Now().Add(h.offset))
	if mut != nil {
		mut(&id)
	}
	h.verifier.mu.Lock()
	h.verifier.identity = id
	h.verifier.mu.Unlock()
	conn.Write(datagram)
	reply := recv(conn, 400*time.Millisecond)
	if reply == nil {
		return nil
	}
	chunks, err := sgwire.ParseChunks(reply[4:])
	if err != nil || len(chunks) != 3 || chunks[0].Tag != sgwire.TagResponse || chunks[2].Tag != sgwire.TagAPRep {
		h.t.Fatalf("bad init response: %v", err)
	}
	if !bytes.HasPrefix(chunks[2].Data, []byte("aprep:")) {
		h.t.Fatal("AP-REP builder not used")
	}
	secret, err := priv.Secret(chunks[1].Data)
	if err != nil {
		h.t.Fatal(err)
	}
	body := chunks[0].Data
	var gwNonce [8]byte
	copy(gwNonce[:], body[20:28])
	if !bytes.Equal(body[12:20], nonce[:]) {
		h.t.Fatal("client nonce not echoed")
	}
	keys := sgwire.DeriveKeys(sessionKey, secret, nonce, gwNonce)
	// The gateway encrypts bytes 0x20..0x40 of the key-exchange chunk; decrypt to check the peer address.
	block, _ := des.NewTripleDESCipher(keys.SGToClient.DES[:])
	whole := bytes.Clone(reply[4 : 4+0x40])
	cipher.NewCBCDecrypter(block, gwNonce[:]).CryptBlocks(whole[0x20:], whole[0x20:])
	if !bytes.Equal(whole[52:56], conn.LocalAddr().(*net.UDPAddr).IP.To4()) {
		h.t.Fatal("client address not reported in encrypted section")
	}
	gwSPI := binary.LittleEndian.Uint32(body[8:12])
	return &client{t: h.t, conn: conn, keys: keys, spi: sgwire.SPIFromU32(gwSPI), seq: 0, init: datagram, reply: reply}
}

func (c *client) send(op sgwire.Opcode, footer, payload []byte) {
	c.seq++
	pkt, err := sgwire.Seal(c.keys.ClientToSG, op, c.spi, c.seq, payload, footer)
	if err != nil {
		c.t.Fatal(err)
	}
	c.conn.Write(pkt)
}
func (c *client) sendRaw(seq uint32, op sgwire.Opcode, footer, payload []byte) {
	pkt, _ := sgwire.Seal(c.keys.ClientToSG, op, c.spi, seq, payload, footer)
	c.conn.Write(pkt)
}
func (c *client) read(wait time.Duration) *sgwire.Packet {
	b := recv(c.conn, wait)
	if b == nil {
		return nil
	}
	p, err := sgwire.Open(b, c.keys.SGToClient, 0)
	if err != nil {
		c.t.Fatalf("gateway packet did not authenticate: %v", err)
	}
	return &p
}
func (c *client) tcp(h sgwire.TCPHeader, payload []byte) {
	op, footer := h.Marshal()
	c.send(op, footer, payload)
}
func (c *client) readTCP(wait time.Duration) (sgwire.TCPHeader, []byte, bool) {
	p := c.read(wait)
	if p == nil || p.Opcode == sgwire.OpControl {
		return sgwire.TCPHeader{}, nil, false
	}
	hd, err := sgwire.ParseTCPHeader(p.Opcode, p.Footer)
	if err != nil {
		c.t.Fatal(err)
	}
	return hd, p.Payload, true
}

func TestHandshakePulseAndNoKeyReuse(t *testing.T) {
	h := newHarness(t, nil)
	a, b := h.connect(nil), h.connect(nil)
	if a == nil || b == nil {
		t.Fatal("handshake failed")
	}
	if a.spi == b.spi || a.keys == b.keys {
		t.Fatal("sessions share SPI or keys")
	}
	if h.srv.SessionCount() != 2 {
		t.Fatal("expected two sessions")
	}
	ping, _ := sgwire.MarshalChunks([]sgwire.Chunk{{Tag: sgwire.TagXbPulse, Data: []byte{7, 0, 0, 0}}})
	a.send(sgwire.OpControl, nil, ping)
	p := a.read(time.Second)
	if p == nil || p.Opcode != sgwire.OpControl {
		t.Fatal("no pulse reply")
	}
	chunks, _ := sgwire.ParseChunks(p.Payload)
	if len(chunks) != 1 || chunks[0].Tag != sgwire.TagSgPulse || binary.LittleEndian.Uint32(chunks[0].Data) != 7 {
		t.Fatal("wrong pulse reply")
	}
	if h.srv.lastHandshake.Load() == 0 {
		t.Fatal("e2e observation missing")
	}
}

func TestInitRejections(t *testing.T) {
	cases := map[string]func(*Identity){
		"wrong gateway":        func(i *Identity) { i.GatewayIP = netip.MustParseAddr("198.51.100.1") },
		"expired ticket":       func(i *Identity) { i.TicketEnd = time.Now().Add(-time.Second) },
		"future ticket":        func(i *Identity) { i.TicketStart = time.Now().Add(time.Minute) },
		"stale authenticator":  func(i *Identity) { i.AuthTime = time.Now().Add(-10 * time.Minute) },
		"future authenticator": func(i *Identity) { i.AuthTime = time.Now().Add(10 * time.Minute) },
		"bad checksum":         func(i *Identity) { i.Checksum = make([]byte, 20) },
		"no aprep":             func(i *Identity) { i.BuildAPRep = nil },
		"zero xuid":            func(i *Identity) { i.XUID = 0 },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, nil)
			if c := h.connect(mut); c != nil {
				t.Fatal("handshake accepted")
			}
			if h.srv.SessionCount() != 0 {
				t.Fatal("session created")
			}
		})
	}
	t.Run("verifier error", func(t *testing.T) {
		h := newHarness(t, nil)
		h.verifier.err = ErrUnauthenticated
		if h.connect(nil) != nil {
			t.Fatal("accepted")
		}
	})
	t.Run("inactive account", func(t *testing.T) {
		h := newHarness(t, nil, func(s *Server) { s.dir = fakeDir{Principal{PrincipalID: "x", Active: false}} })
		if h.connect(nil) != nil {
			t.Fatal("accepted")
		}
	})
	t.Run("no verifier fails closed", func(t *testing.T) {
		h := newHarness(t, nil, func(s *Server) { s.verifier = nil })
		if h.connect(nil) != nil {
			t.Fatal("accepted")
		}
		if h.srv.Health(context.Background()).Ready {
			t.Fatal("ready without verifier")
		}
	})
}

func TestMalformedInitIgnored(t *testing.T) {
	h := newHarness(t, nil)
	conn := h.dial()
	for i := 0; i < 50; i++ {
		b := make([]byte, 4+i*20)
		rand.Read(b)
		b[0] = 0
		copy(b[1:4], []byte{0, 0, 0})
		conn.Write(b)
	}
	if recv(conn, 200*time.Millisecond) != nil {
		t.Fatal("answered garbage")
	}
	h.verifier.mu.Lock()
	calls := h.verifier.calls
	h.verifier.mu.Unlock()
	if calls != 0 {
		t.Fatal("verifier reached by malformed packets")
	}
}

func TestInitReplayAndRetransmit(t *testing.T) {
	h := newHarness(t, nil)
	c := h.connect(nil)
	if c == nil {
		t.Fatal("handshake")
	}
	// Same console retransmits its init: cached reply, no second session.
	c.conn.Write(c.init)
	again := recv(c.conn, 500*time.Millisecond)
	if !bytes.Equal(again, c.reply) || h.srv.SessionCount() != 1 {
		t.Fatalf("retransmitted init not answered idempotently: %d %d %d", len(again), len(c.reply), h.srv.SessionCount())
	}
	// A different source replaying the captured init gets nothing.
	other := h.dial()
	other.Write(c.init)
	if recv(other, 300*time.Millisecond) != nil || h.srv.SessionCount() != 1 {
		t.Fatal("replayed init from another source accepted")
	}
}

func TestSessionPacketReplayAndSourceBinding(t *testing.T) {
	h := newHarness(t, nil)
	c := h.connect(nil)
	ping, _ := sgwire.MarshalChunks([]sgwire.Chunk{{Tag: sgwire.TagXbPulse, Data: []byte{1, 0, 0, 0}}})
	c.send(sgwire.OpControl, nil, ping)
	if c.read(time.Second) == nil {
		t.Fatal("no reply")
	}
	c.sendRaw(c.seq, sgwire.OpControl, nil, ping) // exact replay of sequence number
	if c.read(200*time.Millisecond) != nil {
		t.Fatal("replayed packet answered")
	}
	// Valid packet from a different source port is ignored (session bound to peer).
	imposter := h.dial()
	pkt, _ := sgwire.Seal(c.keys.ClientToSG, sgwire.OpControl, c.spi, c.seq+5, ping, nil)
	imposter.Write(pkt)
	if recv(imposter, 200*time.Millisecond) != nil {
		t.Fatal("session answered a different source")
	}
	// Tampered packet is dropped.
	pkt, _ = sgwire.Seal(c.keys.ClientToSG, sgwire.OpControl, c.spi, c.seq+6, ping, nil)
	pkt[5] ^= 1
	c.conn.Write(pkt)
	if c.read(200*time.Millisecond) != nil {
		t.Fatal("tampered packet answered")
	}
}

func TestServiceDispatchAndUnavailable(t *testing.T) {
	h := newHarness(t, nil)
	c := h.connect(nil)
	syn := sgwire.TCPHeader{Src: 4000, Dst: 107, Seq: 1000, FlagsAndHeader: 6<<12 | sgwire.TCPSyn, Window: 8192}
	c.tcp(syn, []byte{2, 4, 0x05, 0x18})
	hd, _, ok := c.readTCP(time.Second)
	if !ok || hd.Flags() != sgwire.TCPSyn|sgwire.TCPAck || hd.Ack != 1001 || hd.Src != 107 || hd.Dst != 4000 {
		t.Fatalf("expected SYN-ACK, got %+v ok=%v", hd, ok)
	}
	c.tcp(sgwire.TCPHeader{Src: 4000, Dst: 107, Seq: 1001, Ack: hd.Seq + 1, FlagsAndHeader: 5<<12 | sgwire.TCPAck}, nil)
	c.tcp(sgwire.TCPHeader{Src: 4000, Dst: 107, Seq: 1001, Ack: hd.Seq + 1, FlagsAndHeader: 5<<12 | sgwire.TCPAck | sgwire.TCPPsh}, []byte("ping"))
	select {
	case got := <-h.backend.got:
		if string(got) != "ping" {
			t.Fatal("backend received wrong data")
		}
	case <-time.After(time.Second):
		t.Fatal("backend not reached")
	}
	var echoed []byte
	for i := 0; i < 2 && len(echoed) == 0; i++ {
		hd, payload, ok := c.readTCP(time.Second)
		if ok && hd.Flags()&sgwire.TCPPsh != 0 {
			echoed = payload
		}
	}
	if string(echoed) != "echo:ping" {
		t.Fatalf("echo %q", echoed)
	}
	// Binding: the backend saw gateway-bound identity.
	h.backend.mu.Lock()
	cc := h.backend.ctxs[0]
	h.backend.mu.Unlock()
	if cc.PrincipalID != "00000000000000aa" || cc.CoreAccountID != "core-1" || cc.XUID != 0xaa || cc.ServiceID != 7 || cc.TitleID != 0x4d530004 || cc.Generation == 0 {
		t.Fatalf("bad context %+v", cc)
	}
	// Out-of-order data is not delivered.
	c.tcp(sgwire.TCPHeader{Src: 4000, Dst: 107, Seq: 9999, Ack: hd.Seq + 1, FlagsAndHeader: 5<<12 | sgwire.TCPAck}, []byte("skip"))
	select {
	case <-h.backend.got:
		t.Fatal("out-of-order data delivered")
	case <-time.After(150 * time.Millisecond):
	}

	// Service 9 is in the ticket but no backend exists: native unavailable (RST), never success.
	c.tcp(sgwire.TCPHeader{Src: 4001, Dst: 109, Seq: 50, FlagsAndHeader: 5<<12 | sgwire.TCPSyn}, nil)
	for {
		hd, _, ok := c.readTCP(time.Second)
		if !ok {
			t.Fatal("no reset for unimplemented service")
		}
		if hd.Dst == 4001 {
			if hd.Flags()&sgwire.TCPRst == 0 || hd.Flags()&sgwire.TCPSyn != 0 {
				t.Fatalf("expected RST, got flags %x", hd.Flags())
			}
			break
		}
	}
	// A port absent from the ticket is unauthorised.
	c.tcp(sgwire.TCPHeader{Src: 4002, Dst: 150, Seq: 5, FlagsAndHeader: 5<<12 | sgwire.TCPSyn}, nil)
	for {
		hd, _, ok := c.readTCP(time.Second)
		if !ok {
			t.Fatal("no reset for unauthorised port")
		}
		if hd.Dst == 4002 {
			if hd.Flags()&sgwire.TCPRst == 0 {
				t.Fatal("expected RST")
			}
			break
		}
	}
	if h.srv.stats.unauthorizedPort.Load() != 1 || h.srv.stats.unavailable.Load() != 1 {
		t.Fatal("counters wrong")
	}
}

func TestBackendUnavailableErrorBecomesReset(t *testing.T) {
	h := newHarness(t, nil)
	h.backend.setErr(ErrUnavailable)
	c := h.connect(nil)
	c.tcp(sgwire.TCPHeader{Src: 4000, Dst: 107, Seq: 1, FlagsAndHeader: 5<<12 | sgwire.TCPSyn}, nil)
	hd, _, ok := c.readTCP(time.Second)
	if !ok || hd.Flags()&sgwire.TCPRst == 0 {
		t.Fatal("expected reset")
	}
	h.backend.setErr(errors.New("boom"))
	c.tcp(sgwire.TCPHeader{Src: 4001, Dst: 107, Seq: 1, FlagsAndHeader: 5<<12 | sgwire.TCPSyn}, nil)
	hd, _, ok = c.readTCP(time.Second)
	if !ok || hd.Flags()&sgwire.TCPRst == 0 {
		t.Fatal("expected reset on backend error")
	}
}

func TestExpiryRevocationAndCapacity(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.MaxPerIP = 2 })
	a, b := h.connect(nil), h.connect(nil)
	if a == nil || b == nil {
		t.Fatal("handshake")
	}
	if h.connect(nil) != nil {
		t.Fatal("per-IP limit not enforced")
	}
	if n := h.srv.RevokePrincipal("00000000000000aa"); n != 2 {
		t.Fatalf("revoked %d", n)
	}
	p := a.read(time.Second)
	if p == nil {
		t.Fatal("no delete notice")
	}
	if ch, _ := sgwire.ParseChunks(p.Payload); len(ch) != 1 || ch[0].Tag != sgwire.TagDelete {
		t.Fatal("expected delete chunk")
	}
	ping, _ := sgwire.MarshalChunks([]sgwire.Chunk{{Tag: sgwire.TagPulse}})
	a.send(sgwire.OpControl, nil, ping)
	a.send(sgwire.OpControl, nil, ping)
	if h.srv.SessionCount() != 0 {
		t.Fatal("sessions survive revocation")
	}
	c := h.connect(nil)
	if c == nil {
		t.Fatal("new handshake after revocation")
	}
	h.advance(2 * time.Minute) // idle expiry
	h.srv.sweep()
	if h.srv.SessionCount() != 0 {
		t.Fatal("idle session not expired")
	}
	d := h.connect(func(i *Identity) { i.TicketEnd = time.Now().Add(h.offset + 2*time.Second) })
	h.advance(3 * time.Second)
	h.srv.sweep()
	if d == nil || h.srv.SessionCount() != 0 {
		t.Fatal("session outlived its ticket")
	}
}

func TestInitRateLimit(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.InitRate, c.InitBurst = 0.001, 3 })
	conn := h.dial()
	for i := 0; i < 10; i++ {
		d, _, _ := buildInit(t, 0x1100)
		conn.Write(d)
	}
	time.Sleep(200 * time.Millisecond)
	if got := h.srv.stats.initRateLimited.Load(); got != 7 {
		t.Fatalf("rate limited %d, want 7", got)
	}
}

func TestHealthDistinguishesLayers(t *testing.T) {
	h := newHarness(t, nil)
	hl := h.srv.Health(context.Background())
	if hl.Listener != "listening" || !hl.Ready || hl.E2E.State != "never" || hl.Backends["7"] == "" {
		t.Fatalf("%+v", hl)
	}
	if c := h.connect(nil); c == nil {
		t.Fatal("handshake")
	}
	if h.srv.Health(context.Background()).E2E.State != "observed" {
		t.Fatal("e2e not observed after handshake")
	}
}

func TestConfigValidation(t *testing.T) {
	env := map[string]string{"XBGW_ADVERTISE_IP": "10.212.63.175"}
	look := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	if _, err := ConfigFromEnv(look); err == nil {
		t.Fatal("accepted private (ZeroTier) advertise address")
	}
	env["XBGW_ADVERTISE_IP"] = "145.241.228.207"
	c, err := ConfigFromEnv(look)
	if err != nil || c.BindAddr.Port() != 3074 || c.DebugCapture {
		t.Fatalf("defaults: %v %+v", err, c)
	}
	env["XBGW_DEBUG_CAPTURE"] = "1"
	if _, err := ConfigFromEnv(look); err == nil {
		t.Fatal("capture without directory")
	}
	env["XBGW_CAPTURE_DIR"] = "/tmp/cap"
	if _, err := ConfigFromEnv(look); err == nil {
		t.Fatal("capture on RAM disk")
	}
}
