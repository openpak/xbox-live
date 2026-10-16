// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"time"

	"openpak/xb-live/internal/sgwire"
)

const (
	tcpWindow     = 65200
	defaultMSS    = 1304
	streamQueue   = 32
	deleteNormal  = 0
	seqExhaustion = 0xfffffff0
)

type tcpKey struct{ src, dst uint16 }

type tcpState int

const (
	synReceived tcpState = iota
	established
	finSent
)

type tcpConn struct {
	key     tcpKey
	service uint32
	state   tcpState
	rcvNxt  uint32
	sndNxt  uint32
	mss     int
	stream  Stream
	queue   chan []byte
	done    chan struct{}
	once    sync.Once
}

// Session is the per-connection encrypted SG state. It holds transport state
// only; feature state belongs to the backends.
type Session struct {
	srv      *Server
	spi      sgwire.SPI
	peer     netip.AddrPort
	keys     sgwire.ConnectionKeys
	identity ConnIdentity
	initKey  [32]byte
	initResp []byte
	expires  time.Time

	mu        sync.Mutex
	closed    bool
	replay    sgwire.ReplayWindow
	sendSeq   uint32
	lastSeen  time.Time
	bucket    bucket
	qos       *qosState
	conns     map[tcpKey]*tcpConn
	services  map[uint16]uint32
	authDrops uint64
}

// ConnIdentity is the identity the gateway bound at handshake.
type ConnIdentity struct {
	Principal  Principal
	XUID       uint64
	TitleID    uint32
	Generation uint64
}

type qosState struct {
	at   time.Time
	q    sgwire.QoS
	have bool
}

func (s *Session) send(op sgwire.Opcode, footer, payload []byte) {
	if s.sendSeq == 0 {
		s.sendSeq = 1
	}
	if s.sendSeq >= seqExhaustion {
		go s.srv.closeSession(s, "sequence space exhausted", false)
		return
	}
	pkt, err := sgwire.Seal(s.keys.SGToClient, op, s.spi, s.sendSeq, payload, footer)
	s.sendSeq++
	if err != nil {
		return
	}
	s.srv.capture.record(true, byte(op), s.spi.U32(), payload)
	s.srv.conn.WriteToUDPAddrPort(pkt, s.peer)
}

// handle processes one datagram addressed to this session.
func (s *Session) handle(buf []byte, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	pkt, err := sgwire.Open(buf, s.keys.ClientToSG, s.replay.Highest)
	if err != nil {
		s.authDrops++
		s.srv.stats.authDrops.Add(1)
		return
	}
	if !s.replay.Accept(pkt.Seq) {
		s.srv.stats.replayDrops.Add(1)
		return
	}
	if !s.bucket.allow(now, s.srv.cfg.PacketRate, s.srv.cfg.PacketBurst) {
		s.srv.stats.rateDrops.Add(1)
		return
	}
	s.lastSeen = now
	s.srv.capture.record(false, byte(pkt.Opcode), s.spi.U32(), pkt.Payload)
	if pkt.Opcode == sgwire.OpControl {
		s.handleControl(pkt.Payload, now)
		return
	}
	hdr, err := sgwire.ParseTCPHeader(pkt.Opcode, pkt.Footer)
	if err != nil {
		return
	}
	s.handleTCP(hdr, pkt.Payload)
}

func (s *Session) handleControl(payload []byte, now time.Time) {
	chunks, err := sgwire.ParseChunks(payload)
	if err != nil {
		return
	}
	for _, c := range chunks {
		switch c.Tag {
		case sgwire.TagPulse:
		case sgwire.TagXbPulse:
			if len(c.Data) >= 4 {
				if out, err := sgwire.PulseReply(binary.LittleEndian.Uint32(c.Data)); err == nil {
					s.send(sgwire.OpControl, nil, out)
				}
			}
		case sgwire.TagQoSInit:
			s.handleQoS(c.Data, now)
		case sgwire.TagDelete:
			go s.srv.closeSession(s, "client delete", false)
			return
		}
	}
}

// handleQoS mirrors Xombie: flag 0 stores local state, 1 returns RTT/gap, 2 relays.
func (s *Session) handleQoS(data []byte, now time.Time) {
	q, err := sgwire.ParseQoS(data)
	if err != nil {
		return
	}
	reply := func(flags uint8, rtt, gap uint32) {
		if out, err := sgwire.QoSReply(q, flags, rtt, gap); err == nil {
			s.send(sgwire.OpControl, nil, out)
		}
	}
	switch q.Flags {
	case 0:
		s.qos = &qosState{at: now, q: q, have: true}
	case 1:
		st := s.qos
		s.qos = nil
		if st == nil || st.q.Nonce != q.Nonce || st.q.Index != q.Index || st.q.Packet != q.Packet {
			return
		}
		us := uint32(min(now.Sub(st.at).Microseconds(), 0xffffffff))
		reply(0, us, 0)
		reply(1, 0, us)
	case 2:
		reply(0x10, 0, 0)
	}
}

func (s *Session) sendTCP(c *tcpConn, flags uint16, options, data []byte) {
	words := uint16(5)
	if len(options) > 0 {
		words += uint16(len(options) / 4)
	}
	h := sgwire.TCPHeader{Src: c.key.dst, Dst: c.key.src, Seq: c.sndNxt, Ack: c.rcvNxt,
		FlagsAndHeader: words<<12 | flags, Window: tcpWindow}
	op, footer := h.Marshal()
	s.send(op, footer, append(append([]byte(nil), options...), data...))
}

func (s *Session) sendReset(hdr sgwire.TCPHeader, plen int) {
	r := &tcpConn{key: tcpKey{hdr.Src, hdr.Dst}}
	flags := uint16(sgwire.TCPRst)
	if hdr.Flags()&sgwire.TCPAck != 0 {
		r.sndNxt = hdr.Ack
	} else {
		flags |= sgwire.TCPAck
		r.rcvNxt = hdr.Seq + uint32(plen)
		if hdr.Flags()&sgwire.TCPSyn != 0 {
			r.rcvNxt++
		}
	}
	s.sendTCP(r, flags, nil, nil)
}

func mssOption(options []byte) int {
	for len(options) >= 2 {
		kind, l := options[0], int(options[1])
		if kind == 0 {
			break
		}
		if kind == 1 {
			options = options[1:]
			continue
		}
		if l < 2 || l > len(options) {
			break
		}
		if kind == 2 && l == 4 {
			return int(binary.BigEndian.Uint16(options[2:]))
		}
		options = options[l:]
	}
	return defaultMSS
}

func (s *Session) handleTCP(hdr sgwire.TCPHeader, payload []byte) {
	optLen := hdr.OptionsLen()
	if optLen > len(payload) {
		return
	}
	options, data := payload[:optLen], payload[optLen:]
	key := tcpKey{hdr.Src, hdr.Dst}
	flags := hdr.Flags()
	c := s.conns[key]
	if c == nil {
		if flags&sgwire.TCPRst != 0 {
			return
		}
		if flags&sgwire.TCPSyn == 0 || flags&sgwire.TCPAck != 0 {
			s.sendReset(hdr, len(data))
			return
		}
		s.openTCP(hdr, key, options, len(data))
		return
	}
	if flags&sgwire.TCPRst != 0 {
		s.dropConn(c)
		return
	}
	if flags&sgwire.TCPSyn != 0 {
		if c.state == synReceived && hdr.Seq+1 == c.rcvNxt { // retransmitted SYN
			c.sndNxt--
			s.sendTCP(c, sgwire.TCPSyn|sgwire.TCPAck, mssSynOptions(), nil)
			c.sndNxt++
		}
		return
	}
	if flags&sgwire.TCPAck != 0 && c.state == synReceived && hdr.Ack == c.sndNxt {
		c.state = established
	}
	if c.state == synReceived {
		return
	}
	if len(data) > 0 || flags&sgwire.TCPFin != 0 {
		if hdr.Seq != c.rcvNxt {
			s.sendTCP(c, sgwire.TCPAck, nil, nil) // duplicate/out-of-order: re-ack, no reassembly
			return
		}
		if len(data) > 0 {
			select {
			case c.queue <- append([]byte(nil), data...):
			default:
				s.sendTCP(c, sgwire.TCPRst|sgwire.TCPAck, nil, nil)
				s.dropConn(c)
				return
			}
			c.rcvNxt += uint32(len(data))
		}
		if flags&sgwire.TCPFin != 0 {
			c.rcvNxt++
			fl := uint16(sgwire.TCPAck)
			if c.state != finSent {
				fl |= sgwire.TCPFin
				c.state = finSent
			}
			s.sendTCP(c, fl, nil, nil)
			if fl&sgwire.TCPFin != 0 {
				c.sndNxt++
			}
			s.dropConnLater(c)
			return
		}
		s.sendTCP(c, sgwire.TCPAck, nil, nil)
	}
}

func mssSynOptions() []byte { return binary.BigEndian.AppendUint16([]byte{2, 4}, defaultMSS) }

// openTCP accepts a SYN for a ticket-authorised service port and consults the backend.
func (s *Session) openTCP(hdr sgwire.TCPHeader, key tcpKey, options []byte, dataLen int) {
	id, ok := s.services[hdr.Dst]
	if !ok {
		s.srv.stats.unauthorizedPort.Add(1)
		s.sendReset(hdr, dataLen)
		return
	}
	if len(s.conns) >= s.srv.cfg.MaxTCPPerSess {
		s.sendReset(hdr, dataLen)
		return
	}
	backend := s.srv.backends[id]
	if backend == nil {
		s.srv.stats.unavailable.Add(1)
		s.sendReset(hdr, dataLen)
		return
	}
	c := &tcpConn{key: key, service: id, rcvNxt: hdr.Seq + 1, mss: min(mssOption(options), defaultMSS),
		queue: make(chan []byte, streamQueue), done: make(chan struct{})}
	var iss [4]byte
	rand.Read(iss[:])
	c.sndNxt = binary.BigEndian.Uint32(iss[:])
	ctx, cancel := context.WithTimeout(context.Background(), s.srv.cfg.DirectoryWait)
	defer cancel()
	stream, err := backend.Open(ctx, ConnContext{PrincipalID: s.identity.Principal.PrincipalID,
		CoreAccountID: s.identity.Principal.CoreAccountID, XUID: s.identity.XUID, TitleID: s.identity.TitleID,
		ServiceID: id, Generation: s.identity.Generation}, &sink{s: s, c: c})
	if err != nil || stream == nil {
		if errors.Is(err, ErrUnavailable) || err == nil {
			s.srv.stats.unavailable.Add(1)
		} else {
			s.srv.stats.backendErrors.Add(1)
		}
		s.sendReset(hdr, dataLen)
		return
	}
	c.stream = stream
	s.conns[key] = c
	go s.pump(c)
	s.sendTCP(c, sgwire.TCPSyn|sgwire.TCPAck, mssSynOptions(), nil)
	c.sndNxt++
}

// pump delivers received bytes to the backend off the packet loop.
func (s *Session) pump(c *tcpConn) {
	for {
		select {
		case data := <-c.queue:
			if err := c.stream.Receive(data); err != nil {
				s.mu.Lock()
				if s.conns[c.key] == c {
					s.sendTCP(c, sgwire.TCPRst|sgwire.TCPAck, nil, nil)
					s.dropConn(c)
				}
				s.mu.Unlock()
				return
			}
		case <-c.done:
			return
		}
	}
}

func (c *tcpConn) shutdown() {
	c.once.Do(func() {
		close(c.done)
		if c.stream != nil {
			go c.stream.Close()
		}
	})
}

// dropConn requires s.mu.
func (s *Session) dropConn(c *tcpConn) {
	delete(s.conns, c.key)
	c.shutdown()
}
func (s *Session) dropConnLater(c *tcpConn) { s.dropConn(c) }

type sink struct {
	s *Session
	c *tcpConn
}

// Send segments backend output into PSH|ACK packets. There is no retransmit
// queue: loss on the console path is not recovered (see docs, known limitation).
func (k *sink) Send(data []byte) error {
	s, c := k.s, k.c
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.conns[c.key] != c || c.state != established {
		return errors.New("connection closed")
	}
	for len(data) > 0 {
		n := min(len(data), c.mss)
		s.sendTCP(c, sgwire.TCPAck|sgwire.TCPPsh, nil, data[:n])
		c.sndNxt += uint32(n)
		data = data[n:]
	}
	return nil
}

func (k *sink) Close() {
	s, c := k.s, k.c
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.conns[c.key] != c {
		return
	}
	if c.state == established {
		s.sendTCP(c, sgwire.TCPFin|sgwire.TCPAck, nil, nil)
		c.sndNxt++
	}
	s.dropConn(c)
}
