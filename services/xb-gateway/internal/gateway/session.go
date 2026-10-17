// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
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
	rcvClosed // the console sent FIN (half-close): it still reads our reply
	finSent
)

// defaultHalfCloseGrace bounds how long a connection the console half-closed
// may wait for the backend to answer and end the stream.
const defaultHalfCloseGrace = 15 * time.Second

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
	grace   *time.Timer // half-close deadline; guarded by Session.mu
}

// Session is the per-connection encrypted SG state. It holds transport state
// only; feature state belongs to the backends.
type Session struct {
	srv      *Server
	spi      sgwire.SPI // gateway-chosen: carried by packets from the console
	sendSPI  sgwire.SPI // console-chosen (init SPI): carried by packets to the console
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
	pkt, err := sgwire.Seal(s.keys.SGToClient, op, s.sendSPI, s.sendSeq, payload, footer)
	s.sendSeq++
	if err != nil {
		return
	}
	if s.srv.cfg.DebugFrames {
		s.logFrame("tx", op, footer, payload)
	}
	s.srv.capture.record(true, byte(op)|0x40, s.spi.U32(), footer) // 0x40: footer (TCP header)
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
		s.srv.frameLog("drop auth", "gen", s.identity.Generation, "err", err.Error(), "len", len(buf))
		s.authDrops++
		s.srv.stats.authDrops.Add(1)
		return
	}
	if !s.replay.Accept(pkt.Seq) {
		s.srv.frameLog("drop replay", "gen", s.identity.Generation, "seq", pkt.Seq)
		s.srv.stats.replayDrops.Add(1)
		return
	}
	if !s.bucket.allow(now, s.srv.cfg.PacketRate, s.srv.cfg.PacketBurst) {
		s.srv.frameLog("drop rate", "gen", s.identity.Generation)
		s.srv.stats.rateDrops.Add(1)
		return
	}
	s.lastSeen = now
	if s.srv.cfg.DebugFrames {
		s.logFrame("rx", pkt.Opcode, pkt.Footer, pkt.Payload)
	}
	s.srv.capture.record(false, byte(pkt.Opcode)|0x40, s.spi.U32(), pkt.Footer)
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
			s.sendTCP(c, sgwire.TCPAck, nil, nil) // duplicate/out-of-order (incl. a retransmitted FIN): re-ack, no reassembly
			return
		}
		if len(data) > 0 && c.state != established {
			// Data after the console's own FIN, or after ours: not allowed.
			s.sendTCP(c, sgwire.TCPRst|sgwire.TCPAck, nil, nil)
			s.dropConn(c)
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
			s.sendTCP(c, sgwire.TCPAck, nil, nil)
			switch c.state {
			case established:
				// A FIN is a half-close: the request may still be answered. Tell
				// the backend (after the bytes already queued) that the console
				// is done sending, keep our side open, and bound the wait.
				c.state = rcvClosed
				select {
				case c.queue <- nil:
				default:
					s.sendTCP(c, sgwire.TCPRst|sgwire.TCPAck, nil, nil)
					s.dropConn(c)
					return
				}
				grace := s.srv.halfGrace
				if grace <= 0 {
					grace = defaultHalfCloseGrace
				}
				c.grace = time.AfterFunc(grace, func() { s.graceExpired(c) })
			case finSent: // we had already closed: both directions are done
				s.dropConn(c)
			}
			return
		}
		s.sendTCP(c, sgwire.TCPAck, nil, nil)
	}
}

// graceExpired ends a half-closed connection whose backend never finished.
func (s *Session) graceExpired(c *tcpConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.conns[c.key] != c {
		return
	}
	if c.state == rcvClosed {
		s.sendTCP(c, sgwire.TCPFin|sgwire.TCPAck, nil, nil)
		c.sndNxt++
		c.state = finSent
	}
	s.dropConn(c)
}

func mssSynOptions() []byte { return binary.BigEndian.AppendUint16([]byte{2, 4}, defaultMSS) }

// openTCP accepts a SYN for a ticket-authorised service port and consults the backend.
func (s *Session) openTCP(hdr sgwire.TCPHeader, key tcpKey, options []byte, dataLen int) {
	id, ok := s.services[hdr.Dst]
	if !ok {
		s.srv.stats.unauthorizedPort.Add(1)
		s.srv.log.Info("service open refused: port not in ticket", "port", hdr.Dst, "gen", s.identity.Generation)
		s.sendReset(hdr, dataLen)
		return
	}
	if len(s.conns) >= s.srv.cfg.MaxTCPPerSess {
		s.sendReset(hdr, dataLen)
		return
	}
	backend := s.srv.backends[id]
	if backend == nil {
		s.srv.log.Info("service open refused: no backend", "service", id, "port", hdr.Dst, "gen", s.identity.Generation)
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
		s.srv.log.Info("service open failed", "service", id, "gen", s.identity.Generation, "unavailable", err == nil || errors.Is(err, ErrUnavailable))
		s.sendReset(hdr, dataLen)
		return
	}
	c.stream = stream
	s.srv.log.Info("service open", "service", id, "gen", s.identity.Generation)
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
			if data == nil { // the console's FIN, after everything it sent
				if h, ok := c.stream.(HalfCloser); ok {
					h.CloseSend()
				} else {
					c.stream.Close()
				}
				continue
			}
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
		if c.grace != nil {
			c.grace.Stop()
		}
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
	if s.closed || s.conns[c.key] != c || (c.state != established && c.state != rcvClosed) {
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
	if c.state == established || c.state == rcvClosed {
		s.sendTCP(c, sgwire.TCPFin|sgwire.TCPAck, nil, nil)
		c.sndNxt++
		c.state = finSent
	}
	s.dropConn(c)
}

// logFrame logs one frame: opcode, TCP header fields, control chunk tags, and a
// bounded hex prefix of TCP data (after options). Debug aid behind XBGW_DEBUG_FRAMES.
func (s *Session) logFrame(dir string, op sgwire.Opcode, footer, payload []byte) {
	if op == sgwire.OpControl {
		chunks, err := sgwire.ParseChunks(payload)
		if err != nil {
			s.srv.frameLog(dir+" control", "gen", s.identity.Generation, "len", len(payload), "parse", err.Error())
			return
		}
		tags := make([]string, 0, len(chunks))
		for _, c := range chunks {
			tags = append(tags, fmt.Sprintf("%#x/%d:%s", c.Tag, len(c.Data), hex.EncodeToString(c.Data[:min(len(c.Data), 32)])))
		}
		s.srv.frameLog(dir+" control", "gen", s.identity.Generation, "chunks", strings.Join(tags, ","))
		return
	}
	hdr, err := sgwire.ParseTCPHeader(op, footer)
	if err != nil {
		s.srv.frameLog(dir+" tcp", "gen", s.identity.Generation, "op", uint8(op), "err", err.Error())
		return
	}
	data := payload
	if n := hdr.OptionsLen(); n <= len(data) {
		data = data[n:]
	}
	pre := data[:min(len(data), 320)]
	s.srv.frameLog(dir+" tcp", "gen", s.identity.Generation, "op", uint8(op), "sport", hdr.Src, "dport", hdr.Dst,
		"flags", fmt.Sprintf("%#x", hdr.Flags()), "seq", hdr.Seq, "ack", hdr.Ack, "win", hdr.Window, "dlen", len(data), "hex", hex.EncodeToString(pre))
}
