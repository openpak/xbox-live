// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"openpak/xb-live/internal/krb"
	"openpak/xb-live/internal/sgwire"
)

const kdcXUID = 0x0009000000000001

func sgRing(t *testing.T, hexKey string) *krb.Keyring {
	t.Helper()
	r, err := krb.ParseKeyring([]byte(`{"active":5,"keys":{"4":"00112233445566778899aabbccddee01","5":"`+hexKey+`"}}`), 16)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// issueTicket builds the gateway ticket exactly as xb-auth's kdc does (kdc.go
// TGS handler): RC4-HMAC under the active SG key, KVNO = key id, AD users =
// XUID little endian, AD service addresses = the 0xe0 block.
func issueTicket(t *testing.T, ring *krb.Keyring, now time.Time, gw netip.Addr, end time.Duration) (krb.Ticket, [16]byte, krb.PrincipalName) {
	t.Helper()
	sess, _ := krb.NewSessionKey()
	addr := &krb.ServiceAddress{SiteIP: gw, NumServices: 2}
	addr.Results[0] = krb.ServiceResult{ID: 6, Port: 106}
	addr.Results[1] = krb.ServiceResult{ID: 7, HR: krb.HRUnknownService}
	xuid := binary.LittleEndian.AppendUint64(nil, kdcXUID)
	cname := krb.PrincipalName{Type: krb.NameTypeEnterprise, Parts: []string{"Player@xbox.com"}}
	part := &krb.EncTicketPart{Flags: krb.FlagPreAuth, Key: krb.EncryptionKey{Type: krb.ETypeRC4HMAC, Value: sess[:]},
		CRealm: "passport.net", CName: cname, AuthTime: now, EndTime: now.Add(end),
		AuthData: []krb.AuthData{{Type: krb.ADUsers, Data: xuid}, {Type: krb.ADServiceAddresses, Data: addr.Marshal()}}}
	id, raw := ring.Active()
	key, _ := krb.ToKey(raw)
	enc, err := krb.Seal(key, krb.UsageSGTicket, &id, part.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	return krb.Ticket{VNO: krb.PVNO, Realm: "XBOX.COM", SName: krb.PrincipalName{Type: krb.NameTypeSrvInst, Parts: []string{"xbox", "gw"}}, Enc: enc}, sess, cname
}

// realInit builds a native init datagram whose authenticator checksums the init parameters.
func realInit(t *testing.T, tk krb.Ticket, sess [16]byte, cname krb.PrincipalName, authTime time.Time) []byte {
	t.Helper()
	_, pub, _ := dhPair(t)
	var nonce [8]byte
	rand.Read(nonce[:])
	body := binary.LittleEndian.AppendUint16(nil, 0)
	body = binary.LittleEndian.AppendUint16(body, 2)
	body = binary.LittleEndian.AppendUint32(body, 0x59a300)
	body = append(body, nonce[:]...)
	body = binary.LittleEndian.AppendUint32(body, 0)
	head := append(chunk(0x5802, body), chunk(0x5880, pub[:])...)
	mac := hmac.New(sha1.New, sess[:])
	mac.Write(head)
	seqNo := uint32(77)
	auth := &krb.SGAuthenticator{Authenticator: krb.Authenticator{CRealm: "passport.net", CName: cname, CUsec: 123456, CTime: authTime},
		CksumType: krb.ChecksumTypeSGParam, Cksum: mac.Sum(nil), SeqNumber: &seqNo}
	key, _ := krb.ToKey(sess[:])
	encAuth, err := krb.Seal(key, krb.UsageAPReqAuth, nil, auth.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	apreq := (&krb.APReq{Ticket: tk, Authenticator: encAuth}).Marshal()
	out := append([]byte{0, 0, 0, 0}, head...)
	out = append(out, chunk(0x5882, apreq)...)
	return append(out, chunk(0x5886, make([]byte, 8))...)
}

func chunk(tag uint16, data []byte) []byte {
	b := binary.LittleEndian.AppendUint16(nil, tag)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(data)+4))
	return append(b, data...)
}

func krbServer(t *testing.T, ring *krb.Keyring) (*harness, *net.UDPConn) {
	h := newHarness(t, nil, func(s *Server) { s.verifier = KrbVerifier{SGKeys: ring} })
	return h, h.dial()
}

func TestKDCIssuedTicketAdmitsAndAPRepVerifies(t *testing.T) {
	ring := sgRing(t, "a1b2c3d4e5f60718293a4b5c6d7e8f90")
	h, conn := krbServer(t, ring)
	now := time.Now()
	tk, sess, cname := issueTicket(t, ring, now, advertise, time.Hour)
	conn.Write(realInit(t, tk, sess, cname, now))
	reply := recv(conn, time.Second)
	if reply == nil || h.srv.SessionCount() != 1 {
		t.Fatal("valid KDC ticket not admitted")
	}
	chunks := parseReply(t, reply)
	repEnc, err := krb.ParseAPRep(chunks[2])
	if err != nil {
		t.Fatal(err)
	}
	key, _ := krb.ToKey(sess[:])
	plain, err := krb.Open(key, krb.UsageAPRepEncPart, repEnc)
	if err != nil {
		t.Fatal("AP-REP does not open with the ticket session key")
	}
	part, err := krb.ParseEncAPRepPart(plain)
	if err != nil || part.CUsec != 123456 || part.Subkey == nil || part.Subkey.Type != krb.ChecksumTypeSGParam {
		t.Fatalf("AP-REP content: %v %+v", err, part)
	}
	mac := hmac.New(sha1.New, sess[:])
	mac.Write(reply[4 : 4+0x40+4+96])
	if !bytes.Equal(part.Subkey.Value, mac.Sum(nil)) {
		t.Fatal("AP-REP subkey is not the response digest")
	}
	// Admitted services come from the ticket: id 6 port 106 only.
	h.srv.mu.RLock()
	for _, s := range h.srv.sessions {
		if len(s.services) != 1 || s.services[106] != 6 || s.identity.XUID != kdcXUID {
			t.Fatal("service map or XUID wrong")
		}
	}
	h.srv.mu.RUnlock()
}

func TestKDCTicketRejections(t *testing.T) {
	ring := sgRing(t, "a1b2c3d4e5f60718293a4b5c6d7e8f90")
	other := sgRing(t, "0f0e0d0c0b0a09080706050403020100")
	cases := map[string]func() (krb.Ticket, [16]byte, krb.PrincipalName, time.Time){
		"unknown key": func() (krb.Ticket, [16]byte, krb.PrincipalName, time.Time) {
			a, b, c := issueTicket(t, other, time.Now(), advertise, time.Hour)
			return a, b, c, time.Now()
		},
		"expired": func() (krb.Ticket, [16]byte, krb.PrincipalName, time.Time) {
			a, b, c := issueTicket(t, ring, time.Now().Add(-2*time.Hour), advertise, time.Hour)
			return a, b, c, time.Now()
		},
		"other gateway": func() (krb.Ticket, [16]byte, krb.PrincipalName, time.Time) {
			a, b, c := issueTicket(t, ring, time.Now(), netip.MustParseAddr("198.51.100.9"), time.Hour)
			return a, b, c, time.Now()
		},
		"stale authenticator": func() (krb.Ticket, [16]byte, krb.PrincipalName, time.Time) {
			a, b, c := issueTicket(t, ring, time.Now(), advertise, time.Hour)
			return a, b, c, time.Now().Add(-20 * time.Minute)
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			h, conn := krbServer(t, ring)
			tk, sess, cname, at := mk()
			conn.Write(realInit(t, tk, sess, cname, at))
			if recv(conn, 300*time.Millisecond) != nil || h.srv.SessionCount() != 0 {
				t.Fatal("admitted")
			}
		})
	}
	t.Run("wrong session key checksum", func(t *testing.T) {
		h, conn := krbServer(t, ring)
		tk, sess, cname := issueTicket(t, ring, time.Now(), advertise, time.Hour)
		d := realInit(t, tk, sess, cname, time.Now())
		d[40] ^= 1 // alter the signed DH chunk after the checksum was computed
		conn.Write(d)
		if recv(conn, 300*time.Millisecond) != nil || h.srv.SessionCount() != 0 {
			t.Fatal("admitted")
		}
	})
}

func dhPair(t *testing.T) (*sgwire.DHPrivate, [96]byte, error) {
	p, pub, err := sgwire.GenerateDH(nil)
	if err != nil {
		t.Fatal(err)
	}
	return p, pub, nil
}

// parseReply returns the three init-response chunk bodies.
func parseReply(t *testing.T, reply []byte) [][]byte {
	c, err := sgwire.ParseChunks(reply[4:])
	if err != nil || len(c) != 3 {
		t.Fatalf("reply chunks: %v", err)
	}
	return [][]byte{c[0].Data, c[1].Data, c[2].Data}
}
