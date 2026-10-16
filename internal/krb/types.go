// SPDX-License-Identifier: AGPL-3.0-only
package krb

import "time"

const (
	PVNO = 5

	MsgASReq  = 10
	MsgASRep  = 11
	MsgTGSReq = 12
	MsgTGSRep = 13
	MsgAPReq  = 14
	MsgError  = 30

	ETypeRC4HMAC = 23

	NameTypePrincipal  = 1
	NameTypeSrvInst    = 2
	NameTypeEnterprise = 10

	PAAPReq              = 1 // PA-TGS-REQ
	PAEncTimestamp       = 2 // PA-ENC-TIMESTAMP
	PACompoundIdentity   = 130
	PAXboxServiceRequest = 201
	PAXboxServiceAddress = 202
	PAXboxClientVersion  = 206
	PAForCheckDups       = 131 // PA-MSKILE-FOR-CHECK-DUPS
	PAXboxAccountCreate  = 203
	PAXboxPPA            = 204

	KDCOptCanonicalize uint32 = 0x00010000

	MACSRealm = "MACS.XBOX.COM"

	// Ticket flags (RFC 4120 bit positions, MSB first).
	FlagInvalid uint32 = 0x01000000
	FlagInitial uint32 = 0x00400000
	FlagPreAuth uint32 = 0x00200000

	// Key usages. The Xbox client encrypts the AS-REP enclosed part with usage
	// 8, not the RFC's 3; this matches Xombie's measured behaviour.
	UsageASReqTimestamp = 1
	UsageTicket         = 2
	UsageTGSReqAuth     = 7
	UsageKDCRepPart     = 8
	UsageServiceRequest = 1201
	UsageServiceAddress = 1202
	UsageSGTicket       = 3000

	// Authorization data types used by Xombie / OpenPak.
	ADServiceAddresses = 10000
	ADUsers            = 10001
	ADDevice           = 10002 // OpenPak: 8-byte little-endian machine id in a device TGT

	// KRB-ERROR codes.
	ErrCPrincipalUnknown = 6
	ErrSPrincipalUnknown = 7
	ErrPolicy            = 12
	ErrBadOption         = 13
	ErrPADataTypeNoSupp  = 16
	ErrETypeNoSupp       = 14
	ErrClientRevoked     = 18
	ErrPreauthFailed     = 24
	ErrPreauthRequired   = 25
	ErrSvcUnavailable    = 29
	ErrAPBadIntegrity    = 31
	ErrAPTktExpired      = 32
	ErrAPRepeat          = 34
	ErrAPSkew            = 37
	ErrAPModified        = 41
)

type PrincipalName struct {
	Type  int32
	Parts []string
}

func (p PrincipalName) Equal(o PrincipalName) bool {
	if p.Type != o.Type || len(p.Parts) != len(o.Parts) {
		return false
	}
	for i := range p.Parts {
		if p.Parts[i] != o.Parts[i] {
			return false
		}
	}
	return true
}

func (p PrincipalName) marshal() []byte {
	var parts [][]byte
	for _, s := range p.Parts {
		parts = append(parts, genString(s))
	}
	return seq(ctx(0, intg(int64(p.Type))), ctx(1, seq(parts...)))
}

func parsePrincipal(b []byte) (PrincipalName, error) {
	f, err := seqFields(b)
	if err != nil {
		return PrincipalName{}, err
	}
	var p PrincipalName
	v, err := f.need(0)
	if err != nil {
		return p, err
	}
	if p.Type, err = readInt32(v); err != nil {
		return p, err
	}
	v, err = f.need(1)
	if err != nil {
		return p, err
	}
	err = readList(v, func(e []byte) error {
		s, err := readString(e)
		p.Parts = append(p.Parts, s)
		return err
	})
	if err == nil && len(p.Parts) == 0 {
		err = malformed("empty principal")
	}
	return p, err
}

type EncryptedData struct {
	EType  int32
	KVNO   *uint32
	Cipher []byte
}

func (e EncryptedData) Marshal() []byte {
	parts := [][]byte{ctx(0, intg(int64(e.EType)))}
	if e.KVNO != nil {
		parts = append(parts, ctx(1, intg(int64(*e.KVNO))))
	}
	parts = append(parts, ctx(2, octets(e.Cipher)))
	return seq(parts...)
}

func ParseEncryptedData(b []byte) (EncryptedData, error) {
	f, err := seqFields(b)
	if err != nil {
		return EncryptedData{}, err
	}
	return parseEncryptedFields(f)
}

func parseEncryptedFields(f fields) (e EncryptedData, err error) {
	v, err := f.need(0)
	if err != nil {
		return
	}
	if e.EType, err = readInt32(v); err != nil {
		return
	}
	if v, ok := f[1]; ok {
		k, err := readUint32(v)
		if err != nil {
			return e, err
		}
		e.KVNO = &k
	}
	if v, err = f.need(2); err != nil {
		return
	}
	e.Cipher, err = readOctets(v, maxDERLen)
	return
}

type Ticket struct {
	VNO   int32
	Realm string
	SName PrincipalName
	Enc   EncryptedData
}

func (t Ticket) Marshal() []byte {
	return app(1, seq(ctx(0, intg(int64(t.VNO))), ctx(1, genString(t.Realm)),
		ctx(2, t.SName.marshal()), ctx(3, t.Enc.Marshal())))
}

func ParseTicket(b []byte) (t Ticket, err error) {
	f, err := appFields(b, 1)
	if err != nil {
		return
	}
	v, err := f.need(0)
	if err != nil {
		return
	}
	if t.VNO, err = readInt32(v); err != nil {
		return
	}
	if v, err = f.need(1); err != nil {
		return
	}
	if t.Realm, err = readString(v); err != nil {
		return
	}
	if v, err = f.need(2); err != nil {
		return
	}
	if t.SName, err = parsePrincipal(v); err != nil {
		return
	}
	if v, err = f.need(3); err != nil {
		return
	}
	t.Enc, err = ParseEncryptedData(v)
	return
}

// ParseTicketSequence parses a SEQUENCE OF Ticket (PA-MSKILE-COMPOUND-IDENTITY).
func ParseTicketSequence(b []byte) ([]Ticket, error) {
	var out []Ticket
	err := readList(b, func(e []byte) error {
		t, err := ParseTicket(e)
		out = append(out, t)
		return err
	})
	return out, err
}

type PAData struct {
	Type  int32
	Value []byte
}

func marshalPAData(p []PAData) []byte {
	var parts [][]byte
	for _, d := range p {
		parts = append(parts, seq(ctx(1, intg(int64(d.Type))), ctx(2, octets(d.Value))))
	}
	return seq(parts...)
}

func parsePAData(b []byte) ([]PAData, error) {
	var out []PAData
	err := readList(b, func(e []byte) error {
		f, err := seqFields(e)
		if err != nil {
			return err
		}
		v, err := f.need(1)
		if err != nil {
			return err
		}
		var d PAData
		if d.Type, err = readInt32(v); err != nil {
			return err
		}
		if v, err = f.need(2); err != nil {
			return err
		}
		if d.Value, err = readOctets(v, maxDERLen); err != nil {
			return err
		}
		out = append(out, d)
		return nil
	})
	return out, err
}

// FindPA returns the single PA-DATA of the given type; ok is false when it is
// absent or occurs more than once.
func FindPA(list []PAData, typ int32) (value []byte, ok bool) {
	n := 0
	for _, d := range list {
		if d.Type == typ {
			value = d.Value
			n++
		}
	}
	return value, n == 1
}

type KDCReq struct {
	MsgType int // MsgASReq or MsgTGSReq
	Options uint32
	PAData  []PAData
	// Body
	CName  *PrincipalName
	Realm  string
	SName  *PrincipalName
	Nonce  uint32
	ETypes []int32
}

// ParseKDCReq parses an AS-REQ or TGS-REQ datagram. Trailing bytes are rejected.
func ParseKDCReq(b []byte) (*KDCReq, error) {
	if len(b) == 0 {
		return nil, malformed("empty")
	}
	var appTag int
	switch b[0] {
	case 0x6a:
		appTag = MsgASReq
	case 0x6c:
		appTag = MsgTGSReq
	default:
		return nil, malformed("not a KDC request")
	}
	f, err := appFields(b, appTag)
	if err != nil {
		return nil, err
	}
	r := &KDCReq{MsgType: appTag}
	v, err := f.need(1)
	if err != nil {
		return nil, err
	}
	if pvno, err := readInt(v); err != nil || pvno != PVNO {
		return nil, malformed("pvno")
	}
	if v, err = f.need(2); err != nil {
		return nil, err
	}
	if mt, err := readInt(v); err != nil || mt != int64(appTag) {
		return nil, malformed("msg-type")
	}
	if v, ok := f[3]; ok {
		if r.PAData, err = parsePAData(v); err != nil {
			return nil, err
		}
	}
	if v, err = f.need(4); err != nil {
		return nil, err
	}
	bf, err := seqFields(v)
	if err != nil {
		return nil, err
	}
	if v, err = bf.need(0); err != nil {
		return nil, err
	}
	if r.Options, err = readFlags(v); err != nil {
		return nil, err
	}
	if v, ok := bf[1]; ok {
		p, err := parsePrincipal(v)
		if err != nil {
			return nil, err
		}
		r.CName = &p
	}
	if v, err = bf.need(2); err != nil {
		return nil, err
	}
	if r.Realm, err = readString(v); err != nil {
		return nil, err
	}
	if v, ok := bf[3]; ok {
		p, err := parsePrincipal(v)
		if err != nil {
			return nil, err
		}
		r.SName = &p
	}
	if v, err = bf.need(7); err != nil {
		return nil, err
	}
	if r.Nonce, err = readUint32(v); err != nil {
		return nil, err
	}
	if v, err = bf.need(8); err != nil {
		return nil, err
	}
	err = readList(v, func(e []byte) error {
		et, err := readInt32(e)
		r.ETypes = append(r.ETypes, et)
		return err
	})
	return r, err
}

// MarshalKDCReq is used by tests and by in-process clients.
func MarshalKDCReq(r *KDCReq) []byte {
	body := [][]byte{ctx(0, flagsBits(r.Options|KDCOptCanonicalize))}
	if r.CName != nil {
		body = append(body, ctx(1, r.CName.marshal()))
	}
	body = append(body, ctx(2, genString(r.Realm)))
	if r.SName != nil {
		body = append(body, ctx(3, r.SName.marshal()))
	}
	var ets [][]byte
	for _, e := range r.ETypes {
		ets = append(ets, intg(int64(e)))
	}
	body = append(body, ctx(5, genTime(time.Date(2037, 9, 13, 2, 48, 5, 0, time.UTC))),
		ctx(7, intg(int64(r.Nonce))), ctx(8, seq(ets...)))
	parts := [][]byte{ctx(1, intg(PVNO)), ctx(2, intg(int64(r.MsgType)))}
	if r.PAData != nil {
		parts = append(parts, ctx(3, marshalPAData(r.PAData)))
	}
	parts = append(parts, ctx(4, seq(body...)))
	return app(r.MsgType, seq(parts...))
}

type EncryptionKey struct {
	Type  int32
	Value []byte
}

func (k EncryptionKey) marshal() []byte {
	return seq(ctx(0, intg(int64(k.Type))), ctx(1, octets(k.Value)))
}

func parseEncryptionKey(b []byte) (k EncryptionKey, err error) {
	f, err := seqFields(b)
	if err != nil {
		return
	}
	v, err := f.need(0)
	if err != nil {
		return
	}
	if k.Type, err = readInt32(v); err != nil {
		return
	}
	if v, err = f.need(1); err != nil {
		return
	}
	k.Value, err = readOctets(v, 64)
	return
}

type AuthData struct {
	Type int32
	Data []byte
}

func marshalAuthData(list []AuthData) []byte {
	var parts [][]byte
	for _, d := range list {
		parts = append(parts, seq(ctx(0, intg(int64(d.Type))), ctx(1, octets(d.Data))))
	}
	return seq(parts...)
}

func parseAuthData(b []byte) ([]AuthData, error) {
	var out []AuthData
	err := readList(b, func(e []byte) error {
		f, err := seqFields(e)
		if err != nil {
			return err
		}
		v, err := f.need(0)
		if err != nil {
			return err
		}
		var d AuthData
		if d.Type, err = readInt32(v); err != nil {
			return err
		}
		if v, err = f.need(1); err != nil {
			return err
		}
		if d.Data, err = readOctets(v, maxDERLen); err != nil {
			return err
		}
		out = append(out, d)
		return nil
	})
	return out, err
}

type Transited struct {
	Type     int32
	Contents []byte
}

// EncTicketPart is the encrypted part of a ticket (APPLICATION 3).
type EncTicketPart struct {
	Flags     uint32
	Key       EncryptionKey
	CRealm    string
	CName     PrincipalName
	Transited Transited
	AuthTime  time.Time
	StartTime *time.Time
	EndTime   time.Time
	AuthData  []AuthData
}

func (e *EncTicketPart) Marshal() []byte {
	parts := [][]byte{
		ctx(0, flagsBits(e.Flags)), ctx(1, e.Key.marshal()), ctx(2, genString(e.CRealm)),
		ctx(3, e.CName.marshal()),
		ctx(4, seq(ctx(0, intg(int64(e.Transited.Type))), ctx(1, octets(e.Transited.Contents)))),
		ctx(5, genTime(e.AuthTime)),
	}
	if e.StartTime != nil {
		parts = append(parts, ctx(6, genTime(*e.StartTime)))
	}
	parts = append(parts, ctx(7, genTime(e.EndTime)))
	if e.AuthData != nil {
		parts = append(parts, ctx(10, marshalAuthData(e.AuthData)))
	}
	return app(3, seq(parts...))
}

func ParseEncTicketPart(b []byte) (*EncTicketPart, error) {
	f, err := appFields(b, 3)
	if err != nil {
		return nil, err
	}
	e := &EncTicketPart{}
	v, err := f.need(0)
	if err != nil {
		return nil, err
	}
	if e.Flags, err = readFlags(v); err != nil {
		return nil, err
	}
	if v, err = f.need(1); err != nil {
		return nil, err
	}
	if e.Key, err = parseEncryptionKey(v); err != nil {
		return nil, err
	}
	if v, err = f.need(2); err != nil {
		return nil, err
	}
	if e.CRealm, err = readString(v); err != nil {
		return nil, err
	}
	if v, err = f.need(3); err != nil {
		return nil, err
	}
	if e.CName, err = parsePrincipal(v); err != nil {
		return nil, err
	}
	if v, err = f.need(4); err != nil {
		return nil, err
	}
	tf, err := seqFields(v)
	if err != nil {
		return nil, err
	}
	if v, err = tf.need(0); err != nil {
		return nil, err
	}
	if e.Transited.Type, err = readInt32(v); err != nil {
		return nil, err
	}
	if v, err = tf.need(1); err != nil {
		return nil, err
	}
	if e.Transited.Contents, err = readOctets(v, maxStringLen); err != nil {
		return nil, err
	}
	if v, err = f.need(5); err != nil {
		return nil, err
	}
	if e.AuthTime, err = readTime(v); err != nil {
		return nil, err
	}
	if v, ok := f[6]; ok {
		t, err := readTime(v)
		if err != nil {
			return nil, err
		}
		e.StartTime = &t
	}
	if v, err = f.need(7); err != nil {
		return nil, err
	}
	if e.EndTime, err = readTime(v); err != nil {
		return nil, err
	}
	if v, ok := f[10]; ok {
		if e.AuthData, err = parseAuthData(v); err != nil {
			return nil, err
		}
	}
	return e, nil
}

// Start returns the effective start time.
func (e *EncTicketPart) Start() time.Time {
	if e.StartTime != nil {
		return *e.StartTime
	}
	return e.AuthTime
}

// EncKDCRepPart is the encrypted part of AS-REP (APPLICATION 25) or TGS-REP
// (APPLICATION 26).
type EncKDCRepPart struct {
	Key       EncryptionKey
	Nonce     uint32
	KeyExpiry *time.Time
	Flags     uint32
	AuthTime  time.Time
	StartTime *time.Time
	EndTime   time.Time
	SRealm    string
	SName     PrincipalName
}

func (e *EncKDCRepPart) Marshal(msgType int) []byte {
	parts := [][]byte{
		ctx(0, e.Key.marshal()),
		ctx(1, seq()), // empty last-req, as Xombie sends
		ctx(2, intg(int64(e.Nonce))),
	}
	if e.KeyExpiry != nil {
		parts = append(parts, ctx(3, genTime(*e.KeyExpiry)))
	}
	parts = append(parts, ctx(4, flagsBits(e.Flags)), ctx(5, genTime(e.AuthTime)))
	if e.StartTime != nil {
		parts = append(parts, ctx(6, genTime(*e.StartTime)))
	}
	parts = append(parts, ctx(7, genTime(e.EndTime)), ctx(9, genString(e.SRealm)), ctx(10, e.SName.marshal()))
	tag := 25
	if msgType == MsgTGSRep {
		tag = 26
	}
	return app(tag, seq(parts...))
}

// ParseEncKDCRepPart is used by clients and tests.
func ParseEncKDCRepPart(b []byte, msgType int) (*EncKDCRepPart, error) {
	tag := 25
	if msgType == MsgTGSRep {
		tag = 26
	}
	f, err := appFields(b, tag)
	if err != nil {
		return nil, err
	}
	e := &EncKDCRepPart{}
	v, err := f.need(0)
	if err != nil {
		return nil, err
	}
	if e.Key, err = parseEncryptionKey(v); err != nil {
		return nil, err
	}
	if v, err = f.need(2); err != nil {
		return nil, err
	}
	if e.Nonce, err = readUint32(v); err != nil {
		return nil, err
	}
	if v, ok := f[3]; ok {
		t, err := readTime(v)
		if err != nil {
			return nil, err
		}
		e.KeyExpiry = &t
	}
	if v, err = f.need(4); err != nil {
		return nil, err
	}
	if e.Flags, err = readFlags(v); err != nil {
		return nil, err
	}
	if v, err = f.need(5); err != nil {
		return nil, err
	}
	if e.AuthTime, err = readTime(v); err != nil {
		return nil, err
	}
	if v, ok := f[6]; ok {
		t, err := readTime(v)
		if err != nil {
			return nil, err
		}
		e.StartTime = &t
	}
	if v, err = f.need(7); err != nil {
		return nil, err
	}
	if e.EndTime, err = readTime(v); err != nil {
		return nil, err
	}
	if v, err = f.need(9); err != nil {
		return nil, err
	}
	if e.SRealm, err = readString(v); err != nil {
		return nil, err
	}
	if v, err = f.need(10); err != nil {
		return nil, err
	}
	e.SName, err = parsePrincipal(v)
	return e, err
}

// KDCRep is an AS-REP or TGS-REP.
type KDCRep struct {
	MsgType int
	PAData  []PAData
	CRealm  string
	CName   PrincipalName
	Ticket  Ticket
	Enc     EncryptedData
}

func (r *KDCRep) Marshal() []byte {
	parts := [][]byte{ctx(0, intg(PVNO)), ctx(1, intg(int64(r.MsgType)))}
	if len(r.PAData) > 0 {
		parts = append(parts, ctx(2, marshalPAData(r.PAData)))
	}
	parts = append(parts, ctx(3, genString(r.CRealm)), ctx(4, r.CName.marshal()),
		ctx(5, r.Ticket.Marshal()), ctx(6, r.Enc.Marshal()))
	return app(r.MsgType, seq(parts...))
}

func ParseKDCRep(b []byte, msgType int) (*KDCRep, error) {
	f, err := appFields(b, msgType)
	if err != nil {
		return nil, err
	}
	r := &KDCRep{MsgType: msgType}
	if v, ok := f[2]; ok {
		if r.PAData, err = parsePAData(v); err != nil {
			return nil, err
		}
	}
	v, err := f.need(3)
	if err != nil {
		return nil, err
	}
	if r.CRealm, err = readString(v); err != nil {
		return nil, err
	}
	if v, err = f.need(4); err != nil {
		return nil, err
	}
	if r.CName, err = parsePrincipal(v); err != nil {
		return nil, err
	}
	if v, err = f.need(5); err != nil {
		return nil, err
	}
	if r.Ticket, err = ParseTicket(v); err != nil {
		return nil, err
	}
	if v, err = f.need(6); err != nil {
		return nil, err
	}
	r.Enc, err = ParseEncryptedData(v)
	return r, err
}

// Error is a KRB-ERROR (APPLICATION 30).
type Error struct {
	STime  time.Time
	Code   int32
	CRealm string
	CName  *PrincipalName
	Realm  string
	SName  PrincipalName
}

func (e *Error) Marshal() []byte {
	parts := [][]byte{ctx(0, intg(PVNO)), ctx(1, intg(MsgError)), ctx(4, genTime(e.STime)),
		ctx(5, intg(0)), ctx(6, intg(int64(e.Code)))}
	if e.CRealm != "" {
		parts = append(parts, ctx(7, genString(e.CRealm)))
	}
	if e.CName != nil {
		parts = append(parts, ctx(8, e.CName.marshal()))
	}
	parts = append(parts, ctx(9, genString(e.Realm)), ctx(10, e.SName.marshal()))
	return app(MsgError, seq(parts...))
}

func ParseError(b []byte) (*Error, error) {
	f, err := appFields(b, MsgError)
	if err != nil {
		return nil, err
	}
	e := &Error{}
	v, err := f.need(4)
	if err != nil {
		return nil, err
	}
	if e.STime, err = readTime(v); err != nil {
		return nil, err
	}
	if v, err = f.need(6); err != nil {
		return nil, err
	}
	if e.Code, err = readInt32(v); err != nil {
		return nil, err
	}
	if v, err = f.need(9); err != nil {
		return nil, err
	}
	if e.Realm, err = readString(v); err != nil {
		return nil, err
	}
	if v, err = f.need(10); err != nil {
		return nil, err
	}
	e.SName, err = parsePrincipal(v)
	return e, err
}

// IsError reports whether b is a KRB-ERROR datagram.
func IsError(b []byte) bool { return len(b) > 0 && b[0] == 0x7e }

// Authenticator (APPLICATION 2).
type Authenticator struct {
	CRealm string
	CName  PrincipalName
	CUsec  int32
	CTime  time.Time
}

func (a *Authenticator) Marshal() []byte {
	return app(2, seq(ctx(0, intg(PVNO)), ctx(1, genString(a.CRealm)), ctx(2, a.CName.marshal()),
		ctx(4, intg(int64(a.CUsec))), ctx(5, genTime(a.CTime))))
}

func ParseAuthenticator(b []byte) (*Authenticator, error) {
	f, err := appFields(b, 2)
	if err != nil {
		return nil, err
	}
	a := &Authenticator{}
	v, err := f.need(0)
	if err != nil {
		return nil, err
	}
	if n, err := readInt(v); err != nil || n != PVNO {
		return nil, malformed("authenticator-vno")
	}
	if v, err = f.need(1); err != nil {
		return nil, err
	}
	if a.CRealm, err = readString(v); err != nil {
		return nil, err
	}
	if v, err = f.need(2); err != nil {
		return nil, err
	}
	if a.CName, err = parsePrincipal(v); err != nil {
		return nil, err
	}
	if v, err = f.need(4); err != nil {
		return nil, err
	}
	if a.CUsec, err = readInt32(v); err != nil || a.CUsec < 0 || a.CUsec > 999999 {
		return nil, malformed("cusec")
	}
	if v, err = f.need(5); err != nil {
		return nil, err
	}
	a.CTime, err = readTime(v)
	return a, err
}

// APReq (APPLICATION 14), carried in PA-TGS-REQ.
type APReq struct {
	Ticket        Ticket
	Authenticator EncryptedData
}

func (r *APReq) Marshal() []byte {
	return app(MsgAPReq, seq(ctx(0, intg(PVNO)), ctx(1, intg(MsgAPReq)), ctx(2, flagsBits(0)),
		ctx(3, r.Ticket.Marshal()), ctx(4, r.Authenticator.Marshal())))
}

func ParseAPReq(b []byte) (*APReq, error) {
	f, err := appFields(b, MsgAPReq)
	if err != nil {
		return nil, err
	}
	v, err := f.need(0)
	if err != nil {
		return nil, err
	}
	if n, err := readInt(v); err != nil || n != PVNO {
		return nil, malformed("ap-req pvno")
	}
	if v, err = f.need(1); err != nil {
		return nil, err
	}
	if n, err := readInt(v); err != nil || n != MsgAPReq {
		return nil, malformed("ap-req msg-type")
	}
	r := &APReq{}
	if v, err = f.need(3); err != nil {
		return nil, err
	}
	if r.Ticket, err = ParseTicket(v); err != nil {
		return nil, err
	}
	if v, err = f.need(4); err != nil {
		return nil, err
	}
	r.Authenticator, err = ParseEncryptedData(v)
	return r, err
}

// PAEncTSEnc is the decrypted PA-ENC-TIMESTAMP payload.
type PAEncTSEnc struct {
	Time time.Time
	Usec int32
}

func (p PAEncTSEnc) Marshal() []byte {
	return seq(ctx(0, genTime(p.Time)), ctx(1, intg(int64(p.Usec))))
}

func ParsePAEncTSEnc(b []byte) (p PAEncTSEnc, err error) {
	f, err := seqFields(b)
	if err != nil {
		return
	}
	v, err := f.need(0)
	if err != nil {
		return
	}
	if p.Time, err = readTime(v); err != nil {
		return
	}
	if v, ok := f[1]; ok {
		if p.Usec, err = readInt32(v); err != nil || p.Usec < 0 || p.Usec > 999999 {
			err = malformed("pausec")
		}
	}
	return
}
