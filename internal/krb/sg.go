// SPDX-License-Identifier: AGPL-3.0-only
package krb

import "time"

// Messages of the native security-gateway key exchange (AP-REQ authenticator
// with checksum, AP-REP). Added for xb-gateway; the KDC does not use them.

const (
	MsgAPRep            = 15
	UsageAPReqAuth      = 11 // KRB_KEY_USAGE_AP_REQ_AUTHEN
	UsageAPRepEncPart   = 12 // KRB_KEY_USAGE_AP_REP_ENC_PART
	ChecksumTypeSGParam = -131
)

// SGAuthenticator is an authenticator that may carry the init-parameter
// checksum (cksum, field 3) and a sequence number (field 7).
type SGAuthenticator struct {
	Authenticator
	CksumType int32
	Cksum     []byte // nil when absent
	SeqNumber *uint32
}

func (a *SGAuthenticator) Marshal() []byte {
	parts := [][]byte{ctx(0, intg(PVNO)), ctx(1, genString(a.CRealm)), ctx(2, a.CName.marshal())}
	if a.Cksum != nil {
		parts = append(parts, ctx(3, seq(ctx(0, intg(int64(a.CksumType))), ctx(1, octets(a.Cksum)))))
	}
	parts = append(parts, ctx(4, intg(int64(a.CUsec))), ctx(5, genTime(a.CTime)))
	if a.SeqNumber != nil {
		parts = append(parts, ctx(7, intg(int64(*a.SeqNumber))))
	}
	return app(2, seq(parts...))
}

func ParseSGAuthenticator(b []byte) (*SGAuthenticator, error) {
	base, err := ParseAuthenticator(b)
	if err != nil {
		return nil, err
	}
	f, err := appFields(b, 2)
	if err != nil {
		return nil, err
	}
	out := &SGAuthenticator{Authenticator: *base}
	if v, ok := f[3]; ok {
		cf, err := seqFields(v)
		if err != nil {
			return nil, err
		}
		t, err := cf.need(0)
		if err != nil {
			return nil, err
		}
		if out.CksumType, err = readInt32(t); err != nil {
			return nil, err
		}
		if t, err = cf.need(1); err != nil {
			return nil, err
		}
		if out.Cksum, err = readOctets(t, 64); err != nil {
			return nil, err
		}
	}
	if v, ok := f[7]; ok {
		n, err := readUint32(v)
		if err != nil {
			return nil, err
		}
		out.SeqNumber = &n
	}
	return out, nil
}

// EncAPRepPart is the encrypted part of an AP-REP (APPLICATION 27).
type EncAPRepPart struct {
	CTime     time.Time
	CUsec     int32
	Subkey    *EncryptionKey
	SeqNumber *uint32
}

func (e *EncAPRepPart) Marshal() []byte {
	parts := [][]byte{ctx(0, genTime(e.CTime)), ctx(1, intg(int64(e.CUsec)))}
	if e.Subkey != nil {
		parts = append(parts, ctx(2, e.Subkey.marshal()))
	}
	if e.SeqNumber != nil {
		parts = append(parts, ctx(3, intg(int64(*e.SeqNumber))))
	}
	return app(27, seq(parts...))
}

// MarshalAPRep wraps encrypted EncAPRepPart data in an AP-REP (APPLICATION 15).
func MarshalAPRep(enc EncryptedData) []byte {
	return app(MsgAPRep, seq(ctx(0, intg(PVNO)), ctx(1, intg(MsgAPRep)), ctx(2, enc.Marshal())))
}

// ParseAPRep returns the encrypted part of an AP-REP.
func ParseAPRep(b []byte) (EncryptedData, error) {
	f, err := appFields(b, MsgAPRep)
	if err != nil {
		return EncryptedData{}, err
	}
	v, err := f.need(2)
	if err != nil {
		return EncryptedData{}, err
	}
	return ParseEncryptedData(v)
}

// ParseEncAPRepPart decodes a decrypted EncAPRepPart.
func ParseEncAPRepPart(b []byte) (*EncAPRepPart, error) {
	f, err := appFields(b, 27)
	if err != nil {
		return nil, err
	}
	e := &EncAPRepPart{}
	v, err := f.need(0)
	if err != nil {
		return nil, err
	}
	if e.CTime, err = readTime(v); err != nil {
		return nil, err
	}
	if v, err = f.need(1); err != nil {
		return nil, err
	}
	if e.CUsec, err = readInt32(v); err != nil {
		return nil, err
	}
	if v, ok := f[2]; ok {
		k, err := parseEncryptionKey(v)
		if err != nil {
			return nil, err
		}
		e.Subkey = &k
	}
	return e, nil
}
