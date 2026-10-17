// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"encoding/binary"
	"errors"
	"strconv"
	"time"

	"openpak/xb-live/internal/krb"
)

// KrbVerifier validates native AP-REQs carrying xb-auth service tickets. The
// ticket is opened with the shared SG keyring (key version = rotation id), so
// tickets issued under an older key keep working until that id is removed.
type KrbVerifier struct {
	SGKeys *krb.Keyring
}

var errTicket = errors.New("gateway: ticket rejected")

// TicketError is errTicket with the failed check, for the rejection log. It
// names the check only, never ticket contents.
type TicketError struct{ Reason string }

func (e *TicketError) Error() string   { return "gateway: ticket rejected: " + e.Reason }
func (e *TicketError) Is(t error) bool { return t == errTicket }

func ticketErr(reason string) error { return &TicketError{reason} }

func (v KrbVerifier) VerifyAPReq(apReq []byte, now time.Time) (*Identity, error) {
	req, err := krb.ParseAPReq(apReq)
	if err != nil || req.Ticket.VNO != krb.PVNO {
		return nil, ticketErr("ap-req parse or ticket version")
	}
	part, err := krb.OpenTicket(v.SGKeys, krb.UsageSGTicket, req.Ticket)
	if err != nil || part.Flags&krb.FlagInvalid != 0 || part.Key.Type != krb.ETypeRC4HMAC {
		return nil, ticketErr("ticket does not open under the sg keyring (kvno/key/flags)")
	}
	sessionKey, err := krb.ToKey(part.Key.Value)
	if err != nil {
		return nil, ticketErr("session key")
	}
	plain, err := krb.Open(sessionKey, krb.UsageAPReqAuth, req.Authenticator)
	if err != nil {
		return nil, ticketErr("authenticator does not decrypt")
	}
	auth, err := krb.ParseSGAuthenticator(plain)
	if err != nil {
		return nil, ticketErr("authenticator parse")
	}
	if auth.CRealm != part.CRealm {
		return nil, ticketErr("authenticator realm differs from ticket")
	}
	if !auth.CName.Equal(part.CName) {
		return nil, ticketErr("authenticator client name differs from ticket")
	}
	if auth.CksumType != krb.ChecksumTypeSGParam || len(auth.Cksum) == 0 {
		return nil, ticketErr("authenticator checksum type")
	}
	var xuid uint64
	var users, addrs int
	var address *krb.ServiceAddress
	for _, ad := range part.AuthData {
		switch ad.Type {
		case krb.ADUsers:
			users++
			if len(ad.Data) != 8 {
				return nil, ticketErr("users entry size")
			}
			xuid = binary.LittleEndian.Uint64(ad.Data)
		case krb.ADServiceAddresses:
			addrs++
			if address, err = krb.ParseServiceAddress(ad.Data); err != nil {
				return nil, ticketErr("service address entry")
			}
		}
	}
	if users != 1 || addrs != 1 || xuid == 0 || address.NumServices > krb.MaxServices {
		return nil, ticketErr("authorization data (users/service addresses count or xuid)")
	}
	id := &Identity{XUID: xuid, SessionKey: sessionKey, GatewayIP: address.SiteIP,
		TicketStart: part.Start(), TicketEnd: part.EndTime,
		AuthTime: auth.CTime.Add(time.Duration(auth.CUsec) * time.Microsecond), Checksum: auth.Cksum}
	if kv := req.Ticket.Enc.KVNO; kv != nil {
		id.KeyID = strconv.FormatUint(uint64(*kv), 10)
	}
	for _, r := range address.Results[:address.NumServices] {
		if r.HR == 0 && r.Port != 0 {
			id.Services = append(id.Services, ServiceMapping{ID: r.ID, Port: r.Port})
		}
	}
	id.BuildAPRep = func(subkey []byte) ([]byte, error) {
		enc := &krb.EncAPRepPart{CTime: auth.CTime, CUsec: auth.CUsec,
			Subkey: &krb.EncryptionKey{Type: krb.ChecksumTypeSGParam, Value: subkey}, SeqNumber: auth.SeqNumber}
		sealed, err := krb.Seal(sessionKey, krb.UsageAPRepEncPart, nil, enc.Marshal())
		if err != nil {
			return nil, err
		}
		return krb.MarshalAPRep(sealed), nil
	}
	return id, nil
}
