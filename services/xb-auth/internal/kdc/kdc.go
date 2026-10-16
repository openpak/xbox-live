// SPDX-License-Identifier: AGPL-3.0-only
// Package kdc is the original Xbox Live key distribution centre: AS-REQ with
// pre-authentication, and TGS-REQ that issues security-gateway tickets and the
// PA_XBOX_SERVICE_ADDRESS. It is a Go port of Xombie's services/kdc with the
// prototype's fixed keys, stored static session keys, unchecked timestamps,
// missing replay protection and panics on malformed input removed.
package kdc

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"openpak/xb-live/internal/krb"
	"openpak/xb-live/internal/xbaccountapi"
	"openpak/xb-live/internal/xbcrypto"
)

const (
	// DefaultGatewayIP is the secondary server's public address (docs/xbox/
	// secondary-gateway-deployment.md). Never a ZeroTier address.
	DefaultGatewayIP = "145.241.228.207"
	// TGTTicketVNO is what Xombie writes in the TGT's tkt-vno. The client treats
	// the TGT as opaque and echoes it, and this value is part of the measured
	// prototype behaviour; it has not been re-verified against hardware here.
	TGTTicketVNO = 0
	// BandwidthLimit is the bw_limit Xombie advertises. Meaning unmeasured.
	BandwidthLimit = 9001
	// MACSDummyKey is the placeholder session key Xombie puts in the (invalid,
	// ticketless) MACS AS-REP. It protects nothing.
	machineAccountPrefix = "SN."
)

type Config struct {
	Realm          string // client realm, "passport.net"
	TGSRealm       string // krbtgt realm, "XBOX.COM"
	Domains        []string
	GatewayIP      netip.Addr
	TGTLifetime    time.Duration
	TicketLifetime time.Duration
	ClockSkew      time.Duration
	ReplayMax      int

	TGSKeys  *krb.Keyring // encrypts TGTs, local to xb-auth
	SGKeys   *krb.Keyring // encrypts gateway tickets, shared with xb-gateway
	UserKeys *krb.Keyring // 32-byte secrets from which user account keys derive

	Now func() time.Time
}

func DefaultConfig() Config {
	return Config{
		Realm: "passport.net", TGSRealm: "XBOX.COM", Domains: []string{"@xbox.com"},
		GatewayIP:   netip.MustParseAddr(DefaultGatewayIP),
		TGTLifetime: 24 * time.Hour, TicketLifetime: 24 * time.Hour,
		ClockSkew: 5 * time.Minute, ReplayMax: 1 << 16,
	}
}

// PublicIPv4 reports whether ip is a routable unicast IPv4 address that a
// console on the Internet can reach (no loopback, private, CGNAT, link-local).
func PublicIPv4(ip netip.Addr) bool {
	if !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	return !netip.MustParsePrefix("100.64.0.0/10").Contains(ip)
}

type KDC struct {
	cfg      Config
	accounts xbaccountapi.Resolver // gamertag, XUID and device admission (xb-account)
	devices  DeviceKeys            // per-console proof material for MACS
	replay   *ReplayCache
	tgsName  krb.PrincipalName
	macsName krb.PrincipalName
}

func New(cfg Config, accounts xbaccountapi.Resolver, devices DeviceKeys) (*KDC, error) {
	switch {
	case accounts == nil || devices == nil:
		return nil, errors.New("kdc: account resolver and device key store required")
	case cfg.TGSKeys == nil || cfg.SGKeys == nil || cfg.UserKeys == nil:
		return nil, errors.New("kdc: TGS, SG and user key rings are required")
	case cfg.TGSKeys.Shares(cfg.SGKeys) || cfg.TGSKeys.Shares(cfg.UserKeys) || cfg.SGKeys.Shares(cfg.UserKeys):
		return nil, errors.New("kdc: key rings must not share key material")
	case !PublicIPv4(cfg.GatewayIP):
		return nil, errors.New("kdc: gateway address must be a public IPv4 address")
	case cfg.TGTLifetime <= 0 || cfg.TicketLifetime <= 0 || cfg.ClockSkew <= 0 || cfg.ReplayMax <= 0:
		return nil, errors.New("kdc: lifetimes, skew and replay bound must be positive")
	case cfg.Realm == "" || cfg.TGSRealm == "" || len(cfg.Domains) == 0:
		return nil, errors.New("kdc: realms and domains required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &KDC{cfg: cfg, accounts: accounts, devices: devices,
		replay:   NewReplayCache(2*cfg.ClockSkew+time.Second, cfg.ReplayMax),
		tgsName:  krb.PrincipalName{Type: krb.NameTypeSrvInst, Parts: []string{"krbtgt", cfg.TGSRealm}},
		macsName: krb.PrincipalName{Type: krb.NameTypeSrvInst, Parts: []string{"krbtgt", krb.MACSRealm}}}, nil
}

// Handle processes one datagram and returns the reply, or nil when the input
// is not a valid KDC request (it is silently dropped, never answered).
func (k *KDC) Handle(ctx context.Context, datagram []byte) []byte {
	req, err := krb.ParseKDCReq(datagram)
	if err != nil {
		log.Printf("xb-auth request unparseable len=%d", len(datagram))
		return nil
	}
	start := time.Now()
	now := k.cfg.Now().UTC().Truncate(time.Second)
	var reply []byte
	switch req.MsgType {
	case krb.MsgASReq:
		reply = k.handleAS(ctx, req, now)
	default:
		reply = k.handleTGS(ctx, req, now)
	}
	// One line per request: message type, realm class, result code, duration.
	// Never names, keys, tickets or pre-authentication data.
	kind, class := "tgs", "user"
	if req.MsgType == krb.MsgASReq {
		kind = "as"
	}
	if req.Realm == krb.MACSRealm || req.SName != nil && req.SName.Equal(k.macsName) {
		class = "macs"
	}
	result := "ok"
	switch {
	case reply == nil:
		result = "dropped"
	case krb.IsError(reply):
		result = "error"
		if e, perr := krb.ParseError(reply); perr == nil {
			result = fmt.Sprintf("error=%d", e.Code)
		}
	}
	log.Printf("xb-auth %s class=%s result=%s dur=%s", kind, class, result, time.Since(start).Round(time.Millisecond))
	return reply
}

func (k *KDC) fail(code int32, now time.Time, cname *krb.PrincipalName) []byte {
	return (&krb.Error{STime: now, Code: code, Realm: k.cfg.Realm, SName: k.tgsName, CName: cname}).Marshal()
}

func (k *KDC) failMACS(code int32, now time.Time, cname *krb.PrincipalName) []byte {
	return (&krb.Error{STime: now, Code: code, CRealm: krb.MACSRealm, Realm: krb.MACSRealm, SName: k.macsName, CName: cname}).Marshal()
}

func (k *KDC) gamertag(p krb.PrincipalName) (string, bool) {
	if p.Type != krb.NameTypeEnterprise || len(p.Parts) != 1 {
		return "", false
	}
	name := p.Parts[0]
	for _, d := range k.cfg.Domains {
		if len(name) > len(d) && strings.EqualFold(name[len(name)-len(d):], d) {
			g := name[:len(name)-len(d)]
			return g, validGamertag(g)
		}
	}
	return "", false
}

func validGamertag(g string) bool {
	if len(g) < 1 || len(g) > 15 || strings.TrimSpace(g) != g {
		return false
	}
	for _, c := range g {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == ' ' || c == '.' || c == '_') {
			return false
		}
	}
	return true
}

func (k *KDC) skewOK(t, now time.Time) bool {
	d := now.Sub(t)
	return d <= k.cfg.ClockSkew && d >= -k.cfg.ClockSkew
}

func xuidLE(x uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], x)
	return b[:]
}

// denial maps a non-nil resolver error to a KRB-ERROR code.
func denial(err error) int32 {
	var denied *xbaccountapi.DeniedError
	switch {
	case errors.As(err, &denied):
		switch denied.Principal.Status {
		case xbaccountapi.StatusUnlinked, xbaccountapi.StatusDeleted:
			return krb.ErrCPrincipalUnknown
		}
		return krb.ErrClientRevoked
	case errors.Is(err, xbaccountapi.ErrNotFound), errors.Is(err, xbaccountapi.ErrInvalid):
		return krb.ErrCPrincipalUnknown
	}
	return krb.ErrSvcUnavailable
}

// admitted validates a resolver answer for the expected kind (and id, if
// non-empty) and returns the numeric principal id, or an error code.
func admitted(p xbaccountapi.Principal, err error, kind xbaccountapi.Kind, id string) (uint64, int32) {
	if err != nil {
		return 0, denial(err)
	}
	if p.Kind != kind || p.Status != xbaccountapi.StatusActive || !xbaccountapi.ValidID(p.PrincipalID) ||
		p.CoreAccountID == "" || (id != "" && p.PrincipalID != id) {
		return 0, krb.ErrSvcUnavailable // a malformed "success" is never trusted
	}
	n, perr := strconv.ParseUint(p.PrincipalID, 16, 64)
	if perr != nil || n == 0 {
		return 0, krb.ErrSvcUnavailable
	}
	return n, 0
}

func (k *KDC) admitUser(ctx context.Context, xuid uint64) int32 {
	id := fmt.Sprintf("%016x", xuid)
	p, err := k.accounts.ResolveUser(ctx, id)
	_, code := admitted(p, err, xbaccountapi.KindUser, id)
	return code
}

func (k *KDC) admitDevice(ctx context.Context, machineID uint64) int32 {
	id := fmt.Sprintf("%016x", machineID)
	p, err := k.accounts.ResolveDevice(ctx, id)
	_, code := admitted(p, err, xbaccountapi.KindDevice, id)
	return code
}

func hash(parts ...[]byte) [32]byte {
	h := sha256.New()
	for _, p := range parts {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(p)))
		h.Write(l[:])
		h.Write(p)
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

func hasETypeRC4(req *krb.KDCReq) bool {
	for _, e := range req.ETypes {
		if e == krb.ETypeRC4HMAC {
			return true
		}
	}
	return false
}

// machineSession validates the PA-MSKILE-COMPOUND-IDENTITY payload: exactly one
// unexpired TGT that this KDC issued to a console's machine account (it carries
// the device authorization entry and no user entry), for a device that is
// still admitted. It returns the TGT session key, which is mixed into the
// user's key.
func (k *KDC) machineSession(ctx context.Context, value []byte, now time.Time) (*xbcrypto.Key, bool) {
	tickets, err := krb.ParseTicketSequence(value)
	if err != nil || len(tickets) != 1 || !tickets[0].SName.Equal(k.tgsName) {
		return nil, false
	}
	part, err := krb.OpenTicket(k.cfg.TGSKeys, krb.UsageTicket, tickets[0])
	if err != nil || part.CRealm != k.cfg.Realm || part.Key.Type != krb.ETypeRC4HMAC ||
		part.Flags&krb.FlagInvalid != 0 || part.Start().After(now.Add(k.cfg.ClockSkew)) || !part.EndTime.After(now) {
		return nil, false
	}
	var device uint64
	for _, ad := range part.AuthData {
		switch {
		case ad.Type == krb.ADUsers:
			return nil, false
		case ad.Type == krb.ADDevice && len(ad.Data) == 8:
			device = binary.LittleEndian.Uint64(ad.Data)
		}
	}
	if device == 0 || k.admitDevice(ctx, device) != 0 {
		return nil, false
	}
	key, err := krb.ToKey(part.Key.Value)
	if err != nil {
		return nil, false
	}
	return &key, true
}

func (k *KDC) handleAS(ctx context.Context, req *krb.KDCReq, now time.Time) []byte {
	if req.SName != nil && req.SName.Equal(k.macsName) {
		return k.handleMACS(ctx, req, now)
	}
	if req.CName == nil {
		return k.fail(krb.ErrCPrincipalUnknown, now, nil)
	}
	cname := req.CName
	gamertag, ok := k.gamertag(*cname)
	if !ok {
		return k.fail(krb.ErrCPrincipalUnknown, now, cname)
	}
	if !hasETypeRC4(req) {
		return k.fail(krb.ErrETypeNoSupp, now, cname)
	}
	_, hasVersion := krb.FindPA(req.PAData, krb.PAXboxClientVersion)
	tsRaw, hasTS := krb.FindPA(req.PAData, krb.PAEncTimestamp)
	if !hasVersion || !hasTS {
		return k.fail(krb.ErrPreauthRequired, now, cname)
	}

	// Who is it? A console's machine account (gamertag SN.<serial>) or a user.
	var id uint64
	var derive func([]byte) xbcrypto.Key
	var authData krb.AuthData
	var code int32
	if serial, isMachine := strings.CutPrefix(gamertag, machineAccountPrefix); isMachine {
		mid, n, err := krb.MachineIDFromSerial(serial)
		if err != nil {
			return k.fail(krb.ErrCPrincipalUnknown, now, cname)
		}
		p, rerr := k.accounts.ResolveDevice(ctx, mid)
		if id, code = admitted(p, rerr, xbaccountapi.KindDevice, mid); code != 0 {
			return k.fail(code, now, cname)
		}
		_ = n
		derive = func(secret []byte) xbcrypto.Key { return krb.DeriveDeviceKey(secret, id) }
		authData = krb.AuthData{Type: krb.ADDevice, Data: xuidLE(id)}
	} else {
		p, rerr := k.accounts.ResolveGamertag(ctx, gamertag)
		if id, code = admitted(p, rerr, xbaccountapi.KindUser, ""); code != 0 {
			return k.fail(code, now, cname)
		}
		derive = func(secret []byte) xbcrypto.Key { return krb.DeriveUserKey(secret, id) }
		authData = krb.AuthData{Type: krb.ADUsers, Data: xuidLE(id)}
	}

	var machine *xbcrypto.Key
	if raw, present := findAny(req.PAData, krb.PACompoundIdentity); present {
		if authData.Type == krb.ADDevice {
			return k.fail(krb.ErrPreauthFailed, now, cname) // a machine account has no machine
		}
		if machine, ok = k.machineSession(ctx, raw, now); !ok {
			log.Printf("xb-auth as: preauth failed: compound machine ticket rejected (payload %d bytes)", len(raw))
			return k.fail(krb.ErrPreauthFailed, now, cname)
		}
	}
	enc, err := krb.ParseEncryptedData(tsRaw)
	if err != nil {
		log.Printf("xb-auth as: preauth failed: PA-ENC-TIMESTAMP not parseable (%d bytes)", len(tsRaw))
		return k.fail(krb.ErrPreauthFailed, now, cname)
	}
	var clientKey xbcrypto.Key
	var ts krb.PAEncTSEnc
	matched := false
	for _, kid := range k.cfg.UserKeys.IDs() {
		secret, _ := k.cfg.UserKeys.Get(kid)
		candidate := derive(secret)
		if machine != nil {
			candidate = xbcrypto.CompoundKey(candidate, *machine)
		}
		plain, err := krb.Open(candidate, krb.UsageASReqTimestamp, enc)
		if err != nil {
			continue
		}
		if ts, err = krb.ParsePAEncTSEnc(plain); err != nil {
			log.Printf("xb-auth as: preauth failed: timestamp decrypted but unparseable (plain %d bytes, compound=%t, key id %d)", len(plain), machine != nil, kid)
			return k.fail(krb.ErrPreauthFailed, now, cname)
		}
		clientKey, matched = candidate, true
		break
	}
	if !matched {
		log.Printf("xb-auth as: preauth failed: timestamp did not decrypt under any user-key candidate (compound=%t, keys=%d)", machine != nil, len(k.cfg.UserKeys.IDs()))
		return k.fail(krb.ErrPreauthFailed, now, cname)
	}
	if !k.skewOK(ts.Time, now) {
		return k.fail(krb.ErrAPSkew, now, cname)
	}
	// Only authenticated requests enter the replay cache, so garbage cannot fill it.
	if code := k.recordReplay(hash([]byte("as"), xuidLE(id), enc.Cipher), now); code != 0 {
		return k.fail(code, now, cname)
	}

	session, err := krb.NewSessionKey()
	if err != nil {
		return k.fail(krb.ErrSvcUnavailable, now, cname)
	}
	end := now.Add(k.cfg.TGTLifetime)
	start := now
	part := &krb.EncTicketPart{
		Flags:     krb.FlagInitial | krb.FlagPreAuth,
		Key:       krb.EncryptionKey{Type: krb.ETypeRC4HMAC, Value: session[:]},
		CRealm:    k.cfg.Realm,
		CName:     *cname,
		Transited: krb.Transited{Type: 1, Contents: []byte(k.cfg.Realm + "\x00")},
		AuthTime:  now, StartTime: &start, EndTime: end,
		AuthData: []krb.AuthData{authData},
	}
	tgsID, tgsRaw := k.cfg.TGSKeys.Active()
	tgsKey, _ := krb.ToKey(tgsRaw)
	ticketEnc, err := krb.Seal(tgsKey, krb.UsageTicket, &tgsID, part.Marshal())
	if err != nil {
		return k.fail(krb.ErrSvcUnavailable, now, cname)
	}
	rep := &krb.EncKDCRepPart{Key: part.Key, Nonce: req.Nonce, Flags: part.Flags, AuthTime: now,
		StartTime: &start, EndTime: end, SRealm: k.cfg.TGSRealm, SName: k.tgsName}
	repEnc, err := krb.Seal(clientKey, krb.UsageKDCRepPart, nil, rep.Marshal(krb.MsgASRep))
	if err != nil {
		return k.fail(krb.ErrSvcUnavailable, now, cname)
	}
	return (&krb.KDCRep{MsgType: krb.MsgASRep, CRealm: k.cfg.Realm, CName: *cname,
		Ticket: krb.Ticket{VNO: TGTTicketVNO, Realm: k.cfg.Realm, SName: k.tgsName, Enc: ticketEnc},
		Enc:    repEnc}).Marshal()
}

func (k *KDC) recordReplay(key [32]byte, now time.Time) int32 {
	switch err := k.replay.CheckAndAdd(key, now); {
	case err == nil:
		return 0
	case errors.Is(err, ErrFull):
		return krb.ErrSvcUnavailable
	}
	return krb.ErrAPRepeat
}

func findAny(list []krb.PAData, typ int32) ([]byte, bool) {
	for _, d := range list {
		if d.Type == typ {
			return d.Value, true
		}
	}
	return nil, false
}

func validServiceName(p *krb.PrincipalName) bool {
	if p == nil || len(p.Parts) < 1 || len(p.Parts) > 3 || strings.EqualFold(p.Parts[0], "krbtgt") {
		return false
	}
	for _, s := range p.Parts {
		if s == "" || len(s) > 64 {
			return false
		}
	}
	return true
}

func (k *KDC) handleTGS(ctx context.Context, req *krb.KDCReq, now time.Time) []byte {
	// Without an authenticated ticket there is no principal to address an
	// error to; errors below name only what the (validated) TGT carries.
	apRaw, ok := krb.FindPA(req.PAData, krb.PAAPReq)
	if !ok {
		return k.fail(krb.ErrPreauthRequired, now, nil)
	}
	ap, err := krb.ParseAPReq(apRaw)
	if err != nil {
		return nil
	}
	if !ap.Ticket.SName.Equal(k.tgsName) {
		return k.fail(krb.ErrSPrincipalUnknown, now, nil)
	}
	tgt, err := krb.OpenTicket(k.cfg.TGSKeys, krb.UsageTicket, ap.Ticket)
	if err != nil {
		return k.fail(krb.ErrAPModified, now, nil)
	}
	cname := &tgt.CName
	if tgt.Flags&krb.FlagInvalid != 0 || tgt.Start().After(now.Add(k.cfg.ClockSkew)) || !tgt.EndTime.After(now) {
		return k.fail(krb.ErrAPTktExpired, now, cname)
	}
	if tgt.CRealm != k.cfg.Realm || tgt.Key.Type != krb.ETypeRC4HMAC {
		return k.fail(krb.ErrAPModified, now, cname)
	}
	var tgtXUID, tgtDevice uint64
	for _, ad := range tgt.AuthData {
		switch {
		case ad.Type == krb.ADUsers && len(ad.Data) == 8:
			tgtXUID = binary.LittleEndian.Uint64(ad.Data)
		case ad.Type == krb.ADDevice && len(ad.Data) == 8:
			tgtDevice = binary.LittleEndian.Uint64(ad.Data)
		}
	}
	// A machine TGT (device entry, no user) may request a service ticket for
	// the machine account itself, as a real console does before any user has
	// signed in (account creation). A TGT carrying both is malformed.
	if tgtXUID != 0 && tgtDevice != 0 {
		return k.fail(krb.ErrAPModified, now, cname)
	}
	machineOnly := tgtXUID == 0 && tgtDevice != 0
	if machineOnly {
		tgtXUID = tgtDevice
	}
	sessionKey, err := krb.ToKey(tgt.Key.Value)
	if err != nil || tgtXUID == 0 {
		return k.fail(krb.ErrAPModified, now, cname)
	}

	authPlain, err := krb.Open(sessionKey, krb.UsageTGSReqAuth, ap.Authenticator)
	if err != nil {
		return k.fail(krb.ErrAPBadIntegrity, now, cname)
	}
	auth, err := krb.ParseAuthenticator(authPlain)
	if err != nil {
		return k.fail(krb.ErrAPBadIntegrity, now, cname)
	}
	if auth.CRealm != tgt.CRealm || !auth.CName.Equal(tgt.CName) {
		return k.fail(krb.ErrAPModified, now, cname)
	}
	if !k.skewOK(auth.CTime, now) {
		return k.fail(krb.ErrAPSkew, now, cname)
	}
	if code := k.recordReplay(hash([]byte("tgs"), ap.Ticket.Enc.Cipher, ap.Authenticator.Cipher), now); code != 0 {
		return k.fail(code, now, cname)
	}
	if !validServiceName(req.SName) || len(req.Realm) == 0 {
		return k.fail(krb.ErrSPrincipalUnknown, now, cname)
	}

	// Re-check admission on every request so a ban or unlink stops new
	// tickets at once.
	admit := k.admitUser
	if machineOnly {
		admit = k.admitDevice
	}
	if code := admit(ctx, tgtXUID); code != 0 {
		return k.fail(code, now, cname)
	}
	principal := struct{ XUID uint64 }{tgtXUID}

	// Optional service request.
	var pas []krb.PAData
	var address *krb.ServiceAddress
	nonceKey := xbcrypto.NonceKey(sessionKey, req.Nonce)
	if raw, present := findAny(req.PAData, krb.PAXboxServiceRequest); present {
		if _, unique := krb.FindPA(req.PAData, krb.PAXboxServiceRequest); !unique {
			return k.fail(krb.ErrPolicy, now, cname)
		}
		encSR, err := krb.ParseEncryptedData(raw)
		if err != nil {
			return k.fail(krb.ErrPolicy, now, cname)
		}
		plain, err := krb.Open(nonceKey, krb.UsageServiceRequest, encSR)
		if err != nil {
			return k.fail(krb.ErrPolicy, now, cname)
		}
		sr, err := krb.ParseServiceRequest(plain)
		if err != nil {
			return k.fail(krb.ErrPolicy, now, cname)
		}
		address = k.serviceAddress(sr, principal.XUID)
		encAddr, err := krb.Seal(nonceKey, krb.UsageServiceAddress, nil, address.Marshal())
		if err != nil {
			return k.fail(krb.ErrSvcUnavailable, now, cname)
		}
		pas = []krb.PAData{{Type: krb.PAXboxServiceAddress, Value: encAddr.Marshal()}}
	}

	svcSession, err := krb.NewSessionKey()
	if err != nil {
		return k.fail(krb.ErrSvcUnavailable, now, cname)
	}
	end := now.Add(k.cfg.TicketLifetime)
	if end.After(tgt.EndTime) {
		end = tgt.EndTime
	}
	ad := []krb.AuthData{{Type: krb.ADUsers, Data: xuidLE(principal.XUID)}}
	if address != nil {
		ad = append(ad, krb.AuthData{Type: krb.ADServiceAddresses, Data: address.Marshal()})
	}
	part := &krb.EncTicketPart{
		Flags: krb.FlagPreAuth, Key: krb.EncryptionKey{Type: krb.ETypeRC4HMAC, Value: svcSession[:]},
		CRealm: tgt.CRealm, CName: tgt.CName, AuthTime: now, EndTime: end, AuthData: ad,
	}
	sgID, sgRaw := k.cfg.SGKeys.Active()
	sgKey, _ := krb.ToKey(sgRaw)
	ticketEnc, err := krb.Seal(sgKey, krb.UsageSGTicket, &sgID, part.Marshal())
	if err != nil {
		return k.fail(krb.ErrSvcUnavailable, now, cname)
	}
	rep := &krb.EncKDCRepPart{Key: part.Key, Nonce: req.Nonce, Flags: part.Flags, AuthTime: now,
		EndTime: end, SRealm: req.Realm, SName: *req.SName}
	repEnc, err := krb.Seal(sessionKey, krb.UsageKDCRepPart, nil, rep.Marshal(krb.MsgTGSRep))
	if err != nil {
		return k.fail(krb.ErrSvcUnavailable, now, cname)
	}
	return (&krb.KDCRep{MsgType: krb.MsgTGSRep, PAData: pas, CRealm: k.cfg.Realm, CName: tgt.CName,
		Ticket: krb.Ticket{VNO: krb.PVNO, Realm: req.Realm, SName: *req.SName, Enc: ticketEnc},
		Enc:    repEnc}).Marshal()
}

// ServicePort is the gateway port Xombie assigns to a service id (id + 100).
func ServicePort(id uint32) uint16 { return uint16(id + 100) }

// serviceAddress builds the address block. A requested user slot is granted
// only for the authenticated principal's own XUID; the prototype granted any
// non-zero XUID.
func (k *KDC) serviceAddress(sr *krb.ServiceRequest, xuid uint64) *krb.ServiceAddress {
	a := &krb.ServiceAddress{BWLimit: BandwidthLimit, SiteIP: k.cfg.GatewayIP, NumServices: sr.NumServices}
	for i := range a.HRUser {
		switch sr.XUIDs[i] {
		case 0:
			a.HRUser[i] = krb.HRInvalidService
		case xuid:
			a.HRUser[i] = krb.HRSuccess
		default:
			a.HRUser[i] = krb.HRAccessDenied
		}
	}
	for i := range a.Results {
		a.Results[i].HR = 0x80000000 // unused slot, as Xombie fills it
	}
	for i := uint32(0); i < sr.NumServices; i++ {
		id := sr.ServiceIDs[i]
		r := krb.ServiceResult{ID: id}
		switch {
		case id == 0:
			r.HR = krb.HRInvalidService
		case id <= krb.MaxServiceID:
			r.Port = ServicePort(id)
		default:
			r.HR = krb.HRUnknownService
		}
		a.Results[i] = r
	}
	return a
}

// UserAccountBlob returns the account blob a console stores for a user
// provisioned by xb-account: xuid, gamertag, domain, realm and the user's
// account key (krb.DeriveUserKey under the active user-key secret), the same
// layout and key AS pre-authentication later verifies. It is only produced for
// a currently admitted user. The blob is key material: the caller must seal it
// for the console (as MACS does with the machine key) and never log it.
func (k *KDC) UserAccountBlob(ctx context.Context, xuid string) ([]byte, error) {
	p, err := k.accounts.ResolveUser(ctx, xuid)
	n, code := admitted(p, err, xbaccountapi.KindUser, xuid)
	if code != 0 {
		return nil, fmt.Errorf("kdc: user not admitted (krb error %d)", code)
	}
	if !validGamertag(p.Gamertag) {
		return nil, errors.New("kdc: user has no usable gamertag")
	}
	_, secret := k.cfg.UserKeys.Active()
	return krb.MachineAccount{XUID: n, Gamertag: p.Gamertag, Domain: strings.TrimPrefix(k.cfg.Domains[0], "@"),
		Realm: k.cfg.Realm, Key: krb.DeriveUserKey(secret, n)}.Marshal()
}
