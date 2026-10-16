// SPDX-License-Identifier: AGPL-3.0-only
package kdc_test

import (
	"bytes"
	"encoding/binary"
	"slices"
	"testing"
	"time"

	"openpak/xb-live/internal/krb"
	"openpak/xb-live/internal/xbaccountapi"
	"openpak/xb-live/internal/xbcrypto"
	"openpak/xb-live/services/xb-auth/internal/kdc"
)

const (
	serial    = "123456789012"
	machineID = "0000001cbe991a14" // 123456789012 in hex, zero padded
)

var machineKey = xbcrypto.Key{0xa1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

func (e *env) provisionDevice(st xbaccountapi.Status, withKey bool) {
	var k *xbcrypto.Key
	if withKey {
		k = &machineKey
	}
	e.res.SetDevice(machineID, st, k)
}

func (e *env) macsReq(key xbcrypto.Key, ts time.Time, nonce uint32, mutate ...func(*krb.KDCReq)) []byte {
	e.t.Helper()
	enc, err := krb.Seal(key, krb.UsageASReqTimestamp, nil, krb.PAEncTSEnc{Time: ts, Usec: 7}.Marshal())
	if err != nil {
		e.t.Fatal(err)
	}
	sn := krb.PrincipalName{Type: krb.NameTypeSrvInst, Parts: []string{"krbtgt", krb.MACSRealm}}
	r := &krb.KDCReq{MsgType: krb.MsgASReq, Realm: krb.MACSRealm, SName: &sn, Nonce: nonce,
		CName:  &krb.PrincipalName{Type: krb.NameTypeEnterprise, Parts: []string{serial}},
		ETypes: []int32{krb.ETypeRC4HMAC},
		PAData: []krb.PAData{
			{Type: krb.PAEncTimestamp, Value: enc.Marshal()},
			{Type: krb.PAForCheckDups, Value: []byte{1, 2, 3}},
			{Type: krb.PAXboxPPA, Value: []byte{4, 5}},
			{Type: krb.PAXboxClientVersion, Value: krb.SignClientVersion(machineKey, []byte("Version=1.00.5849.3 Title=0xFFFE0000\x00"))},
		}}
	for _, m := range mutate {
		m(r)
	}
	return krb.MarshalKDCReq(r)
}

func (e *env) macsErr(reply []byte, code int32) {
	e.t.Helper()
	e.mustErr(reply, code)
	pe, _ := krb.ParseError(reply)
	if pe.Realm != krb.MACSRealm {
		e.t.Fatalf("MACS error must name the MACS realm, got %q", pe.Realm)
	}
}

// readAccount performs the console side of MACS and returns the account blob.
func (e *env) macsAccount(nonce uint32) []byte {
	e.t.Helper()
	reply := e.handle(e.macsReq(machineKey, e.clock.Now(), nonce))
	if reply == nil || krb.IsError(reply) {
		e.t.Fatalf("MACS failed: %x", reply)
	}
	rep, err := krb.ParseKDCRep(reply, krb.MsgASRep)
	if err != nil {
		e.t.Fatal(err)
	}
	if rep.Ticket.Enc.EType != 0 || string(rep.Ticket.Enc.Cipher) != "empty" {
		e.t.Fatal("MACS must not issue a ticket")
	}
	plain, err := krb.Open(machineKey, krb.UsageKDCRepPart, rep.Enc)
	if err != nil {
		e.t.Fatal("reply part does not open with the machine key")
	}
	part, err := krb.ParseEncKDCRepPart(plain, krb.MsgASRep)
	if err != nil || part.Nonce != nonce || part.Flags&krb.FlagInvalid == 0 || part.KeyExpiry == nil || part.KeyExpiry.Unix() != 0 {
		e.t.Fatalf("reply part: %+v %v", part, err)
	}
	pa, ok := krb.FindPA(rep.PAData, krb.PAXboxAccountCreate)
	if !ok {
		e.t.Fatal("no account PA")
	}
	ed, _ := krb.ParseEncryptedData(pa)
	blob, err := krb.Open(xbcrypto.NonceKey(machineKey, nonce), krb.UsageMachineAccount, ed)
	if err != nil {
		e.t.Fatal("account blob does not open:", err)
	}
	return blob
}

func TestMACSIssuesMachineAccount(t *testing.T) {
	e := newEnv(t)
	e.provisionDevice(xbaccountapi.StatusActive, true)
	blob := e.macsAccount(0x1234)
	if len(blob) != 84 || binary.LittleEndian.Uint64(blob) != 123456789012 ||
		string(bytes.TrimRight(blob[8:24], "\x00")) != "SN."+serial ||
		string(bytes.TrimRight(blob[24:44], "\x00")) != "xbox.com" ||
		string(bytes.TrimRight(blob[44:68], "\x00")) != "passport.net" {
		t.Fatalf("account blob %x", blob)
	}
	_, secret := e.cfg.UserKeys.Active()
	if !bytes.Equal(blob[68:], func() []byte { k := krb.DeriveDeviceKey(secret, 123456789012); return k[:] }()) {
		t.Fatal("account key is not the derived device key")
	}
}

// The full console path: MACS, machine sign-in, then user sign-in with compound
// identity, then TGS.
func TestMachineAndUserSignInEndToEnd(t *testing.T) {
	e := newEnv(t)
	e.provisionDevice(xbaccountapi.StatusActive, true)
	blob := e.macsAccount(1)
	var accountKey xbcrypto.Key
	copy(accountKey[:], blob[68:])

	// Machine account AS (no compound identity).
	machineName := &krb.PrincipalName{Type: krb.NameTypeEnterprise, Parts: []string{"SN." + serial + "@xbox.com"}}
	e.clock.Advance(time.Second)
	reply := e.handle(e.asReq(accountKey, e.clock.Now(), 2, func(r *krb.KDCReq) { r.CName = machineName }))
	rep, err := krb.ParseKDCRep(reply, krb.MsgASRep)
	if err != nil {
		t.Fatalf("machine AS failed: %x", reply)
	}
	plain, err := krb.Open(accountKey, krb.UsageKDCRepPart, rep.Enc)
	if err != nil {
		t.Fatal(err)
	}
	part, _ := krb.ParseEncKDCRepPart(plain, krb.MsgASRep)
	machineSession, _ := krb.ToKey(part.Key.Value)
	machineTGT := rep.Ticket

	// User AS with the machine TGT as compound identity.
	ticketSeq := wrapSeq(machineTGT.Marshal())
	withMachine := func(r *krb.KDCReq) {
		r.PAData = append(r.PAData, krb.PAData{Type: krb.PACompoundIdentity, Value: ticketSeq})
	}
	compound := xbcrypto.CompoundKey(e.userKey(), machineSession)
	e.clock.Advance(time.Second)
	reply = e.handle(e.asReq(compound, e.clock.Now(), 3, withMachine))
	urep, err := krb.ParseKDCRep(reply, krb.MsgASRep)
	if err != nil {
		t.Fatalf("compound user AS failed: %x", reply)
	}
	plain, err = krb.Open(compound, krb.UsageKDCRepPart, urep.Enc)
	if err != nil {
		t.Fatal("user AS-REP must be sealed with the compound key")
	}
	upart, _ := krb.ParseEncKDCRepPart(plain, krb.MsgASRep)
	userSession, _ := krb.ToKey(upart.Key.Value)

	// And the user's TGT works at the TGS.
	e.clock.Advance(time.Second)
	treply := e.handle(e.tgsReq(tgt{ticket: urep.Ticket, session: userSession}, tgsOpts{ids: []uint32{6}}))
	if trep, err := krb.ParseKDCRep(treply, krb.MsgTGSRep); err != nil || trep.Ticket.SName.Parts[0] != "xbox" {
		t.Fatalf("TGS after compound sign-in failed: %x", treply)
	}

	// Negative: plain user key with the compound ticket, compound key without it.
	e.clock.Advance(time.Second)
	e.mustErr(e.handle(e.asReq(e.userKey(), e.clock.Now(), 4, withMachine)), krb.ErrPreauthFailed)
	e.mustErr(e.handle(e.asReq(compound, e.clock.Now(), 4)), krb.ErrPreauthFailed)
	// A machine TGT gets a service ticket for the machine account itself (the
	// pre-sign-in account-creation path a real console takes), but only while
	// the device stays admitted.
	mreply := e.handle(e.tgsReq(tgt{ticket: machineTGT, session: machineSession},
		tgsOpts{cname: machineName, ids: []uint32{6}}))
	if _, err := krb.ParseKDCRep(mreply, krb.MsgTGSRep); err != nil {
		t.Fatalf("machine TGS failed: %x", mreply)
	}
	e.provisionDevice(xbaccountapi.StatusRevoked, true)
	e.clock.Advance(time.Second)
	e.mustErr(e.handle(e.tgsReq(tgt{ticket: machineTGT, session: machineSession},
		tgsOpts{cname: machineName, ids: []uint32{6}})), krb.ErrClientRevoked)
	e.provisionDevice(xbaccountapi.StatusActive, true)
	// A user TGT is not a machine identity, and garbage is not a ticket.
	userTGT := e.login()
	e.clock.Advance(time.Second)
	for _, bad := range [][]byte{wrapSeq(userTGT.ticket.Marshal()), {1, 2, 3}, wrapSeq(nil)} {
		bad := bad
		e.mustErr(e.handle(e.asReq(compound, e.clock.Now(), 5, func(r *krb.KDCReq) {
			r.PAData = append(r.PAData, krb.PAData{Type: krb.PACompoundIdentity, Value: bad})
		})), krb.ErrPreauthFailed)
	}
	// A machine account cannot present compound identity itself.
	e.mustErr(e.handle(e.asReq(accountKey, e.clock.Now(), 6, func(r *krb.KDCReq) { r.CName = machineName; withMachine(r) })), krb.ErrPreauthFailed)

	// Revoking the console stops compound sign-in at once, and expiry does too.
	e.provisionDevice(xbaccountapi.StatusRevoked, true)
	e.clock.Advance(time.Second)
	e.mustErr(e.handle(e.asReq(compound, e.clock.Now(), 7, withMachine)), krb.ErrPreauthFailed)
	e.provisionDevice(xbaccountapi.StatusActive, true)
	e.clock.Advance(25 * time.Hour)
	e.mustErr(e.handle(e.asReq(compound, e.clock.Now(), 8, withMachine)), krb.ErrPreauthFailed)
}

func TestMACSNegative(t *testing.T) {
	e := newEnv(t)
	now := e.clock.Now()

	t.Run("unknown device", func(t *testing.T) {
		e.macsErr(e.handle(e.macsReq(machineKey, now, 1)), krb.ErrCPrincipalUnknown)
	})
	t.Run("known device without proof material is not provisioned", func(t *testing.T) {
		e.provisionDevice(xbaccountapi.StatusActive, false)
		e.macsErr(e.handle(e.macsReq(machineKey, now, 1)), krb.ErrCPrincipalUnknown)
	})
	t.Run("revoked and deleted device", func(t *testing.T) {
		e.provisionDevice(xbaccountapi.StatusRevoked, true)
		e.macsErr(e.handle(e.macsReq(machineKey, now, 2)), krb.ErrClientRevoked)
		e.provisionDevice(xbaccountapi.StatusDeleted, true)
		e.macsErr(e.handle(e.macsReq(machineKey, now, 3)), krb.ErrCPrincipalUnknown)
	})
	t.Run("account service down", func(t *testing.T) {
		e.provisionDevice(xbaccountapi.StatusActive, true)
		e.res.Unavailable = true
		e.macsErr(e.handle(e.macsReq(machineKey, now, 4)), krb.ErrSvcUnavailable)
		e.res.Unavailable = false
	})
	e.provisionDevice(xbaccountapi.StatusActive, true)
	t.Run("wrong machine key", func(t *testing.T) {
		wrong := machineKey
		wrong[0] ^= 1
		// Wrong proof in the client-version MAC.
		e.macsErr(e.handle(e.macsReq(machineKey, now, 5, func(r *krb.KDCReq) {
			r.PAData[3].Value = krb.SignClientVersion(wrong, []byte("Version=1\x00"))
		})), krb.ErrPreauthFailed)
		// Right MAC, timestamp sealed under another key.
		e.macsErr(e.handle(e.macsReq(wrong, now, 5)), krb.ErrPreauthFailed)
		// Truncated or tampered MAC.
		e.macsErr(e.handle(e.macsReq(machineKey, now, 5, func(r *krb.KDCReq) { r.PAData[3].Value = r.PAData[3].Value[:10] })), krb.ErrPreauthFailed)
	})
	t.Run("skew", func(t *testing.T) {
		e.macsErr(e.handle(e.macsReq(machineKey, now.Add(-time.Hour), 6)), krb.ErrAPSkew)
	})
	t.Run("replay", func(t *testing.T) {
		req := e.macsReq(machineKey, now, 7)
		if r := e.handle(req); krb.IsError(r) {
			t.Fatal("first MACS must succeed")
		}
		e.macsErr(e.handle(req), krb.ErrAPRepeat)
	})
	t.Run("request shape", func(t *testing.T) {
		e.macsErr(e.handle(e.macsReq(machineKey, now, 8, func(r *krb.KDCReq) { r.Realm = "OTHER.COM" })), krb.ErrBadOption)
		e.macsErr(e.handle(e.macsReq(machineKey, now, 8, func(r *krb.KDCReq) { r.Options = 0x40000000 })), krb.ErrBadOption)
		e.macsErr(e.handle(e.macsReq(machineKey, now, 8, func(r *krb.KDCReq) { r.ETypes = []int32{23, 17} })), krb.ErrETypeNoSupp)
		e.macsErr(e.handle(e.macsReq(machineKey, now, 8, func(r *krb.KDCReq) { r.PAData = slices.Delete(r.PAData, 1, 2) })), krb.ErrPADataTypeNoSupp)
		e.macsErr(e.handle(e.macsReq(machineKey, now, 8, func(r *krb.KDCReq) { r.PAData = append(r.PAData, r.PAData[0]) })), krb.ErrPADataTypeNoSupp)
		e.macsErr(e.handle(e.macsReq(machineKey, now, 8, func(r *krb.KDCReq) { r.PAData[1].Type = 999 })), krb.ErrPADataTypeNoSupp)
		for _, s := range []string{"12345", "12345678901a", "000000000000", "1234567890123"} {
			e.macsErr(e.handle(e.macsReq(machineKey, now, 8, func(r *krb.KDCReq) {
				r.CName = &krb.PrincipalName{Type: krb.NameTypeEnterprise, Parts: []string{s}}
			})), krb.ErrCPrincipalUnknown)
		}
		e.macsErr(e.handle(e.macsReq(machineKey, now, 8, func(r *krb.KDCReq) { r.CName = nil })), krb.ErrCPrincipalUnknown)
	})
	t.Run("machine accounts need a registered, active device", func(t *testing.T) {
		accountKey := krb.DeriveDeviceKey(bytes.Repeat([]byte{0}, 32), 1) // wrong secret
		name := &krb.PrincipalName{Type: krb.NameTypeEnterprise, Parts: []string{"SN." + serial + "@xbox.com"}}
		e.mustErr(e.handle(e.asReq(accountKey, now, 9, func(r *krb.KDCReq) { r.CName = name })), krb.ErrPreauthFailed)
		e.provisionDevice(xbaccountapi.StatusRevoked, true)
		e.mustErr(e.handle(e.asReq(accountKey, now, 9, func(r *krb.KDCReq) { r.CName = name })), krb.ErrClientRevoked)
		unknown := &krb.PrincipalName{Type: krb.NameTypeEnterprise, Parts: []string{"SN.999999999999@xbox.com"}}
		e.mustErr(e.handle(e.asReq(accountKey, now, 9, func(r *krb.KDCReq) { r.CName = unknown })), krb.ErrCPrincipalUnknown)
	})
}

func TestKDCRequiresDeviceStore(t *testing.T) {
	e := newEnv(t)
	if _, err := kdc.New(e.cfg, e.res, nil); err == nil {
		t.Fatal("nil device store accepted")
	}
}
