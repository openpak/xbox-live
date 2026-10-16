// SPDX-License-Identifier: AGPL-3.0-only
package kdc

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"openpak/xb-live/internal/krb"
	"openpak/xb-live/internal/xbaccountapi"
	"openpak/xb-live/internal/xbcrypto"
)

// macsDummyKey is the placeholder session key Xombie puts in the invalid,
// ticketless MACS reply. It protects nothing and is not a secret.
var macsDummyKey = []byte{0x47, 0xd0, 0x5d, 0x59, 0x74, 0x9a, 0xbd, 0x27, 0xeb, 0x69, 0xa2, 0xf6, 0xca, 0x81, 0x37, 0xc6}

// handleMACS serves the machine-account request (realm MACS.XBOX.COM): a console
// proves possession of its machine key and receives its machine account
// (gamertag SN.<serial>) sealed under that key. The reply carries no ticket;
// the console then signs in as that account through the normal AS path and
// presents the resulting TGT as compound identity for its users.
func (k *KDC) handleMACS(ctx context.Context, req *krb.KDCReq, now time.Time) []byte {
	cname := req.CName
	if req.Options != krb.KDCOptCanonicalize || req.Realm != krb.MACSRealm {
		return k.failMACS(krb.ErrBadOption, now, cname)
	}
	if cname == nil || cname.Type != krb.NameTypeEnterprise || len(cname.Parts) != 1 {
		return k.failMACS(krb.ErrCPrincipalUnknown, now, cname)
	}
	serial := cname.Parts[0]
	machineID, machineNum, err := krb.MachineIDFromSerial(serial)
	if err != nil {
		return k.failMACS(krb.ErrCPrincipalUnknown, now, cname)
	}
	if !slices.Equal(req.ETypes, []int32{krb.ETypeRC4HMAC}) {
		return k.failMACS(krb.ErrETypeNoSupp, now, cname)
	}
	// Exactly these four pre-authentication entries, each once.
	want := []int32{krb.PAEncTimestamp, krb.PAForCheckDups, krb.PAXboxClientVersion, krb.PAXboxPPA}
	got := make([]int32, 0, len(req.PAData))
	for _, d := range req.PAData {
		got = append(got, d.Type)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		return k.failMACS(krb.ErrPADataTypeNoSupp, now, cname)
	}

	p, rerr := k.accounts.ResolveDevice(ctx, machineID)
	if _, code := admitted(p, rerr, xbaccountapi.KindDevice, machineID); code != 0 {
		return k.failMACS(code, now, cname)
	}
	machineKey, err := k.devices.MachineKey(ctx, machineID)
	switch {
	case errors.Is(err, ErrNoDeviceKey):
		return k.failMACS(krb.ErrCPrincipalUnknown, now, cname) // unprovisioned: refuse
	case err != nil:
		return k.failMACS(krb.ErrSvcUnavailable, now, cname)
	}

	version, _ := krb.FindPA(req.PAData, krb.PAXboxClientVersion)
	if _, ok := krb.VerifyClientVersion(machineKey, version); !ok {
		return k.failMACS(krb.ErrPreauthFailed, now, cname)
	}
	// The client version MAC is static per console and release, so it cannot
	// itself stop replays. The encrypted timestamp (fresh confounder) can.
	tsRaw, _ := krb.FindPA(req.PAData, krb.PAEncTimestamp)
	enc, err := krb.ParseEncryptedData(tsRaw)
	if err != nil {
		return k.failMACS(krb.ErrPreauthFailed, now, cname)
	}
	plain, err := krb.Open(machineKey, krb.UsageASReqTimestamp, enc)
	if err != nil {
		return k.failMACS(krb.ErrPreauthFailed, now, cname)
	}
	ts, err := krb.ParsePAEncTSEnc(plain)
	if err != nil {
		return k.failMACS(krb.ErrPreauthFailed, now, cname)
	}
	if !k.skewOK(ts.Time, now) {
		return k.failMACS(krb.ErrAPSkew, now, cname)
	}
	if code := k.recordReplay(hash([]byte("macs"), []byte(machineID), enc.Cipher), now); code != 0 {
		return k.failMACS(code, now, cname)
	}

	_, secret := k.cfg.UserKeys.Active()
	blob, err := krb.MachineAccount{
		XUID: machineNum, Gamertag: machineAccountPrefix + serial,
		Domain: strings.TrimPrefix(k.cfg.Domains[0], "@"), Realm: k.cfg.Realm,
		Key: krb.DeriveDeviceKey(secret, machineNum),
	}.Marshal()
	if err != nil {
		return k.failMACS(krb.ErrSvcUnavailable, now, cname)
	}
	accountEnc, err := krb.Seal(xbcrypto.NonceKey(machineKey, req.Nonce), krb.UsageMachineAccount, nil, blob)
	if err != nil {
		return k.failMACS(krb.ErrSvcUnavailable, now, cname)
	}
	epoch := time.Unix(0, 0).UTC()
	part := &krb.EncKDCRepPart{
		Key:   krb.EncryptionKey{Type: krb.ETypeRC4HMAC, Value: bytes.Clone(macsDummyKey)},
		Nonce: req.Nonce, KeyExpiry: &epoch, Flags: krb.FlagInvalid, AuthTime: now, EndTime: epoch,
		SRealm: krb.MACSRealm, SName: k.macsName,
	}
	repEnc, err := krb.Seal(machineKey, krb.UsageKDCRepPart, nil, part.Marshal(krb.MsgASRep))
	if err != nil {
		return k.failMACS(krb.ErrSvcUnavailable, now, cname)
	}
	return (&krb.KDCRep{
		MsgType: krb.MsgASRep, PAData: []krb.PAData{{Type: krb.PAXboxAccountCreate, Value: accountEnc.Marshal()}},
		CRealm: krb.MACSRealm, CName: *cname,
		Ticket: krb.Ticket{VNO: krb.PVNO, Realm: krb.MACSRealm, SName: k.macsName,
			Enc: krb.EncryptedData{EType: 0, Cipher: []byte("empty")}},
		Enc: repEnc,
	}).Marshal()
}
