// SPDX-License-Identifier: AGPL-3.0-only
package kdc_test

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"openpak/xb-live/internal/krb"
	"openpak/xb-live/internal/xbaccountapi"
	"openpak/xb-live/internal/xbcrypto"
)

// capturedMACS is a real MACS AS-REQ sent by the stock 5960 dashboard
// (client 1.00.5849.3) running in Berth with a throwaway generated EEPROM
// (serial 884985900905), captured 2026-10-16. The nonce 0xbaff651c is encoded
// as a signed 32-bit INTEGER (negative), which the parser used to reject.
const capturedMACS = "6a82019930820195a103020105a20302010aa382010830820104303aa104020200cca2320430da429c70625ddd0148e4d01f84c2a9e93f6053e1ac96b976da09d9cd1e4e8e77c96ae4d1884cfaccf19603fdedc639b9305fa104020200cea2570455ff97dc92900d2c415428ab8978c49279ec9121d358626f782056657273696f6e3d312e30302e353834392e33205469746c653d30784646464530303030205469746c6556657273696f6e3d343038383537383536003048a103020102a241043f303da003020117a23604346eb80c52d80bc0a0eeb3facd18031967f55b32841f7ee38a2c7acbdf20e3af07457efab02973887aa411db31ab00ca511d7af7f2301ba10402020083a2130411300fa0030101ffa108300602010d02010ea47d307ba00703050000010000a1193017a00302010aa110300e1b0c383834393835393030393035a20f1b0d4d4143532e58424f582e434f4da3223020a003020102a11930171b066b72627467741b0d4d4143532e58424f582e434f4da511180f32303337303931333032343830355aa7060204baff651ca8053003020117"

// Machine key derived from that throwaway EEPROM; protects nothing real.
var capturedMachineKey = xbcrypto.Key{0x1e, 0x5e, 0x6b, 0xfa, 0xed, 0x03, 0x2f, 0x9d, 0x70, 0x70, 0x7b, 0x31, 0x42, 0x77, 0x79, 0x95}

func TestMACSRealClientCapture(t *testing.T) {
	e := newEnv(t)
	e.clock.t = time.Date(2026, 10, 16, 11, 35, 30, 0, time.UTC)
	const id = "000000ce0d452f69" // 884985900905
	e.res.SetDevice(id, xbaccountapi.StatusActive, &capturedMachineKey)
	raw, _ := hex.DecodeString(capturedMACS)
	reply := e.handle(raw)
	if reply == nil || krb.IsError(reply) {
		pe, _ := krb.ParseError(reply)
		t.Fatalf("real client MACS rejected: %x %+v", reply, pe)
	}
	rep, err := krb.ParseKDCRep(reply, krb.MsgASRep)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := krb.Open(capturedMachineKey, krb.UsageKDCRepPart, rep.Enc)
	if err != nil {
		t.Fatal(err)
	}
	part, err := krb.ParseEncKDCRepPart(plain, krb.MsgASRep)
	if err != nil || part.Nonce != 0xbaff651c {
		t.Fatalf("nonce %x err %v", part.Nonce, err)
	}
	// The client sent the nonce signed; the sealed part echoes it signed too.
	if !bytes.Contains(plain, []byte{0x02, 0x04, 0xba, 0xff, 0x65, 0x1c}) {
		t.Fatal("reply nonce not echoed in the client's signed encoding")
	}
}
