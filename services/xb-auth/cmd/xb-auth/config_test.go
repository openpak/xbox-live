// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeRing(t *testing.T, dir, name, body string, mode os.FileMode) string {
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadSettings(t *testing.T) {
	dir := t.TempDir()
	env := map[string]string{
		"XB_TGS_KEYRING_FILE":      writeRing(t, dir, "tgs", `{"active":1,"keys":{"1":"00112233445566778899aabbccddeeff"}}`, 0o600),
		"XB_SG_KEYRING_FILE":       writeRing(t, dir, "sg", `{"active":1,"keys":{"1":"ffeeddccbbaa99887766554433221100"}}`, 0o600),
		"XB_USER_KEY_SECRETS_FILE": writeRing(t, dir, "user", `{"active":1,"keys":{"1":"`+"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"+`"}}`, 0o600),
		"XB_ACCOUNT_URL":           "https://xb-account.internal:8443",
		"XB_ACCOUNT_CA_FILE":       "/x/ca", "XB_TLS_CERT_FILE": "/x/c", "XB_TLS_KEY_FILE": "/x/k",
	}
	get := func(k string) string { return env[k] }
	s, err := loadSettings(get)
	if err != nil {
		t.Fatal(err)
	}
	if s.kdc.GatewayIP.String() != "145.241.228.207" || s.udpAddr != ":88" {
		t.Fatalf("defaults: %v %v", s.kdc.GatewayIP, s.udpAddr)
	}
	env["XB_GATEWAY_PUBLIC_IPV4"] = "203.0.113.9"
	env["XB_CLOCK_SKEW"] = "2m"
	if s, err = loadSettings(get); err != nil || s.kdc.GatewayIP.String() != "203.0.113.9" || s.kdc.ClockSkew.Minutes() != 2 {
		t.Fatalf("overrides: %v", err)
	}
	for _, name := range []string{"XB_TGS_KEYRING_FILE", "XB_SG_KEYRING_FILE", "XB_USER_KEY_SECRETS_FILE", "XB_ACCOUNT_URL", "XB_TLS_KEY_FILE"} {
		saved := env[name]
		delete(env, name)
		if _, err := loadSettings(get); err == nil {
			t.Errorf("missing %s accepted", name)
		}
		env[name] = saved
	}
	env["XB_CLOCK_SKEW"] = "-1s"
	if _, err := loadSettings(get); err == nil {
		t.Error("negative skew accepted")
	}
	delete(env, "XB_CLOCK_SKEW")
	env["XB_TGS_KEYRING_FILE"] = writeRing(t, dir, "wide", `{"active":1,"keys":{"1":"00112233445566778899aabbccddeeff"}}`, 0o666)
	os.Chmod(env["XB_TGS_KEYRING_FILE"], 0o666)
	if _, err := loadSettings(get); err == nil {
		t.Error("world-writable key file accepted")
	}
	// The 16-byte user secret is too short: user secrets must be 32 bytes.
	env["XB_TGS_KEYRING_FILE"] = writeRing(t, dir, "tgs2", `{"active":1,"keys":{"1":"00112233445566778899aabbccddeeff"}}`, 0o600)
	env["XB_USER_KEY_SECRETS_FILE"] = env["XB_TGS_KEYRING_FILE"]
	if _, err := loadSettings(get); err == nil {
		t.Error("short user secret accepted")
	}
}
