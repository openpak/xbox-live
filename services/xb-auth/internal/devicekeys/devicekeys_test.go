// SPDX-License-Identifier: AGPL-3.0-only
package devicekeys

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"openpak/xb-live/services/xb-auth/internal/kdc"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	write := func(body string, mode os.FileMode) string {
		p := filepath.Join(dir, "k")
		os.Remove(p)
		os.WriteFile(p, []byte(body), mode)
		os.Chmod(p, mode)
		return p
	}
	s, err := Load(write(`{"0000001cbe991a14":"a1020304050607080910111213141516"}`, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	if k, err := s.MachineKey(context.Background(), "0000001cbe991a14"); err != nil || k[0] != 0xa1 {
		t.Fatalf("%v", err)
	}
	if _, err := s.MachineKey(context.Background(), "0000000000000002"); !errors.Is(err, kdc.ErrNoDeviceKey) {
		t.Fatal("unknown device must have no key")
	}
	if _, err := None.MachineKey(context.Background(), "0000001cbe991a14"); !errors.Is(err, kdc.ErrNoDeviceKey) {
		t.Fatal("empty store must have no keys")
	}
	for name, body := range map[string]string{
		"bad id":   `{"zz":"a1020304050607080910111213141516"}`,
		"bad key":  `{"0000001cbe991a14":"a1"}`,
		"zero key": `{"0000001cbe991a14":"00000000000000000000000000000000"}`,
		"not json": `x`,
	} {
		if _, err := Load(write(body, 0o600)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := Load(write(`{}`, 0o666)); err == nil {
		t.Error("world-writable file accepted")
	}
}
