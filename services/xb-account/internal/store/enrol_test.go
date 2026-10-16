// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"bytes"
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

// A database created before enrolment existed gains the device link columns
// and keeps its devices as completed signups.
func TestOpenMigratesExistingDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	old, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = old.Exec(`CREATE TABLE devices(machine_id TEXT PRIMARY KEY, core_account_id TEXT NOT NULL, status TEXT NOT NULL,
 proof_mac BLOB NOT NULL, proof_sealed BLOB NOT NULL DEFAULT x'', created INTEGER NOT NULL, updated INTEGER NOT NULL);
INSERT INTO devices VALUES('0000001cbe991a14','acct','active',x'00',x'',1,1);`)
	if err != nil {
		t.Fatal(err)
	}
	old.Close()
	for i := 0; i < 2; i++ { // twice: the migration is idempotent
		s, err := Open(path, bytes.Repeat([]byte{1}, 32))
		if err != nil {
			t.Fatal(err)
		}
		d, err := s.GetDevice(context.Background(), "0000001cbe991a14")
		if err != nil || d.Signup != SignupComplete || d.XUID != "" || d.CoreAccountID != "acct" {
			t.Fatalf("device after migration: %+v %v", d, err)
		}
		s.Close()
	}
}
