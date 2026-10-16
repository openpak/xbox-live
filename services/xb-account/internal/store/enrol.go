// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"errors"
	"strings"
	"time"

	"openpak/xb-live/internal/xbaccountapi"
)

// Device signup states (devices.signup).
const (
	SignupComplete         = "complete"          // user exists (or legacy provisioned device)
	SignupAwaitingGamertag = "awaiting_gamertag" // device linked to the account; XUID reserved, no user/gamertag yet
)

var (
	ErrMachineActive  = errors.New("store: machine already enrolled")
	ErrBusy           = errors.New("store: too many pending enrolments")
	ErrVoucherInvalid = errors.New("store: subscription code invalid")
	ErrVoucherUsed    = errors.New("store: subscription code already used")
)

const schemaEnrol = `
CREATE TABLE IF NOT EXISTS enrolments(
 id TEXT PRIMARY KEY, code_hash BLOB NOT NULL UNIQUE, poll_hash BLOB NOT NULL UNIQUE,
 machine_id TEXT NOT NULL, client_info TEXT NOT NULL DEFAULT '', proof_mac BLOB NOT NULL, proof_sealed BLOB NOT NULL,
 expires INTEGER NOT NULL, state TEXT NOT NULL, core_account_id TEXT NOT NULL DEFAULT '',
 xuid TEXT NOT NULL DEFAULT '', link_id TEXT NOT NULL DEFAULT '', fail_reason TEXT NOT NULL DEFAULT '',
 created INTEGER NOT NULL, updated INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS enrolments_machine ON enrolments(machine_id);
CREATE TABLE IF NOT EXISTS vouchers(
 code_hash BLOB PRIMARY KEY, core_account_id TEXT NOT NULL, machine_id TEXT NOT NULL DEFAULT '',
 expires INTEGER NOT NULL, state TEXT NOT NULL, consumed_machine TEXT NOT NULL DEFAULT '',
 created INTEGER NOT NULL, updated INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS vouchers_account ON vouchers(core_account_id);
`

// migrateEnrol adds the enrolment tables and the device link columns to a new
// or existing database.
func migrateEnrol(db *sql.DB) error {
	if _, err := db.Exec(schemaEnrol); err != nil {
		return err
	}
	rows, err := db.Query(`PRAGMA table_info(devices)`)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		have[name] = true
	}
	rows.Close()
	for _, c := range []struct{ name, ddl string }{
		{"xuid", `ALTER TABLE devices ADD COLUMN xuid TEXT NOT NULL DEFAULT ''`},
		{"link_id", `ALTER TABLE devices ADD COLUMN link_id TEXT NOT NULL DEFAULT ''`},
		{"signup", `ALTER TABLE devices ADD COLUMN signup TEXT NOT NULL DEFAULT 'complete'`},
	} {
		if !have[c.name] {
			if _, err := db.Exec(c.ddl); err != nil {
				return err
			}
		}
	}
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS devices_xuid ON devices(xuid) WHERE xuid<>''`)
	return err
}

// CodeHash keys a human-typed code for storage and lookup:
// HMAC-SHA256(pepper, label || 0 || code). Codes are never stored.
func (s *Store) CodeHash(label, code string) []byte {
	m := hmac.New(sha256.New, s.pepper)
	m.Write([]byte("xb-code\x00" + label + "\x00" + code))
	return m.Sum(nil)
}

// ---- enrolments ----

type EnrolState string

const (
	EnrolPending   EnrolState = "pending"   // waiting for approval
	EnrolApproving EnrolState = "approving" // claimed by an account, nothing in core yet
	EnrolReserved  EnrolState = "reserved"  // core link pending
	EnrolActivated EnrolState = "activated" // core link active
	EnrolApproved  EnrolState = "approved"  // device committed
	EnrolRollback  EnrolState = "rollback"  // terminal failure, core link still to be unlinked
	EnrolFailed    EnrolState = "failed"
)

type Enrolment struct {
	ID, MachineID, ClientInfo, CoreAccountID, XUID, LinkID, FailReason string
	CodeHash, PollHash, ProofMAC, ProofSealed                          []byte
	Expires                                                            time.Time
	State                                                              EnrolState
}

const enrolCols = `id,code_hash,poll_hash,machine_id,client_info,proof_mac,proof_sealed,expires,state,core_account_id,xuid,link_id,fail_reason`

func scanEnrol(row interface{ Scan(...any) error }) (Enrolment, error) {
	var e Enrolment
	var exp int64
	var st string
	err := row.Scan(&e.ID, &e.CodeHash, &e.PollHash, &e.MachineID, &e.ClientInfo, &e.ProofMAC, &e.ProofSealed, &exp, &st,
		&e.CoreAccountID, &e.XUID, &e.LinkID, &e.FailReason)
	if errors.Is(err, sql.ErrNoRows) {
		return e, ErrNotFound
	}
	e.Expires, e.State = time.Unix(exp, 0), EnrolState(st)
	return e, err
}

// CreateEnrolment inserts a pending enrolment. ErrMachineActive: the machine
// is an active (or banned) device. ErrBusy: maxPending live pending enrolments
// exist. An older pending enrolment of the same machine is replaced. ErrConflict
// means a code or token collision: the caller generates new ones.
func (s *Store) CreateEnrolment(ctx context.Context, e Enrolment, maxPending int) error {
	n := s.unix()
	return s.tx(ctx, func(t *sql.Tx) error {
		var st string
		err := t.QueryRowContext(ctx, `SELECT status FROM devices WHERE machine_id=?`, e.MachineID).Scan(&st)
		if err == nil && (xbaccountapi.Status(st) == xbaccountapi.StatusActive || xbaccountapi.Status(st) == xbaccountapi.StatusBanned) {
			return ErrMachineActive
		} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if _, err := t.ExecContext(ctx, `DELETE FROM enrolments WHERE machine_id=? AND state='pending'`, e.MachineID); err != nil {
			return err
		}
		var c int
		if err := t.QueryRowContext(ctx, `SELECT COUNT(*) FROM enrolments WHERE state='pending' AND expires>?`, n).Scan(&c); err != nil {
			return err
		}
		if c >= maxPending {
			return ErrBusy
		}
		_, err = t.ExecContext(ctx, `INSERT INTO enrolments(id,code_hash,poll_hash,machine_id,client_info,proof_mac,proof_sealed,expires,state,created,updated) VALUES(?,?,?,?,?,?,?,?,'pending',?,?)`,
			e.ID, e.CodeHash, e.PollHash, e.MachineID, e.ClientInfo, e.ProofMAC, e.ProofSealed, e.Expires.Unix(), n, n)
		if isUnique(err) {
			return ErrConflict
		}
		return err
	})
}

func (s *Store) EnrolmentByPoll(ctx context.Context, pollHash []byte) (Enrolment, error) {
	return scanEnrol(s.db.QueryRowContext(ctx, `SELECT `+enrolCols+` FROM enrolments WHERE poll_hash=?`, pollHash))
}

func (s *Store) EnrolmentByCode(ctx context.Context, codeHash []byte) (Enrolment, error) {
	return scanEnrol(s.db.QueryRowContext(ctx, `SELECT `+enrolCols+` FROM enrolments WHERE code_hash=?`, codeHash))
}

func (s *Store) GetEnrolment(ctx context.Context, id string) (Enrolment, error) {
	return scanEnrol(s.db.QueryRowContext(ctx, `SELECT `+enrolCols+` FROM enrolments WHERE id=?`, id))
}

// SetEnrolment updates the mutable resume fields.
func (s *Store) SetEnrolment(ctx context.Context, e Enrolment) error {
	return s.tx(ctx, func(t *sql.Tx) error {
		_, err := t.ExecContext(ctx, `UPDATE enrolments SET state=?,core_account_id=?,xuid=?,link_id=?,fail_reason=?,updated=? WHERE id=?`,
			e.State, e.CoreAccountID, e.XUID, e.LinkID, e.FailReason, s.unix(), e.ID)
		return err
	})
}

// StaleEnrolments lists claimed enrolments whose time ran out before they
// finished (they may hold a core link that must be rolled back).
func (s *Store) StaleEnrolments(ctx context.Context) ([]Enrolment, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+enrolCols+` FROM enrolments WHERE expires<=? AND state IN ('approving','reserved','activated','rollback')`, s.unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Enrolment
	for rows.Next() {
		e, err := scanEnrol(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// PurgeEnrolments deletes finished or expired rows older than keep past expiry
// (so the console can still read "approved"/"expired" for a while).
func (s *Store) PurgeEnrolments(ctx context.Context, keep time.Duration) error {
	return s.tx(ctx, func(t *sql.Tx) error {
		_, err := t.ExecContext(ctx, `DELETE FROM enrolments WHERE expires<=? AND state IN ('pending','approved','failed')`, s.now().Add(-keep).Unix())
		return err
	})
}

// CommitEnrolment makes the approved machine a device of the account: active,
// holding the console's sealed machine key and the reserved XUID/link, with
// signup pending. It marks the enrolment approved in the same transaction.
// ErrConflict: the machine is active for another account or banned.
func (s *Store) CommitEnrolment(ctx context.Context, e Enrolment) error {
	n := s.unix()
	return s.tx(ctx, func(t *sql.Tx) error {
		var st string
		err := t.QueryRowContext(ctx, `SELECT status FROM devices WHERE machine_id=?`, e.MachineID).Scan(&st)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			_, err = t.ExecContext(ctx, `INSERT INTO devices(machine_id,core_account_id,status,proof_mac,proof_sealed,xuid,link_id,signup,created,updated) VALUES(?,?,'active',?,?,?,?,?,?,?)`,
				e.MachineID, e.CoreAccountID, e.ProofMAC, e.ProofSealed, e.XUID, e.LinkID, SignupAwaitingGamertag, n, n)
		case err != nil:
		case xbaccountapi.Status(st) == xbaccountapi.StatusActive, xbaccountapi.Status(st) == xbaccountapi.StatusBanned:
			return ErrConflict
		default: // revoked, unlinked or deleted earlier: revive for this account
			_, err = t.ExecContext(ctx, `UPDATE devices SET core_account_id=?,status='active',proof_mac=?,proof_sealed=?,xuid=?,link_id=?,signup=?,updated=? WHERE machine_id=?`,
				e.CoreAccountID, e.ProofMAC, e.ProofSealed, e.XUID, e.LinkID, SignupAwaitingGamertag, n, e.MachineID)
		}
		if err != nil {
			return conflict(err)
		}
		_, err = t.ExecContext(ctx, `UPDATE enrolments SET state='approved',updated=? WHERE id=?`, n, e.ID)
		return err
	})
}

// AccountXbox is what the website shows for an account.
type AccountXbox struct {
	Devices []Device
	User    *User // newest user that is not unlinked/deleted, if any
}

func (s *Store) AccountXbox(ctx context.Context, account string) (AccountXbox, error) {
	var out AccountXbox
	rows, err := s.db.QueryContext(ctx, `SELECT machine_id,core_account_id,status,xuid,link_id,signup FROM devices WHERE core_account_id=? ORDER BY created`, account)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var d Device
		var st string
		if err := rows.Scan(&d.MachineID, &d.CoreAccountID, &st, &d.XUID, &d.LinkID, &d.Signup); err != nil {
			return out, err
		}
		d.Status = xbaccountapi.Status(st)
		out.Devices = append(out.Devices, d)
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	var u User
	var st string
	err = s.db.QueryRowContext(ctx, `SELECT xuid,core_account_id,gamertag,link_id,status FROM users WHERE core_account_id=? AND status IN ('active','banned') ORDER BY created DESC LIMIT 1`, account).
		Scan(&u.XUID, &u.CoreAccountID, &u.Gamertag, &u.LinkID, &st)
	if err == nil {
		u.Status = xbaccountapi.Status(st)
		out.User = &u
	} else if !errors.Is(err, sql.ErrNoRows) {
		return out, err
	}
	return out, nil
}

// ---- subscription codes ----

type Voucher struct {
	Hash                                      []byte
	CoreAccountID, MachineID, ConsumedMachine string
	Expires                                   time.Time
	State                                     string // issued, consumed, revoked
}

// CreateVoucher stores a new code and revokes the account's earlier unused ones.
func (s *Store) CreateVoucher(ctx context.Context, v Voucher) error {
	n := s.unix()
	return s.tx(ctx, func(t *sql.Tx) error {
		if _, err := t.ExecContext(ctx, `UPDATE vouchers SET state='revoked',updated=? WHERE core_account_id=? AND state='issued'`, n, v.CoreAccountID); err != nil {
			return err
		}
		_, err := t.ExecContext(ctx, `INSERT INTO vouchers(code_hash,core_account_id,machine_id,expires,state,created,updated) VALUES(?,?,?,?,'issued',?,?)`,
			v.Hash, v.CoreAccountID, v.MachineID, v.Expires.Unix(), n, n)
		if isUnique(err) {
			return ErrConflict
		}
		return err
	})
}

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func getVoucher(ctx context.Context, q queryer, hash []byte) (Voucher, error) {
	v := Voucher{Hash: hash}
	var exp int64
	err := q.QueryRowContext(ctx, `SELECT core_account_id,machine_id,expires,state,consumed_machine FROM vouchers WHERE code_hash=?`, hash).
		Scan(&v.CoreAccountID, &v.MachineID, &exp, &v.State, &v.ConsumedMachine)
	if errors.Is(err, sql.ErrNoRows) {
		return v, ErrNotFound
	}
	v.Expires = time.Unix(exp, 0)
	return v, err
}

// usable reports why v cannot be used for account/machine now (nil = usable).
// Unknown, expired, revoked, wrong-account and wrong-machine codes are all
// ErrVoucherInvalid; only an already consumed one is ErrVoucherUsed.
func (v Voucher) usable(account, machineID string, now time.Time) error {
	switch {
	case v.State == "consumed":
		return ErrVoucherUsed
	case v.State != "issued", !now.Before(v.Expires), v.CoreAccountID != account,
		v.MachineID != "" && v.MachineID != machineID:
		return ErrVoucherInvalid
	}
	return nil
}

// CheckVoucher is the non-consuming verifyvoucher check.
func (s *Store) CheckVoucher(ctx context.Context, hash []byte, account, machineID string) error {
	v, err := getVoucher(ctx, s.db, hash)
	if errors.Is(err, ErrNotFound) {
		return ErrVoucherInvalid
	}
	if err != nil {
		return err
	}
	return v.usable(account, machineID, s.now())
}

// VoucherConsumedBy reports whether the code was consumed by machineID (replay detection).
func (s *Store) VoucherConsumedBy(ctx context.Context, hash []byte, machineID string) (bool, error) {
	v, err := getVoucher(ctx, s.db, hash)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return err == nil && v.State == "consumed" && v.ConsumedMachine == machineID, err
}

// CommitSignup is the createowneracct transaction: it consumes the code and
// creates the user (the device's reserved XUID/link), the gamertag alias and
// completes the device, atomically. Errors: ErrNotFound (no such awaiting
// device), ErrVoucherInvalid/ErrVoucherUsed, ErrConflict (gamertag or primary
// user already exists).
func (s *Store) CommitSignup(ctx context.Context, machineID string, hash []byte, gamertag string) (User, error) {
	n := s.unix()
	var u User
	err := s.tx(ctx, func(t *sql.Tx) error {
		var acct, st, xuid, linkID, signup string
		err := t.QueryRowContext(ctx, `SELECT core_account_id,status,xuid,link_id,signup FROM devices WHERE machine_id=?`, machineID).Scan(&acct, &st, &xuid, &linkID, &signup)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if xbaccountapi.Status(st) != xbaccountapi.StatusActive || signup != SignupAwaitingGamertag || xuid == "" {
			return ErrNotFound
		}
		v, err := getVoucher(ctx, t, hash)
		if errors.Is(err, ErrNotFound) {
			return ErrVoucherInvalid
		}
		if err != nil {
			return err
		}
		if err := v.usable(acct, machineID, s.now()); err != nil {
			return err
		}
		if _, err := t.ExecContext(ctx, `UPDATE vouchers SET state='consumed',consumed_machine=?,updated=? WHERE code_hash=? AND state='issued'`, machineID, n, hash); err != nil {
			return err
		}
		if _, err := t.ExecContext(ctx, `INSERT INTO users(xuid,core_account_id,gamertag,link_id,status,created,updated) VALUES(?,?,?,?,'active',?,?)`, xuid, acct, gamertag, linkID, n, n); err != nil {
			return conflict(err)
		}
		if _, err := t.ExecContext(ctx, `INSERT INTO gamertag_aliases(alias_lower,xuid,created) VALUES(?,?,?)`, strings.ToLower(gamertag), xuid, n); err != nil {
			return conflict(err)
		}
		if _, err := t.ExecContext(ctx, `UPDATE devices SET signup=?,updated=? WHERE machine_id=?`, SignupComplete, n, machineID); err != nil {
			return err
		}
		if _, err := t.ExecContext(ctx, `DELETE FROM name_reservations WHERE core_account_id=?`, acct); err != nil {
			return err
		}
		u = User{XUID: xuid, CoreAccountID: acct, Gamertag: gamertag, LinkID: linkID, Status: xbaccountapi.StatusActive}
		return nil
	})
	return u, err
}
