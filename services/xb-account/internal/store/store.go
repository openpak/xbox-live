// SPDX-License-Identifier: AGPL-3.0-only

// Package store is xb-account's own durable state: Xbox user principals
// (XUID), device principals (machine ID), gamertag aliases, provisioning
// transactions, the core event cursor and the revocation outbox.
//
// Storage choice: embedded SQLite through the pure-Go modernc driver. The
// state is small and single-writer (one xb-account instance), so a file on the
// service's own volume avoids a new Postgres database, role and credentials in
// production and keeps the image CGO-free and `scratch`-based. The account
// core's Postgres (pgx) is not shared: this service never touches core tables.
// If xb-account is ever replicated, move this package behind the same methods
// onto Postgres; no caller depends on SQL.
package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
	"openpak/xb-live/internal/xbaccountapi"
)

var (
	ErrNotFound = errors.New("store: not found")
	ErrConflict = errors.New("store: conflict")
)

type Store struct {
	db     *sql.DB
	pepper []byte
	now    func() time.Time
	mu     sync.Mutex // serialises write transactions
}

const schema = `
CREATE TABLE IF NOT EXISTS users(
 xuid TEXT PRIMARY KEY, core_account_id TEXT NOT NULL, gamertag TEXT NOT NULL, link_id TEXT NOT NULL,
 status TEXT NOT NULL, created INTEGER NOT NULL, updated INTEGER NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS users_one_primary ON users(core_account_id) WHERE status IN ('active','banned');
CREATE INDEX IF NOT EXISTS users_account ON users(core_account_id);
CREATE TABLE IF NOT EXISTS gamertag_aliases(
 alias_lower TEXT PRIMARY KEY, xuid TEXT NOT NULL REFERENCES users(xuid), created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS devices(
 machine_id TEXT PRIMARY KEY, core_account_id TEXT NOT NULL, status TEXT NOT NULL,
 proof_mac BLOB NOT NULL, created INTEGER NOT NULL, updated INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS devices_account ON devices(core_account_id);
CREATE TABLE IF NOT EXISTS provisions(
 id TEXT PRIMARY KEY, core_account_id TEXT NOT NULL, machine_id TEXT NOT NULL, challenge_hash BLOB NOT NULL,
 expires INTEGER NOT NULL, state TEXT NOT NULL, xuid TEXT NOT NULL DEFAULT '', link_id TEXT NOT NULL DEFAULT '',
 gamertag TEXT NOT NULL DEFAULT '', proof_mac BLOB, fail_reason TEXT NOT NULL DEFAULT '',
 created INTEGER NOT NULL, updated INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS cursors(name TEXT PRIMARY KEY, version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS processed_events(event_id TEXT PRIMARY KEY, version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS revocations(
 seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE, scope TEXT NOT NULL,
 principal_id TEXT NOT NULL, core_account_id TEXT NOT NULL, reason TEXT NOT NULL, created INTEGER NOT NULL);
`

// Durability: WAL with synchronous=NORMAL survives process crashes; an OS
// crash can lose the last commits, which is safe here because provisioning
// resumes via core's idempotency keys and the event cursor simply re-polls.
//
// Open opens (creating) the database at path. pepper keys the device-proof MAC
// and must be at least 32 bytes of secret material kept outside the database.
func Open(path string, pepper []byte) (*Store, error) {
	if len(pepper) < 32 {
		return nil, errors.New("store: pepper must be at least 32 bytes")
	}
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, pepper: append([]byte(nil), pepper...), now: time.Now}, nil
}

func (s *Store) Close() error                { return s.db.Close() }
func (s *Store) SetClock(f func() time.Time) { s.now = f }
func (s *Store) unix() int64                 { return s.now().Unix() }

// ProofMAC derives the stored form of a device proof secret. The proof is
// never stored; only HMAC-SHA256(pepper, "xb-device-proof" || machine || proof).
func (s *Store) ProofMAC(machineID string, proof []byte) []byte {
	m := hmac.New(sha256.New, s.pepper)
	m.Write([]byte("xb-device-proof\x00" + machineID + "\x00"))
	m.Write(proof)
	return m.Sum(nil)
}

// tx runs f in a serialised write transaction.
func (s *Store) tx(ctx context.Context, f func(*sql.Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := f(t); err != nil {
		t.Rollback()
		return err
	}
	return t.Commit()
}

func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// ---- principals ----

type User struct {
	XUID, CoreAccountID, Gamertag, LinkID string
	Status                                xbaccountapi.Status
}

type Device struct {
	MachineID, CoreAccountID string
	Status                   xbaccountapi.Status
}

func (s *Store) GetUser(ctx context.Context, xuid string) (User, error) {
	var u User
	var st string
	err := s.db.QueryRowContext(ctx, `SELECT xuid,core_account_id,gamertag,link_id,status FROM users WHERE xuid=?`, xuid).
		Scan(&u.XUID, &u.CoreAccountID, &u.Gamertag, &u.LinkID, &st)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	u.Status = xbaccountapi.Status(st)
	return u, err
}

// GetUserByGamertag resolves a current alias (case-insensitive).
func (s *Store) GetUserByGamertag(ctx context.Context, tag string) (User, error) {
	var xuid string
	err := s.db.QueryRowContext(ctx, `SELECT xuid FROM gamertag_aliases WHERE alias_lower=?`, strings.ToLower(tag)).Scan(&xuid)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	return s.GetUser(ctx, xuid)
}

func (s *Store) GetDevice(ctx context.Context, machineID string) (Device, error) {
	var d Device
	var st string
	err := s.db.QueryRowContext(ctx, `SELECT machine_id,core_account_id,status FROM devices WHERE machine_id=?`, machineID).
		Scan(&d.MachineID, &d.CoreAccountID, &st)
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, ErrNotFound
	}
	d.Status = xbaccountapi.Status(st)
	return d, err
}

// VerifyDeviceProof reports whether proof matches the stored material for an
// ACTIVE device. This checks a provisioned shared secret only; it is not
// Kerberos proof and does not replace ticket validation.
func (s *Store) VerifyDeviceProof(ctx context.Context, machineID string, proof []byte) (bool, error) {
	var mac []byte
	var st string
	err := s.db.QueryRowContext(ctx, `SELECT proof_mac,status FROM devices WHERE machine_id=?`, machineID).Scan(&mac, &st)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return xbaccountapi.Status(st) == xbaccountapi.StatusActive && hmac.Equal(mac, s.ProofMAC(machineID, proof)), nil
}

// ---- provisioning ----

type ProvState string

const (
	ProvPending   ProvState = "pending"
	ProvClaimed   ProvState = "claimed"   // fingerprint + xuid fixed, nothing in core yet
	ProvReserved  ProvState = "reserved"  // core link pending
	ProvActivated ProvState = "activated" // core link active
	ProvCoded     ProvState = "coded"     // public code published
	ProvDone      ProvState = "done"
	ProvRollback  ProvState = "rollback" // terminal failure, core link still to be unlinked
	ProvFailed    ProvState = "failed"
)

type Provision struct {
	ID, CoreAccountID, MachineID string
	ChallengeHash                [32]byte
	Expires                      time.Time
	State                        ProvState
	XUID, LinkID, Gamertag       string
	ProofMAC                     []byte
	FailReason                   string
}

func (s *Store) CreateProvision(ctx context.Context, p Provision) error {
	n := s.unix()
	return s.tx(ctx, func(t *sql.Tx) error {
		_, err := t.ExecContext(ctx, `INSERT INTO provisions(id,core_account_id,machine_id,challenge_hash,expires,state,created,updated) VALUES(?,?,?,?,?,?,?,?)`,
			p.ID, p.CoreAccountID, p.MachineID, p.ChallengeHash[:], p.Expires.Unix(), ProvPending, n, n)
		if isUnique(err) {
			return ErrConflict
		}
		return err
	})
}

func scanProv(row interface{ Scan(...any) error }) (Provision, error) {
	var p Provision
	var ch []byte
	var exp int64
	var st string
	err := row.Scan(&p.ID, &p.CoreAccountID, &p.MachineID, &ch, &exp, &st, &p.XUID, &p.LinkID, &p.Gamertag, &p.ProofMAC, &p.FailReason)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	copy(p.ChallengeHash[:], ch)
	p.Expires = time.Unix(exp, 0)
	p.State = ProvState(st)
	return p, err
}

const provCols = `id,core_account_id,machine_id,challenge_hash,expires,state,xuid,link_id,gamertag,proof_mac,fail_reason`

func (s *Store) GetProvision(ctx context.Context, id string) (Provision, error) {
	return scanProv(s.db.QueryRowContext(ctx, `SELECT `+provCols+` FROM provisions WHERE id=?`, id))
}

// StaleProvisions lists unfinished provisions whose token expired.
func (s *Store) StaleProvisions(ctx context.Context) ([]Provision, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+provCols+` FROM provisions WHERE expires<=? AND state IN ('claimed','reserved','activated','coded','rollback')`, s.unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Provision
	for rows.Next() {
		p, err := scanProv(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SetProvision updates the mutable resume fields.
func (s *Store) SetProvision(ctx context.Context, p Provision) error {
	return s.tx(ctx, func(t *sql.Tx) error {
		_, err := t.ExecContext(ctx, `UPDATE provisions SET state=?,xuid=?,link_id=?,gamertag=?,proof_mac=?,fail_reason=?,updated=? WHERE id=?`,
			p.State, p.XUID, p.LinkID, p.Gamertag, p.ProofMAC, p.FailReason, s.unix(), p.ID)
		return err
	})
}

// CommitProvision atomically creates the user, gamertag alias and device and
// marks the provision done. ErrConflict means a local invariant failed (second
// primary user for the account, gamertag in use, machine bound elsewhere).
func (s *Store) CommitProvision(ctx context.Context, p Provision) error {
	n := s.unix()
	return s.tx(ctx, func(t *sql.Tx) error {
		if _, err := t.ExecContext(ctx, `INSERT INTO users(xuid,core_account_id,gamertag,link_id,status,created,updated) VALUES(?,?,?,?,'active',?,?)`,
			p.XUID, p.CoreAccountID, p.Gamertag, p.LinkID, n, n); err != nil {
			return conflict(err)
		}
		if _, err := t.ExecContext(ctx, `INSERT INTO gamertag_aliases(alias_lower,xuid,created) VALUES(?,?,?)`, strings.ToLower(p.Gamertag), p.XUID, n); err != nil {
			return conflict(err)
		}
		var acct, st string
		err := t.QueryRowContext(ctx, `SELECT core_account_id,status FROM devices WHERE machine_id=?`, p.MachineID).Scan(&acct, &st)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			_, err = t.ExecContext(ctx, `INSERT INTO devices(machine_id,core_account_id,status,proof_mac,created,updated) VALUES(?,?,'active',?,?,?)`, p.MachineID, p.CoreAccountID, p.ProofMAC, n, n)
		case err != nil:
		case xbaccountapi.Status(st) == xbaccountapi.StatusActive && acct != p.CoreAccountID,
			xbaccountapi.Status(st) == xbaccountapi.StatusBanned:
			return ErrConflict
		default: // re-provisioning the same account's device, or reviving a revoked one
			_, err = t.ExecContext(ctx, `UPDATE devices SET core_account_id=?,status='active',proof_mac=?,updated=? WHERE machine_id=?`, p.CoreAccountID, p.ProofMAC, n, p.MachineID)
		}
		if err != nil {
			return conflict(err)
		}
		_, err = t.ExecContext(ctx, `UPDATE provisions SET state='done',updated=? WHERE id=?`, n, p.ID)
		return err
	})
}

func conflict(err error) error {
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

// DeviceBoundElsewhere reports whether machineID is an active device of another account.
func (s *Store) DeviceBoundElsewhere(ctx context.Context, machineID, account string) (bool, error) {
	d, err := s.GetDevice(ctx, machineID)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return err == nil && d.CoreAccountID != account && (d.Status == xbaccountapi.StatusActive || d.Status == xbaccountapi.StatusBanned), err
}

// ---- events and revocations ----

// Change is the local effect of one core event, computed by the processor.
type Change struct {
	EventID   string
	Version   uint64
	AccountID string
	// Exactly one of the effects below (or none, to just advance the cursor).
	SetAccount *StatusChange            // applies to the users and/or devices of AccountID
	UnlinkXUID string                   // user unlinked (also revokes the account's devices)
	Emit       *xbaccountapi.Revocation // at most one per event (event_id is unique)
}

// StatusChange moves principals from any status in From to To.
type StatusChange struct {
	From           []xbaccountapi.Status
	To             xbaccountapi.Status
	Users, Devices bool
	// ReleaseGamertag drops the alias and clears the gamertag (deletion).
	ReleaseGamertag bool
}

const cursorName = "core-events"

func (s *Store) Cursor(ctx context.Context) (uint64, error) {
	var v uint64
	err := s.db.QueryRowContext(ctx, `SELECT version FROM cursors WHERE name=?`, cursorName).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return v, err
}

func inList(from []xbaccountapi.Status) (string, []any) {
	ph := make([]string, len(from))
	args := make([]any, len(from))
	for i, f := range from {
		ph[i], args[i] = "?", string(f)
	}
	return strings.Join(ph, ","), args
}

// ApplyChange applies c, appends its revocations and advances the cursor in
// one transaction. A previously processed EventID only advances the cursor, so
// redelivery is harmless. Versions must not move the cursor backwards.
func (s *Store) ApplyChange(ctx context.Context, c Change) error {
	n := s.unix()
	return s.tx(ctx, func(t *sql.Tx) error {
		var cur uint64
		err := t.QueryRowContext(ctx, `SELECT version FROM cursors WHERE name=?`, cursorName).Scan(&cur)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		var seen int
		if err := t.QueryRowContext(ctx, `SELECT COUNT(*) FROM processed_events WHERE event_id=?`, c.EventID).Scan(&seen); err != nil {
			return err
		}
		if seen == 0 {
			if err := s.effects(ctx, t, c, n); err != nil {
				return err
			}
			if r := c.Emit; r != nil {
				if _, err := t.ExecContext(ctx, `INSERT INTO revocations(event_id,scope,principal_id,core_account_id,reason,created) VALUES(?,?,?,?,?,?)`,
					c.EventID, r.Scope, r.PrincipalID, r.CoreAccountID, r.Reason, n); err != nil {
					return err
				}
			}
			if _, err := t.ExecContext(ctx, `INSERT INTO processed_events(event_id,version) VALUES(?,?)`, c.EventID, c.Version); err != nil {
				return err
			}
		}
		if c.Version > cur {
			_, err = t.ExecContext(ctx, `INSERT INTO cursors(name,version) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET version=excluded.version`, cursorName, c.Version)
			return err
		}
		return nil
	})
}

func (s *Store) effects(ctx context.Context, t *sql.Tx, c Change, n int64) error {
	if sc := c.SetAccount; sc != nil {
		in, args := inList(sc.From)
		base := []any{string(sc.To), n, c.AccountID}
		if sc.Users {
			if _, err := t.ExecContext(ctx, `UPDATE users SET status=?,updated=? WHERE core_account_id=? AND status IN (`+in+`)`, append(base, args...)...); err != nil {
				return err
			}
		}
		if sc.Devices {
			if _, err := t.ExecContext(ctx, `UPDATE devices SET status=?,updated=? WHERE core_account_id=? AND status IN (`+in+`)`, append(base, args...)...); err != nil {
				return err
			}
		}
		if sc.ReleaseGamertag {
			if _, err := t.ExecContext(ctx, `DELETE FROM gamertag_aliases WHERE xuid IN (SELECT xuid FROM users WHERE core_account_id=?)`, c.AccountID); err != nil {
				return err
			}
			if _, err := t.ExecContext(ctx, `UPDATE users SET gamertag='' WHERE core_account_id=?`, c.AccountID); err != nil {
				return err
			}
		}
	}
	if c.UnlinkXUID != "" {
		var acct string
		err := t.QueryRowContext(ctx, `SELECT core_account_id FROM users WHERE xuid=?`, c.UnlinkXUID).Scan(&acct)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := t.ExecContext(ctx, `UPDATE users SET status='unlinked',updated=? WHERE xuid=? AND status IN ('active','banned')`, n, c.UnlinkXUID); err != nil {
			return err
		}
		if _, err := t.ExecContext(ctx, `DELETE FROM gamertag_aliases WHERE xuid=?`, c.UnlinkXUID); err != nil {
			return err
		}
		if _, err := t.ExecContext(ctx, `UPDATE devices SET status='unlinked',updated=? WHERE core_account_id=? AND status IN ('active','banned')`, n, acct); err != nil {
			return err
		}
	}
	return nil
}

// Revocations returns up to limit entries with seq > after, ascending.
func (s *Store) Revocations(ctx context.Context, after uint64, limit int) ([]xbaccountapi.Revocation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT seq,event_id,scope,principal_id,core_account_id,reason,created FROM revocations WHERE seq>? ORDER BY seq LIMIT ?`, after, limit)
	if err != nil {
		return nil, fmt.Errorf("revocations: %w", err)
	}
	defer rows.Close()
	var out []xbaccountapi.Revocation
	for rows.Next() {
		var r xbaccountapi.Revocation
		var sc, rs string
		if err := rows.Scan(&r.Seq, &r.EventID, &sc, &r.PrincipalID, &r.CoreAccountID, &rs, &r.CreatedUnix); err != nil {
			return nil, err
		}
		r.Scope, r.Reason = xbaccountapi.Scope(sc), xbaccountapi.Status(rs)
		out = append(out, r)
	}
	return out, rows.Err()
}
