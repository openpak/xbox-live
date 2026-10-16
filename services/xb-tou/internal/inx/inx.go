// SPDX-License-Identifier: AGPL-3.0-only

// Package inx reads and writes the console dashboard's country description
// files (CountryMaster2.INX, CountryInfo2.INX). The format is a UTF-16LE,
// byte-order-marked, INI-like text: "[Section]" lines and ID="value" lines.
// The grammar, limits and field meanings are the facts recorded in
// docs/xbox/inx-format.md (observed from the dashboard's own behaviour);
// this package is an independent implementation of that description.
package inx

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Limits observed in the dashboard's parser (characters, not bytes).
const (
	MaxName  = 63   // section names and IDs
	MaxValue = 9999 // quoted values
	MaxFile  = 1 << 20
)

// Entry is one ID="value" assignment inside a section.
type Entry struct {
	Section, ID, Value string
	Line               int
}

// Error describes a syntax error; the dashboard abandons the file on any of them.
type Error struct {
	Line int
	Msg  string
}

func (e *Error) Error() string { return fmt.Sprintf("inx: line %d: %s", e.Line, e.Msg) }

type state int

const (
	idle state = iota
	inID
	wantValue
	inValue
	inSection
	inComment
)

// Parse tokenizes a file. strict additionally rejects what the dashboard
// tolerates silently (missing BOM, odd length, unterminated string at EOF),
// which a generator must never emit.
func Parse(data []byte, strict bool) ([]Entry, error) {
	if len(data) < 2 || data[0] != 0xFF || data[1] != 0xFE {
		if strict {
			return nil, &Error{1, "missing UTF-16LE byte-order mark"}
		}
	}
	if len(data) > MaxFile {
		return nil, &Error{1, "file larger than the dashboard's 1 MiB buffer"}
	}
	if strict && len(data)%2 != 0 {
		return nil, &Error{1, "odd byte length"}
	}
	n := len(data) / 2
	units := make([]uint16, 0, n)
	for i := 1; i < n; i++ { // skip the BOM unit
		units = append(units, uint16(data[2*i])|uint16(data[2*i+1])<<8)
	}

	var (
		out     []Entry
		st      = idle
		line    = 1
		idLine  = 1
		section []uint16
		id, val []uint16
		pending bool // an ID has been read and not yet emitted
		emit    = func() {
			out = append(out, Entry{string(utf16.Decode(section)), string(utf16.Decode(id)), string(utf16.Decode(val)), idLine})
			id, val, pending = nil, nil, false
		}
	)
	for _, c := range units {
		if c == '\r' {
			line++
			if st == inValue || st == inSection {
				return nil, &Error{line - 1, "string or section name not terminated before end of line"}
			}
			if st == inID && pending {
				emit()
				st = idle
				continue
			}
			if st == inComment {
				st = idle
			}
			continue
		}
		if st == inComment {
			if c == '\n' {
				st = idle
			}
			continue
		}
		if st != inValue && st != inSection {
			switch c {
			case ' ', '\t', '\n':
				continue
			case '#', ';':
				st = inComment
				continue
			}
		}
		switch st {
		case idle:
			if c == '"' {
				st = inValue
				continue
			}
			if pending {
				emit()
			}
			id, val = nil, nil
			if c == '[' {
				st, section = inSection, nil
				continue
			}
			st = inID
			fallthrough
		case inID:
			switch c {
			case '=':
				st = wantValue
			case '"', ']':
				return nil, &Error{line, "misplaced quote or ]"}
			default:
				if len(id) >= MaxName {
					return nil, &Error{line, "ID too long"}
				}
				id, idLine, pending = append(id, c), line, true
			}
		case wantValue:
			if c != '"' {
				return nil, &Error{line, "string expected"}
			}
			st = inValue
		case inValue:
			if c == '"' {
				st = idle
				continue
			}
			if len(val) >= MaxValue {
				return nil, &Error{line, "string too long"}
			}
			val = append(val, c)
		case inSection:
			if c == ']' {
				st = idle
				continue
			}
			if len(section) >= MaxName {
				return nil, &Error{line, "section name too long"}
			}
			section = append(section, c)
		}
	}
	if strict && (st == inValue || st == inSection || st == wantValue) {
		return nil, &Error{line, "unterminated string or section at end of file"}
	}
	if pending {
		emit()
	}
	return out, nil
}

// Country is what the dashboard builds for one section.
type Country struct {
	Name                          string // section name (ISO 3166-1 alpha-2 here); localisation key and URL directory
	LocaleCode                    int    // account country byte, 1..255
	DayPosition, MonthPosition    int    // 0..2 slot in the date entry/display
	YearPosition                  int
	DateSeparator                 rune
	DateOfBirthPresent            bool
	MinimumAge, ParentAge         int
	PostalLookup, PostalRightJust bool
	StateSceneTitleLocTag         string
	Fields                        map[string]map[string]string // "PostalCode" -> {"Min":"5"}
	BillingFields                 int
}

// known top-level IDs. Anything else is ignored by the dashboard; Validate
// rejects it so generated files stay precise.
var scalar = map[string]bool{"LocaleCode": true, "DayPosition": true, "MonthPosition": true,
	"YearPosition": true, "DateSeparator": true, "DateOfBirthPresent": true, "MinimumAge": true,
	"ParentAge": true, "PostalLookup": true, "PostalLookupRightJustify": true,
	"StateSceneTitleLocTag": true, "BillingField": true}

// Interpret applies entries the way the dashboard does: sections are matched
// case-insensitively, values use base-10 integer conversion that yields 0 on
// garbage, and "Prefix.Property" IDs address a billing field object.
func Interpret(entries []Entry) ([]*Country, error) {
	var list []*Country
	find := func(name string) *Country {
		for _, c := range list {
			if strings.EqualFold(c.Name, name) {
				return c
			}
		}
		return nil
	}
	for _, e := range entries {
		c := find(e.Section)
		if c == nil {
			c = &Country{Name: e.Section, Fields: map[string]map[string]string{}}
			list = append(list, c)
		}
		if i := strings.IndexByte(e.ID, '.'); i >= 0 {
			p := e.ID[:i]
			if c.Fields[p] == nil {
				c.Fields[p] = map[string]string{}
			}
			c.Fields[p][e.ID[i+1:]] = e.Value
			continue
		}
		if !scalar[e.ID] {
			return nil, &Error{e.Line, "unknown ID " + strconv.Quote(e.ID)}
		}
		num := atoi(e.Value)
		switch e.ID {
		case "LocaleCode":
			c.LocaleCode = num
		case "DayPosition":
			c.DayPosition = num
		case "MonthPosition":
			c.MonthPosition = num
		case "YearPosition":
			c.YearPosition = num
		case "DateSeparator":
			if r := []rune(e.Value); len(r) > 0 {
				c.DateSeparator = r[0]
			}
		case "DateOfBirthPresent":
			c.DateOfBirthPresent = num != 0
		case "MinimumAge":
			c.MinimumAge = num
		case "ParentAge":
			c.ParentAge = num
		case "PostalLookup":
			c.PostalLookup = num != 0
		case "PostalLookupRightJustify":
			c.PostalRightJust = num != 0
		case "StateSceneTitleLocTag":
			c.StateSceneTitleLocTag = e.Value
		case "BillingField":
			c.BillingFields++
		}
	}
	return list, nil
}

func atoi(s string) int {
	s = strings.TrimLeft(s, " \t")
	end := 0
	for end < len(s) && (s[end] >= '0' && s[end] <= '9' || end == 0 && (s[end] == '-' || s[end] == '+')) {
		end++
	}
	n, _ := strconv.Atoi(s[:end])
	return n
}

// ValidateMaster checks a region master list: every section needs a unique
// LocaleCode in 1..255 and a name usable as a URL path element.
func ValidateMaster(cs []*Country) error {
	if len(cs) == 0 {
		return fmt.Errorf("inx: master lists no countries")
	}
	codes := map[int]string{}
	for _, c := range cs {
		if err := validName(c.Name); err != nil {
			return err
		}
		if c.LocaleCode < 1 || c.LocaleCode > 255 {
			return fmt.Errorf("inx: %s: LocaleCode %d outside 1..255", c.Name, c.LocaleCode)
		}
		if o, dup := codes[c.LocaleCode]; dup {
			return fmt.Errorf("inx: %s and %s share LocaleCode %d", o, c.Name, c.LocaleCode)
		}
		codes[c.LocaleCode] = c.Name
	}
	return nil
}

// ValidateInfo checks a per-country info file against the master entry.
func ValidateInfo(c, master *Country) error {
	if err := validName(c.Name); err != nil {
		return err
	}
	if c.LocaleCode != master.LocaleCode {
		return fmt.Errorf("inx: %s: info LocaleCode %d differs from master %d", c.Name, c.LocaleCode, master.LocaleCode)
	}
	for _, p := range []int{c.DayPosition, c.MonthPosition, c.YearPosition} {
		if p < 0 || p > 2 {
			return fmt.Errorf("inx: %s: date position %d outside 0..2", c.Name, p)
		}
	}
	if c.DayPosition == c.MonthPosition || c.DayPosition == c.YearPosition || c.MonthPosition == c.YearPosition {
		return fmt.Errorf("inx: %s: date positions must be distinct", c.Name)
	}
	if c.DateSeparator == 0 {
		return fmt.Errorf("inx: %s: DateSeparator missing", c.Name)
	}
	if c.DateOfBirthPresent && (c.MinimumAge < 0 || c.ParentAge < c.MinimumAge) {
		return fmt.Errorf("inx: %s: ParentAge below MinimumAge", c.Name)
	}
	return nil
}

func validName(n string) error {
	if n == "" || len(n) > MaxName {
		return fmt.Errorf("inx: bad country name %q", n)
	}
	for _, r := range n {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return fmt.Errorf("inx: country name %q must be alphanumeric (it is a URL directory and a string key)", n)
		}
	}
	return nil
}

// Writer builds a file.
type Writer struct{ b []uint16 }

// NewWriter starts a file with the byte-order mark.
func NewWriter() *Writer { return &Writer{b: []uint16{0xFEFF}} }

func (w *Writer) raw(s string) { w.b = append(w.b, utf16.Encode([]rune(s))...) }

// Comment adds a ";" line.
func (w *Writer) Comment(s string) { w.raw("; " + strings.ReplaceAll(s, "\n", " ") + "\r\n") }

// Section starts "[name]".
func (w *Writer) Section(name string) error {
	if len(name) > MaxName || strings.ContainsAny(name, "]\r\n") {
		return fmt.Errorf("inx: bad section name %q", name)
	}
	w.raw("[" + name + "]\r\n")
	return nil
}

// Set writes ID="value"; values cannot contain a quote or carriage return.
func (w *Writer) Set(id, value string) error {
	if id == "" || len(id) > MaxName || strings.ContainsAny(id, " \t\r\n=\"[];#") {
		return fmt.Errorf("inx: bad ID %q", id)
	}
	if strings.ContainsAny(value, "\"\r") || len([]rune(value)) > MaxValue {
		return fmt.Errorf("inx: bad value for %s", id)
	}
	w.raw(id + "=\"" + value + "\"\r\n")
	return nil
}

// Bytes returns the UTF-16LE file.
func (w *Writer) Bytes() []byte {
	out := make([]byte, 0, len(w.b)*2)
	for _, u := range w.b {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

// EncodeText encodes plain text (Terms of Use etc.) as UTF-16LE with a BOM.
func EncodeText(s string) []byte { w := NewWriter(); w.raw(s); return w.Bytes() }
