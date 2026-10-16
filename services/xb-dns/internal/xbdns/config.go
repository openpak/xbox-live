// SPDX-License-Identifier: AGPL-3.0-only
package xbdns

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// BuildTable creates the table: authIP for every auth name, then overrides
// from file lines "name ip" (only names in AuthNames, IPv4, no wildcards).
func BuildTable(authIP string, file string) (Table, error) {
	t := Table{}
	if authIP != "" {
		a, err := parseIP(authIP)
		if err != nil {
			return nil, fmt.Errorf("auth ip: %w", err)
		}
		for _, n := range AuthNames {
			t[n] = a
		}
	}
	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		allowed := map[string]bool{}
		for _, n := range AuthNames {
			allowed[n] = true
		}
		sc := bufio.NewScanner(f)
		for ln := 1; sc.Scan(); ln++ {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fs := strings.Fields(line)
			if len(fs) != 2 {
				return nil, fmt.Errorf("%s:%d: want \"name ip\"", file, ln)
			}
			name := strings.ToLower(strings.TrimSuffix(fs[0], "."))
			if !allowed[name] {
				return nil, fmt.Errorf("%s:%d: name %q is not an Xbox discovery name", file, ln, name)
			}
			a, err := parseIP(fs[1])
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %w", file, ln, err)
			}
			t[name] = a
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	if len(t) == 0 {
		return nil, fmt.Errorf("no mappings configured")
	}
	return t, nil
}

func parseIP(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || !a.Is4() || a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() {
		return netip.Addr{}, fmt.Errorf("invalid public-routable IPv4 %q", s)
	}
	return a, nil
}
