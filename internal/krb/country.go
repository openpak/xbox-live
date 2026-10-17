// SPDX-License-Identifier: AGPL-3.0-only
package krb

import "strings"

// localeCodes maps an ISO 3166-1 alpha-2 country to the LocaleCode xb-tou lists
// in /Country/*/CountryMaster2.INX (services/xb-tou/internal/content). Keep the
// two in step: the console refuses to go online when the country byte it gets
// is not an entry of that list.
var localeCodes = map[string]byte{"US": 103, "IE": 66}

// LocaleCode returns the LocaleCode for an alpha-2 country, case-insensitively.
func LocaleCode(country string) (byte, bool) {
	id, ok := localeCodes[strings.ToUpper(strings.TrimSpace(country))]
	return id, ok
}
