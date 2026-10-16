// SPDX-License-Identifier: AGPL-3.0-only

// Package content generates the OpenPak-authored country and legal files the
// dashboard asks service 11 for. Nothing here is copied from Microsoft or any
// other operator; the texts describe OpenPak. File structure follows
// docs/xbox/inx-format.md.
package content

import (
	"fmt"
	"sort"
	"strings"

	"openpak/xb-live/services/xb-tou/internal/inx"
)

// Country is one country OpenPak accounts can be created in.
type Country struct {
	Code             string // ISO 3166-1 alpha-2; section name, string key and URL directory
	LocaleCode       int    // account country byte (1..255), unique per country
	Day, Month, Year int
	Separator        string
	MinAge           int
	ParentAge        int
}

// Known holds the countries OpenPak knows how to describe. Date order and
// minimum ages are OpenPak policy, not Microsoft data. LocaleCode values are
// OpenPak's own assignment: the values Microsoft used are not known to us.
var Known = map[string]Country{
	"US": {Code: "US", LocaleCode: 103, Day: 1, Month: 0, Year: 2, Separator: "/", MinAge: 13, ParentAge: 18},
	"IE": {Code: "IE", LocaleCode: 66, Day: 0, Month: 1, Year: 2, Separator: "/", MinAge: 16, ParentAge: 18},
}

// Regions are the directory names the dashboard derives from the console's
// game region setting (America, Asia, Europe, or NoRegion when unset).
var Regions = []string{"America", "Asia", "Europe", "NoRegion"}

// Set is a path (with a leading slash) to file bytes mapping.
type Set map[string][]byte

// Build generates the master lists (one copy per region) and, for each
// country, CountryInfo2.INX plus the four legal documents.
func Build(codes []string) (Set, error) {
	if len(codes) == 0 {
		return nil, fmt.Errorf("content: no countries configured")
	}
	var cs []Country
	seen := map[string]bool{}
	for _, c := range codes {
		c = strings.ToUpper(strings.TrimSpace(c))
		k, ok := Known[c]
		if !ok {
			return nil, fmt.Errorf("content: no built-in definition for country %q", c)
		}
		if !seen[c] {
			seen[c] = true
			cs = append(cs, k)
		}
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].Code < cs[j].Code })

	set := Set{}
	mw := inx.NewWriter()
	mw.Comment("OpenPak country list")
	for _, c := range cs {
		must(mw.Section(c.Code))
		must(mw.Set("LocaleCode", fmt.Sprint(c.LocaleCode)))
	}
	master := mw.Bytes()
	for _, r := range Regions {
		set["/Country/"+r+"/CountryMaster2.INX"] = master
	}
	for _, c := range cs {
		iw := inx.NewWriter()
		iw.Comment("OpenPak country settings for " + c.Code)
		must(iw.Section(c.Code))
		must(iw.Set("LocaleCode", fmt.Sprint(c.LocaleCode)))
		must(iw.Set("DayPosition", fmt.Sprint(c.Day)))
		must(iw.Set("MonthPosition", fmt.Sprint(c.Month)))
		must(iw.Set("YearPosition", fmt.Sprint(c.Year)))
		must(iw.Set("DateSeparator", c.Separator))
		must(iw.Set("DateOfBirthPresent", "1"))
		must(iw.Set("MinimumAge", fmt.Sprint(c.MinAge)))
		must(iw.Set("ParentAge", fmt.Sprint(c.ParentAge)))
		must(iw.Set("PostalLookup", "0"))
		must(iw.Set("PostalLookupRightJustify", "0"))
		base := "/" + c.Code + "/"
		set[base+"CountryInfo2.INX"] = iw.Bytes()
		set[base+"TermsOfUse.ini"] = inx.EncodeText(termsOfUse(c))
		set[base+"CodeOfConduct.ini"] = inx.EncodeText(codeOfConduct)
		set[base+"PrivacyStatement.ini"] = inx.EncodeText(privacy)
		set[base+"RefundInfo.ini"] = inx.EncodeText(refunds)
	}
	return set, nil
}

func must(err error) {
	if err != nil {
		panic(err) // generator inputs are compile-time constants and validated codes
	}
}

func termsOfUse(c Country) string {
	return fmt.Sprintf(`OPENPAK ONLINE SERVICE - TERMS OF USE

1. What this is
OpenPak is an independent, community-run online service for original Xbox consoles. It is not operated by, affiliated with or endorsed by Microsoft Corporation.

2. Who may use it
You must be at least %d years old, or have the permission of a parent or guardian if you are under %d. You must be allowed to create an account in the country you selected (%s).

3. Your account
Your gamertag and account belong to the service operator's records. Keep your sign-in details private. You are responsible for what is done with your account.

4. Acceptable use
Do not harass other players, cheat in ways that spoil games for others, attack the service or its network, or use it for anything unlawful.

5. The service
OpenPak is in development. It is provided as is, without warranty. It may change, be interrupted, or be reset at any time, and accounts and data may be removed.

6. Ending access
The operator may suspend or remove accounts that break these terms. You may stop using the service at any time.

7. Changes
These terms may change. You will be asked to accept updated terms before you continue to play online.
`, c.MinAge, c.ParentAge, c.Code)
}

const codeOfConduct = `OPENPAK CODE OF CONDUCT

Be kind. Treat other players the way you would like to be treated.
No hate speech, threats, harassment or spam.
No impersonating other players or the operators.
No cheating that spoils games for others, and no attacks on the service.
Choose a gamertag that you would be comfortable saying out loud.
The operators may remove content and suspend accounts that break these rules.
`

const privacy = `OPENPAK PRIVACY STATEMENT

OpenPak keeps the minimum needed to run the service: your gamertag, the country you chose, your date of birth for age checks, your console's identifiers, and the connection and gameplay information needed for matchmaking.
This information is used only to operate and secure the service. It is not sold. It is kept only as long as the account exists.
You can ask the operator to delete your account and its data.
OpenPak is a private community service and is not run by Microsoft.
`

const refunds = `OPENPAK REFUNDS

OpenPak does not currently take payments or sell anything, so there is nothing to refund.
`
