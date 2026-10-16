// SPDX-License-Identifier: AGPL-3.0-only
package xbdns

import "os"

func writeFile(p, s string) error { return os.WriteFile(p, []byte(s), 0o600) }
