// SPDX-License-Identifier: AGPL-3.0-only
package kdc

import (
	"context"
	"errors"

	"openpak/xb-live/internal/xbcrypto"
)

// ErrNoDeviceKey means the console has no provisioned proof material. The KDC
// answers "principal unknown"; it never invents a key.
var ErrNoDeviceKey = errors.New("no device key provisioned")

// DeviceKeys supplies the per-console machine key (derived from the console's
// HDD key and online key, xbcrypto.MachineKey) used to verify MACS requests.
// xbaccountapi.Resolver proves a device is known and permitted but carries no
// secrets by design, so proof material comes through this separate interface.
// The key is a console secret: implementations must not log it.
type DeviceKeys interface {
	MachineKey(ctx context.Context, machineID string) (xbcrypto.Key, error)
}
