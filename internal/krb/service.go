// SPDX-License-Identifier: AGPL-3.0-only
package krb

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	MaxServices        = 12
	MaxServiceID       = 20
	ServiceRequestSize = 0x6c
	ServiceAddressSize = 0xe0

	// HRESULTs observed in Xombie's PA_XBOX_SERVICE_ADDRESS.
	HRSuccess        uint32 = 0
	HRInvalidService uint32 = 0x80000001
	HRUnknownService uint32 = 0x80000002
	HRAccessDenied   uint32 = 0x80070005
)

// ServiceRequest is the decrypted PA_XBOX_SERVICE_REQUEST (little endian).
type ServiceRequest struct {
	StructVersion  uint16
	StructSize     uint16
	LibraryVersion [4]uint16
	TitleID        uint32
	TitleVersion   uint32
	TitleRegion    uint32
	XUIDs          [4]uint64
	NumServices    uint32
	ServiceIDs     [MaxServices]uint32
}

var ErrServiceRequest = errors.New("krb: invalid service request")

func ParseServiceRequest(b []byte) (*ServiceRequest, error) {
	if len(b) != ServiceRequestSize {
		return nil, ErrServiceRequest
	}
	le := binary.LittleEndian
	r := &ServiceRequest{StructVersion: le.Uint16(b), StructSize: le.Uint16(b[2:])}
	for i := range r.LibraryVersion {
		r.LibraryVersion[i] = le.Uint16(b[4+2*i:])
	}
	r.TitleID, r.TitleVersion, r.TitleRegion = le.Uint32(b[12:]), le.Uint32(b[16:]), le.Uint32(b[20:])
	for i := range r.XUIDs {
		r.XUIDs[i] = le.Uint64(b[24+8*i:])
	}
	r.NumServices = le.Uint32(b[56:])
	for i := range r.ServiceIDs {
		r.ServiceIDs[i] = le.Uint32(b[60+4*i:])
	}
	if r.StructVersion != 1 || r.StructSize != ServiceRequestSize || r.NumServices > MaxServices {
		return nil, ErrServiceRequest
	}
	return r, nil
}

func (r *ServiceRequest) Marshal() []byte {
	b := make([]byte, ServiceRequestSize)
	le := binary.LittleEndian
	le.PutUint16(b, r.StructVersion)
	le.PutUint16(b[2:], r.StructSize)
	for i, v := range r.LibraryVersion {
		le.PutUint16(b[4+2*i:], v)
	}
	le.PutUint32(b[12:], r.TitleID)
	le.PutUint32(b[16:], r.TitleVersion)
	le.PutUint32(b[20:], r.TitleRegion)
	for i, v := range r.XUIDs {
		le.PutUint64(b[24+8*i:], v)
	}
	le.PutUint32(b[56:], r.NumServices)
	for i, v := range r.ServiceIDs {
		le.PutUint32(b[60+4*i:], v)
	}
	return b
}

type ServiceResult struct {
	ID   uint32
	HR   uint32
	Port uint16
}

// ServiceAddress is PA_XBOX_SERVICE_ADDRESS (0xe0 bytes).
type ServiceAddress struct {
	HR          uint32
	HRUser      [4]uint32
	UserFlags   [4]uint32
	BWLimit     uint32
	SiteIP      netip.Addr // IPv4, network byte order on the wire
	NumServices uint32
	Results     [MaxServices]ServiceResult
}

func (a *ServiceAddress) Marshal() []byte {
	b := make([]byte, ServiceAddressSize)
	le := binary.LittleEndian
	le.PutUint32(b, a.HR)
	for i := 0; i < 4; i++ {
		le.PutUint32(b[4+4*i:], a.HRUser[i])
		le.PutUint32(b[20+4*i:], a.UserFlags[i])
	}
	le.PutUint32(b[36:], a.BWLimit)
	// 0x28..0x47 reserved, zero
	ip := a.SiteIP.As4()
	copy(b[0x48:], ip[:])
	le.PutUint32(b[0x4c:], a.NumServices)
	for i, r := range a.Results {
		o := 0x50 + 12*i
		le.PutUint32(b[o:], r.ID)
		le.PutUint32(b[o+4:], r.HR)
		le.PutUint16(b[o+8:], r.Port)
	}
	return b
}

func ParseServiceAddress(b []byte) (*ServiceAddress, error) {
	if len(b) != ServiceAddressSize {
		return nil, ErrServiceRequest
	}
	le := binary.LittleEndian
	a := &ServiceAddress{HR: le.Uint32(b), BWLimit: le.Uint32(b[36:]),
		SiteIP: netip.AddrFrom4([4]byte(b[0x48:0x4c])), NumServices: le.Uint32(b[0x4c:])}
	for i := 0; i < 4; i++ {
		a.HRUser[i], a.UserFlags[i] = le.Uint32(b[4+4*i:]), le.Uint32(b[20+4*i:])
	}
	for i := range a.Results {
		o := 0x50 + 12*i
		a.Results[i] = ServiceResult{le.Uint32(b[o:]), le.Uint32(b[o+4:]), le.Uint16(b[o+8:])}
	}
	return a, nil
}
