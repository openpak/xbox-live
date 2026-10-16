// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"openpak/xb-live/internal/xbcodes"
	"openpak/xb-live/internal/xbenrolapi"
	"openpak/xb-live/services/xb-account/internal/enrol"
	"openpak/xb-live/services/xb-account/internal/voucher"
)

// Routes for the xb-enroll front (peer spiffe://openpak/xb-enroll only):
//
//	POST /internal/v1/enrolments        register a pending enrolment
//	POST /internal/v1/enrolments/poll   status by poll token
//
// Routes for the website/app (peer spiffe://openpak/xb-provisioner only; the
// caller has already authenticated the user with 2FA and names the account):
//
//	POST /internal/v1/enrolments/preview   what a pairing code refers to
//	POST /internal/v1/enrolments/approve   approve it for the account
//	POST /internal/v1/vouchers             issue a subscription code
//	POST /internal/v1/accounts/xbox        the account's Xbox link state
func mountEnrol(mux *http.ServeMux, s *enrol.Service) {
	mux.Handle("POST /internal/v1/enrolments", Only(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req xbenrolapi.EnrolRequest
		if !decodeE(w, r, &req) {
			return
		}
		id, ok := xbenrolapi.ParseMachineID(req.MachineID)
		key, ok2 := xbenrolapi.ParseMachineKey(req.MachineKey)
		if !ok || !ok2 {
			errJSON(w, 400, xbenrolapi.CodeInvalidRequest)
			return
		}
		res, err := s.Enrol(r.Context(), enrol.EnrolRequest{MachineID: id, MachineKey: key, ClientInfo: req.ClientInfo})
		if err != nil {
			enrolFail(w, err)
			return
		}
		reply(w, xbenrolapi.EnrolResponse{PairingCode: res.PairingCode, PollToken: res.PollToken, ExpiresUnix: res.Expires.Unix()})
	}), Enroll))
	mux.Handle("POST /internal/v1/enrolments/poll", Only(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req xbenrolapi.PollRequest
		if !decodeE(w, r, &req) {
			return
		}
		st, exp, err := s.Poll(r.Context(), req.PollToken)
		if err != nil {
			enrolFail(w, err)
			return
		}
		reply(w, xbenrolapi.PollResponse{Status: st, ExpiresUnix: exp.Unix()})
	}), Enroll))

	type codeReq struct {
		CoreAccountID string `json:"core_account_id"`
		PairingCode   string `json:"pairing_code"`
	}
	mux.Handle("POST /internal/v1/enrolments/preview", Only(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req codeReq
		if !decodeE(w, r, &req) {
			return
		}
		p, err := s.Preview(r.Context(), req.CoreAccountID, req.PairingCode)
		if err != nil {
			enrolFail(w, err)
			return
		}
		reply(w, map[string]any{"machine_id_suffix": p.MachineIDSuffix, "client_info": p.ClientInfo, "expires_unix": p.Expires.Unix(), "approved": p.Approved})
	}), Provisioner))
	mux.Handle("POST /internal/v1/enrolments/approve", Only(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req codeReq
		if !decodeE(w, r, &req) {
			return
		}
		a, err := s.Approve(r.Context(), req.CoreAccountID, req.PairingCode)
		if err != nil {
			enrolFail(w, err)
			return
		}
		reply(w, map[string]any{"status": "approved", "machine_id_suffix": a.MachineIDSuffix, "already_approved": a.Replay})
	}), Provisioner))
	mux.Handle("POST /internal/v1/accounts/xbox", Only(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			CoreAccountID string `json:"core_account_id"`
		}
		if !decodeE(w, r, &req) {
			return
		}
		st, err := s.AccountState(r.Context(), req.CoreAccountID)
		if err != nil {
			enrolFail(w, err)
			return
		}
		devs := make([]map[string]string, 0, len(st.Devices))
		for _, d := range st.Devices {
			devs = append(devs, map[string]string{"machine_id_suffix": d.MachineIDSuffix, "status": string(d.Status), "signup": d.Signup})
		}
		reply(w, map[string]any{"state": st.State, "gamertag": st.Gamertag, "devices": devs})
	}), Provisioner))
}

func mountVoucher(mux *http.ServeMux, v *voucher.Service) {
	mux.Handle("POST /internal/v1/vouchers", Only(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			CoreAccountID string `json:"core_account_id"`
			MachineID     string `json:"machine_id"`
		}
		if !decodeE(w, r, &req) {
			return
		}
		machine := ""
		if req.MachineID != "" {
			var ok bool
			if machine, ok = xbenrolapi.ParseMachineID(req.MachineID); !ok {
				errJSON(w, 400, xbenrolapi.CodeInvalidRequest)
				return
			}
		}
		is, err := v.Issue(r.Context(), req.CoreAccountID, machine)
		switch {
		case err == nil:
			reply(w, map[string]any{"code": is.Code, "expires_unix": is.Expires.Unix(), "length": xbcodes.VoucherLen})
		case errors.Is(err, voucher.ErrInvalid):
			errJSON(w, 400, xbenrolapi.CodeInvalidRequest)
		case errors.Is(err, voucher.ErrAccount):
			errJSON(w, 403, xbenrolapi.CodeNotEligible)
		case errors.Is(err, voucher.ErrDeviceBound):
			errJSON(w, 409, xbenrolapi.CodeConflict)
		case errors.Is(err, voucher.ErrRateLimited):
			w.Header().Set("Retry-After", strconv.Itoa(int((10 * time.Minute).Seconds())))
			errJSON(w, 429, xbenrolapi.CodeRateLimited)
		default:
			errJSON(w, 503, xbenrolapi.CodeUnavailable)
		}
	}), Provisioner))
}

func decodeE(w http.ResponseWriter, r *http.Request, v any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, xbenrolapi.MaxBody))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		errJSON(w, 400, xbenrolapi.CodeInvalidRequest)
		return false
	}
	return true
}

func errJSON(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	w.Write([]byte(`{"error":"` + code + `"}` + "\n"))
}

func enrolFail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, enrol.ErrInvalid):
		errJSON(w, 400, xbenrolapi.CodeInvalidRequest)
	case errors.Is(err, enrol.ErrMachineActive):
		errJSON(w, 409, xbenrolapi.CodeMachineActive)
	case errors.Is(err, enrol.ErrRateLimited):
		w.Header().Set("Retry-After", "600")
		errJSON(w, 429, xbenrolapi.CodeRateLimited)
	case errors.Is(err, enrol.ErrBusy):
		w.Header().Set("Retry-After", "60")
		errJSON(w, 503, xbenrolapi.CodeBusy)
	case errors.Is(err, enrol.ErrNotFound):
		errJSON(w, 404, xbenrolapi.CodeNotFound)
	case errors.Is(err, enrol.ErrAccount):
		errJSON(w, 403, xbenrolapi.CodeNotEligible)
	case errors.Is(err, enrol.ErrConflict):
		errJSON(w, 409, xbenrolapi.CodeConflict)
	case errors.Is(err, enrol.ErrFailed):
		errJSON(w, 422, "approval_failed")
	default:
		errJSON(w, 503, xbenrolapi.CodeUnavailable)
	}
}
