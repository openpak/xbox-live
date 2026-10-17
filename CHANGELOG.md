# Changelog

## v0.1.13

- xb-account: every active account in the account core now gets an `xbox` link,
  whether or not a console was ever enrolled. A reconcile loop (at start, then
  every 60 s) pages `Identity.ListAccounts` and creates a console-less
  projection link (subject `0000` + 12 hex, never a real XUID, no public code,
  no device or user row, admits nothing). Revoked links are left revoked.
- A real enrolment or web provisioning replaces the projection link; the
  console-side resolver never treats a projection as a device's link.
