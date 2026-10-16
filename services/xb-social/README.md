# xb-social

Native Xbox friend list and presence projection for OpenPak. Read-only: the
canonical friend graph, blocks and live sessions stay in account core (Social,
Sessions, Links over gRPC). Nothing is copied or cached here.

`GET /internal/v1/friends?viewer=<xuid>` (mTLS, `spiffe://openpak/xb-gateway`
only; the gateway binds the viewer from its authenticated connection) returns
the viewer's accepted friends. The viewer is resolved through xb-account
(`xbaccountapi.Resolver`), so banned, unlinked or deleted viewers get 403.

Rules:
- A friend is listed only with an active `xbox` link and a published gamertag;
  the XUID is the link's real subject. Friends without one are counted in
  `omitted`, never listed, and no gamertag is derived from a display name.
- Presence comes from core live sessions. A title id is reported only for
  sessions in the `xbox` namespace; a friend playing on another platform is
  `online` without a title. Presence is only asked for friends the viewer may
  discover (core CheckInteraction), so a blocked friend appears offline.
- Any backend failure returns 503, never a partial list.

Not implemented: friend requests, avatars/gamerpics, rich presence strings,
real-time presence push (poll only), and the native wire encoding (that is
xb-gateway's job).

Config: `XB_LISTEN_ADDR`, `XB_TLS_CERT_FILE`, `XB_TLS_KEY_FILE`,
`XB_CLIENT_CA_FILE`, `XB_ACCOUNT_URL`, `XB_ACCOUNT_CA_FILE`, `XB_CORE_ADDR`,
`XB_CORE_KEY_FILE`, and `XB_CORE_CA_FILE`/`XB_CORE_SERVER_NAME` or
`XB_CORE_PLAINTEXT_INTERNAL=1`.
