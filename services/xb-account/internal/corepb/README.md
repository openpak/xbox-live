Generated from OpenPak account core's `proto/openpak/account/v1/account.proto`.
The source is included to make builds independent of a sibling checkout.
The core's AGPL-3.0-only license applies; see repository LICENSE.

Regenerate from the workspace root:

```sh
protoc -I account/proto \
  --go_out=servers/xbox-live \
  --go_opt=module=openpak/xb-live \
  --go_opt=Mopenpak/account/v1/account.proto=openpak/xb-live/services/xb-account/internal/corepb \
  --go-grpc_out=servers/xbox-live \
  --go-grpc_opt=module=openpak/xb-live \
  --go-grpc_opt=Mopenpak/account/v1/account.proto=openpak/xb-live/services/xb-account/internal/corepb \
  openpak/account/v1/account.proto
```
