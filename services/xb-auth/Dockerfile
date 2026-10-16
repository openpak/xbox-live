FROM docker.io/library/golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal ./internal
COPY services/xb-auth ./services/xb-auth
RUN CGO_ENABLED=0 go build -trimpath -o /out/xb-auth ./services/xb-auth/cmd/xb-auth
FROM scratch
COPY --from=build /out/xb-auth /xb-auth
USER 10001:10001
ENTRYPOINT ["/xb-auth"]
