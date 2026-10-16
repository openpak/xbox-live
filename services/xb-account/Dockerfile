FROM docker.io/library/golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal ./internal
COPY services/xb-account ./services/xb-account
RUN CGO_ENABLED=0 go build -trimpath -o /out/xb-account ./services/xb-account/cmd/xb-account
FROM scratch
COPY --from=build /out/xb-account /xb-account
USER 10001:10001
ENTRYPOINT ["/xb-account"]
