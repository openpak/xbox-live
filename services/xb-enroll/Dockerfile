FROM docker.io/library/golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal ./internal
COPY services/xb-enroll ./services/xb-enroll
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/xb-enroll ./services/xb-enroll/cmd/xb-enroll
FROM scratch
COPY --from=build /out/xb-enroll /xb-enroll
USER 10001:10001
ENTRYPOINT ["/xb-enroll"]
