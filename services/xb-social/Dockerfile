FROM docker.io/library/golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal ./internal
COPY services/xb-social ./services/xb-social
RUN CGO_ENABLED=0 go build -trimpath -o /out/xb-social ./services/xb-social/cmd/xb-social
FROM scratch
COPY --from=build /out/xb-social /xb-social
USER 10001:10001
ENTRYPOINT ["/xb-social"]
