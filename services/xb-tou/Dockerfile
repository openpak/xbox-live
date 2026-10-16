FROM docker.io/library/golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal ./internal
COPY services/xb-tou ./services/xb-tou
RUN CGO_ENABLED=0 go build -trimpath -o /out/xb-tou ./services/xb-tou/cmd/xb-tou
FROM scratch
COPY --from=build /out/xb-tou /xb-tou
USER 10001:10001
ENTRYPOINT ["/xb-tou"]
