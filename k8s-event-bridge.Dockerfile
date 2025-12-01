FROM golang:1.25.4-alpine3.22@sha256:d3f0cf7723f3429e3f9ed846243970b20a2de7bae6a5b66fc5914e228d831bbb AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags="-w -s" \
    -o k8s-event-bridge \
    ./cmd/k8s-event-bridge/main.go

FROM alpine:3.22.2@sha256:4b7ce07002c69e8f3d704a9c5d6fd3053be500b7f1c69fc0d80990c2ad8dd412

LABEL org.opencontainers.image.source=https://github.com/burdzwastaken/osquery-operator

RUN addgroup -g 65532 nonroot && \
    adduser -D -u 65532 -G nonroot nonroot
USER 65532

COPY --from=builder --chown=65532:65532 /build/k8s-event-bridge /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/k8s-event-bridge"]
