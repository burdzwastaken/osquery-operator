FROM golang:1.26.0-alpine3.23@sha256:7c6a62c80c3f15fb49aae282d7a296149889ebe39b2318f3a299f2759c1ce135 AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags="-w -s" \
    -o manager \
    ./cmd/main.go

FROM alpine:3.23.0@sha256:51183f2cfa6320055da30872f211093f9ff1d3cf06f39a0bdb212314c5dc7375

LABEL org.opencontainers.image.source=https://github.com/burdzwastaken/osquery-operator

RUN addgroup -g 65532 nonroot && \
    adduser -D -u 65532 -G nonroot nonroot
USER 65532

COPY --from=builder --chown=65532:65532 /build/manager /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/manager"]
