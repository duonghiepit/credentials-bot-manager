# ==============================================================================
# Build Stage
# ==============================================================================
FROM golang:1.24-alpine AS builder

WORKDIR /src

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum* ./
RUN go mod download || true

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
    -ldflags="-s -w -X main.version=1.0.0" \
    -o /bin/platform-controller main.go

# ==============================================================================
# Final Minimal Stage
# ==============================================================================
FROM alpine:3.21

RUN apk add --no-cache ca-certificates

COPY --from=builder /bin/platform-controller /usr/local/bin/platform-controller

ENTRYPOINT ["/usr/local/bin/platform-controller"]
CMD ["--help"]
