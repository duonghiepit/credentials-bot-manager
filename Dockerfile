# ==============================================================================
# Build Stage
# ==============================================================================
FROM golang:1.24-alpine AS builder

WORKDIR /src

RUN apk add --no-cache git ca-certificates && \
    echo "nonroot:x:65532:65532:nonroot:/nonexistent:/sbin/nologin" > /etc/passwd.nonroot && \
    echo "nonroot:x:65532:" > /etc/group.nonroot

COPY go.mod go.sum* ./
RUN go mod download || true

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
    -trimpath \
    -ldflags="-s -w -X main.version=1.0.0" \
    -o /bin/platform-controller main.go

# ==============================================================================
# Final Hardened Scratch Stage (Distroless / Zero Shell / Non-Root)
# ==============================================================================
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /etc/passwd.nonroot /etc/passwd
COPY --from=builder /etc/group.nonroot /etc/group
COPY --from=builder /bin/platform-controller /usr/local/bin/platform-controller

USER 65532:65532

ENTRYPOINT ["/usr/local/bin/platform-controller"]
CMD ["--help"]
