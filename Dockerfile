# ==============================================================================
# Build Stage
# ==============================================================================
FROM golang:1.24-alpine AS builder

WORKDIR /src

RUN echo "nonroot:x:65532:65532:nonroot:/nonexistent:/sbin/nologin" > /etc/passwd.nonroot && \
    echo "nonroot:x:65532:" > /etc/group.nonroot

COPY go.mod go.sum* ./
RUN go mod download || true

COPY . .

ARG TARGETOS=linux
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -trimpath \
    -ldflags="-s -w -X main.version=1.0.0" \
    -o /bin/credentials-bot-manager main.go

# ==============================================================================
# Final Hardened Scratch Stage (Distroless / Zero Shell / Non-Root)
# ==============================================================================
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /etc/passwd.nonroot /etc/passwd
COPY --from=builder /etc/group.nonroot /etc/group
COPY --from=builder /bin/credentials-bot-manager /usr/local/bin/credentials-bot-manager

USER 65532:65532

ENTRYPOINT ["/usr/local/bin/credentials-bot-manager"]
CMD ["--help"]
