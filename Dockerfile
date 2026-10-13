# Kazeshini Distroless Containerfile
# Multi-stage build producing a minimal, read-only rootfs, non-root image.

FROM golang:alpine AS builder
ENV GOTOOLCHAIN=auto

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /kazeshini ./cmd/kazeshini

# Minimal distroless base
FROM gcr.io/distroless/static-debian12:nonroot

USER 65532:65532
COPY --from=builder /kazeshini /usr/local/bin/kazeshini

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/kazeshini"]
CMD ["serve", "--addr", "0.0.0.0:8080"]
