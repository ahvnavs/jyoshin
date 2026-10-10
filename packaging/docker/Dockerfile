# Multi-stage static build on scratch
FROM golang:1.24-alpine AS builder

WORKDIR /src
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w -extldflags '-static'" -o /jyoshin ./cmd/jyoshin

FROM scratch
USER 65534:65534
COPY --from=builder /jyoshin /jyoshin
EXPOSE 7777
ENTRYPOINT ["/jyoshin"]
CMD ["serve"]

