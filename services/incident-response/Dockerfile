# Incident Response Service — Go
FROM golang:1.21-alpine AS builder
RUN apk add --no-cache git gcc musl-dev
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /incident-response ./cmd/main.go

FROM alpine:3.19
RUN apk add --no-cache ca-certificates && \
    addgroup -S cybershield && adduser -S appuser -G cybershield
WORKDIR /app
COPY --from=builder /incident-response .
COPY playbooks /app/playbooks
USER appuser
EXPOSE 8004
HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://localhost:8004/health || exit 1
CMD ["./incident-response"]
