FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY cmd/ cmd/
RUN CGO_ENABLED=0 go build -o /chaos-guardrails ./cmd/main.go

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /chaos-guardrails /chaos-guardrails
EXPOSE 8024
CMD ["/chaos-guardrails"]
