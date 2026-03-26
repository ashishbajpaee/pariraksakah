FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod ./
RUN go mod tidy
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o response-coordinator .
FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/response-coordinator .
EXPOSE 8063
CMD ["./response-coordinator"]
