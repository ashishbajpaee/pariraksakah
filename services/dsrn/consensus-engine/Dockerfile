FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod ./
RUN go mod tidy
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o consensus-engine .
FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/consensus-engine .
EXPOSE 8061
CMD ["./consensus-engine"]
