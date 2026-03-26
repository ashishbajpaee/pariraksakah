FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod ./
RUN go mod tidy
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o dsrn-dashboard-api .
FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/dsrn-dashboard-api .
EXPOSE 8067
CMD ["./dsrn-dashboard-api"]
