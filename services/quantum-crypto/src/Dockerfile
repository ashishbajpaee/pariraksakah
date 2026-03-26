FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY agility.go .
RUN go get golang.org/x/crypto/sha3 && CGO_ENABLED=0 go build -o /agility-api ./agility.go

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /agility-api /agility-api
EXPOSE 8031
CMD ["/agility-api"]
