FROM golang:1.21-alpine as builder
WORKDIR /app
COPY go.mod ./
RUN go mod download || true # ignore if empty till we copy main
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -o neuro-immune main.go

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/neuro-immune .
EXPOSE 8075
CMD ["./neuro-immune"]
