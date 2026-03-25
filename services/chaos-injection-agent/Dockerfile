FROM rust:1.76-slim AS builder
RUN apt-get update && apt-get install -y cmake pkg-config libssl-dev librdkafka-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml ./
COPY src/ src/
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates iptables && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/chaos-injection-agent /chaos-injection-agent
EXPOSE 8021
CMD ["/chaos-injection-agent"]
