FROM rust:1.75 AS builder
WORKDIR /usr/src/app
COPY Cargo.toml .
RUN mkdir src && echo "fn main(){}" > src/main.rs && cargo build --release && rm -f target/release/deps/dsrn_peer_node*
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y iproute2 procps && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/app/target/release/dsrn_peer_node /usr/local/bin/dsrn_peer_node
EXPOSE 8060 4001
CMD ["dsrn_peer_node"]
