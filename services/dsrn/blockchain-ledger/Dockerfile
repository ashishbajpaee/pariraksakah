FROM rust:1.75 AS builder
WORKDIR /usr/src/app
COPY Cargo.toml .
RUN mkdir src && echo "fn main(){}" > src/main.rs && cargo build --release && rm -f target/release/deps/dsrn_blockchain_ledger*
COPY src ./src
RUN cargo build --release
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y procps && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/app/target/release/dsrn_blockchain_ledger /usr/local/bin/dsrn_blockchain_ledger
EXPOSE 8065
CMD ["dsrn_blockchain_ledger"]
