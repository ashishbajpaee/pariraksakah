FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get install -y libpq-dev && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/neuro_synaptic_memory /usr/local/bin/
RUN mkdir -p /data
EXPOSE 8071
CMD ["neuro_synaptic_memory"]
