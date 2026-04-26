FROM rust:1.77-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p rl-discovery

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/rl-discovery-server /usr/local/bin/
EXPOSE 22001
ENV RL_DISCOVERY_PORT=22001
CMD ["rl-discovery-server"]
