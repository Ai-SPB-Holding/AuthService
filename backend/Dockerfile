FROM rust:1.88-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates wget && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/auth_service /usr/local/bin/auth_service
EXPOSE 8080
HEALTHCHECK --interval=20s --timeout=2s --retries=3 CMD ["/bin/sh", "-c", "wget -qO- http://127.0.0.1:8080/health || exit 1"]
CMD ["auth_service"]
