# Build stage: compile a fully static binary with musl so the runtime
# image needs no libc or any other files.
FROM rust:1.88-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY common ./common
COPY enclave ./enclave
COPY host ./host

RUN cargo build --release --locked -p enclave

# Runtime stage: scratch keeps the EIF as small as possible and minimizes
# the attack surface / measurement inputs (PCR0).
FROM scratch

COPY --from=builder /build/target/release/enclave /enclave

# nitro-cli uses ENTRYPOINT/CMD as the enclave's init process.
ENTRYPOINT ["/enclave"]
