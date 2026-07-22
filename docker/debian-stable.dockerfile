# Debian 12 — ntpsec oracle container
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ntpsec \
    build-essential \
    git \
    clang \
    linux-headers-amd64 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install rustup for a modern Rust toolchain (system cargo too old for lockfile v4)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"

# Build ntpsec-rs from local source
COPY . /opt/ntpsec-rs
WORKDIR /opt/ntpsec-rs
RUN cargo build --release --workspace

# Test configuration
COPY docker/config/oracle-ntp.conf /etc/ntp.conf

EXPOSE 123/udp

CMD ["/opt/ntpsec-rs/target/release/ntpd-rs", "-c", "/etc/ntp.conf", "-n"]
