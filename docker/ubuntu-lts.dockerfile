# Ubuntu 24.04 LTS — ntpsec oracle container
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    ntpsec \
    build-essential \
    git \
    rustc \
    cargo \
    clang \
    linux-headers-generic \
    && rm -rf /var/lib/apt/lists/*

# Build ntpsec-rs from local source
COPY .. /opt/ntpsec-rs
WORKDIR /opt/ntpsec-rs
RUN cargo build --release --workspace

# Test configuration
COPY docker/config/oracle-ntp.conf /etc/ntp.conf

EXPOSE 123/udp

CMD ["/opt/ntpsec-rs/target/release/ntpd-rs", "-c", "/etc/ntp.conf", "-n"]
