# Fedora 40 — ntpsec oracle container
FROM fedora:40

RUN dnf install -y \
    ntpsec \
    gcc \
    git \
    clang \
    kernel-headers \
    curl \
    && dnf clean all

# Install rustup for a modern Rust toolchain
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
