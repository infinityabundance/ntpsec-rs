# Alpine Linux — ntpsec oracle container
FROM alpine:3.20

RUN apk add --no-cache \
    ntpsec \
    ntpsec-doc \
    ntpsec-clients \
    build-base \
    git \
    rust \
    cargo \
    clang \
    linux-headers

# Build ntpsec-rs from local source
COPY .. /opt/ntpsec-rs
WORKDIR /opt/ntpsec-rs
RUN cargo build --release --workspace

# Test configuration
COPY docker/config/oracle-ntp.conf /etc/ntp.conf

EXPOSE 123/udp

CMD ["/opt/ntpsec-rs/target/release/ntpd-rs", "-c", "/etc/ntp.conf", "-n"]
