# Alpine Linux — ntpsec oracle container
FROM alpine:3.18

# Install build dependencies + C ntpq runtime
RUN apk add --no-cache \
    ntpsec \
    build-base \
    git \
    clang \
    linux-headers \
    curl \
    cmake \
    bison \
    flex \
    openssl-dev \
    python3 \
    py3-pip \
    libcap-dev

# Install rustup for Rust ntpsec-rs toolchain
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"

# Remove Python ntpq — we want the C binary for oracle comparison
RUN rm -f /usr/bin/ntpq /usr/bin/ntpdig 2>/dev/null || true

# Compile C ntpq (ntpq-classic) from ntpsec source (tag NTPsec_0_9_4, last C version)
RUN git clone --depth 1 https://gitlab.com/NTPsec/ntpsec.git /tmp/ntpsec-src && \
    cd /tmp/ntpsec-src && \
    git fetch --tags --depth 100 origin NTPsec_0_9_4 && \
    git checkout NTPsec_0_9_4

WORKDIR /tmp/ntpsec-src
# Patch waf for Python 3.11+ compatibility
RUN python3 ./waf --help 2>/dev/null; true && \
    find . -path '*/waflib/*.py' -exec sed -i \
    -e "s/'rU'/'r'/g" \
    -e "s/'rUb'/'rb'/g" \
    -e 's/"rU"/"r"/g' \
    -e 's/"rUb"/"rb"/g' \
    -e 's/raise StopIteration/return/g' \
    {} \; 2>/dev/null || true
# Fix Python 2 source for Python 3 using 2to3
RUN set -ex && \
    python3 -m lib2to3 -w -n --no-diffs wscript wafhelpers/ pylib/ 2>&1 | tail -10 && \
    # Expand tabs to 8 spaces in all Python files (except .waf3) 
    find . -name '*.py' -not -path './.waf3*' -exec sh -c \
    'for f; do expand -t 8 "$f" > /tmp/pyfix && mv /tmp/pyfix "$f"; done' _ {} + && \
    # Fix Python 3 compat issues
    sed -i 's/\.replace("\\n", "")/.decode().replace("\\n", "")/g' wafhelpers/configure.py && \
    sed -i 's/sorted(sizeofs)/sorted(sizeofs, key=lambda x: str(x[0]))/g' wafhelpers/configure.py && \
    # Fix broken relative imports (2to3 converts badly)
    sed -i 's/from \.util import/from util import/g' wafhelpers/asciidoc.py
RUN python3 ./waf configure --prefix=/usr
# Fix C compilation error on struct ntptimeval (tai member removed in recent Linux)
RUN sed -i '/ntv\.tai/d' ntptime/ntptime.c && \
    sed -i 's/NTP_API > 3/0/' ntptime/ntptime.c
RUN python3 ./waf build 2>&1; echo "===WAF BUILD EXIT: $?==="; \
    cp build/main/ntpq/ntpq /usr/bin/ntpq 2>&1 && echo "===NTPQ COPIED===" || echo "===NTPQ BUILD FAILED==="; \
    cp build/main/ntpdig/ntpdig /usr/bin/ntpdig 2>&1 || true

# Verify C ntpq is an ELF binary
RUN file /usr/bin/ntpq | grep -q ELF || (echo "ERROR: ntpq is not an ELF binary" && exit 1)

# Build ntpsec-rs from local source
COPY . /opt/ntpsec-rs
WORKDIR /opt/ntpsec-rs
RUN cargo build --release --workspace

# Test configuration
COPY docker/config/oracle-ntp.conf /etc/ntp.conf

EXPOSE 123/udp

CMD ["/opt/ntpsec-rs/target/release/ntpd-rs", "-c", "/etc/ntp.conf", "-n"]
