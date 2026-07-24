# FreeBSD NTPsec oracle container
#
# NOTE: FreeBSD cannot run Linux Docker containers natively.
# This file is documentation for setting up a FreeBSD jail or VM.
# See docs/platform-courts.md for setup instructions.
#
# To test locally, use a FreeBSD VM:
#   vagrant init freebsd/FreeBSD-13.4-RELEASE
#   vagrant up
#   vagrant ssh
#
# Inside the VM:
#   pkg install -y rust cargo git
#   git clone https://github.com/ntpsec/ntpsec-rs
#   cd ntpsec-rs
#   cargo test
