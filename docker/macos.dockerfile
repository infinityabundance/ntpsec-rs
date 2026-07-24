# macOS NTPsec oracle container
#
# NOTE: macOS cannot run Linux Docker containers natively.
# This file is documentation for setting up a macOS build environment.
# See docs/platform-courts.md for setup instructions.
#
# To test locally, use a macOS VM or physical Mac:
#   1. Install Xcode Command Line Tools:
#      xcode-select --install
#   2. Install Rust:
#      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
#   3. Clone and build:
#      git clone https://github.com/ntpsec/ntpsec-rs
#      cd ntpsec-rs
#      cargo test
