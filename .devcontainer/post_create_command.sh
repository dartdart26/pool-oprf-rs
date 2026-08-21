#!/bin/bash

set -euo pipefail

# Package manager dependencies.
sudo apt update
sudo apt install -y build-essential pkg-config libudev-dev llvm libclang-dev protobuf-compiler libssl-dev vim poppler-utils

# Install the Rust toolchain.
rustup toolchain install
rustup component add rustfmt
rustup component add clippy

# Install Claude Code.
curl --proto '=https' --tlsv1.2 -sSfL https://claude.ai/install.sh | bash
