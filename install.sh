#!/bin/bash

set -e

APP_NAME="oktopass" # Change this if your binary name is different
INSTALL_DIR="/usr/local/bin"

# Allow overriding with environment variables
CARGO_BIN=${CARGO_BIN:-$HOME/.cargo/bin}

echo "🔧 Building release version..."
cargo build --release

BIN_PATH="target/release/$APP_NAME"

if [[ ! -f "$BIN_PATH" ]]; then
  echo "❌ Build failed: $BIN_PATH not found"
  exit 1
fi

# macOS / Linux distinction for permissions
if [[ "$OSTYPE" == "darwin"* ]]; then
  echo "🍏 Detected macOS"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
  echo "🐧 Detected Linux"
else
  echo "❓ Unsupported OS: $OSTYPE"
  exit 1
fi

# Install
if [[ -w "$INSTALL_DIR" ]]; then
  echo "📦 Installing to $INSTALL_DIR"
  cp "$BIN_PATH" "$INSTALL_DIR/$APP_NAME"
else
  echo "⚠️ $INSTALL_DIR is not writable, using sudo..."
  sudo cp "$BIN_PATH" "$INSTALL_DIR/$APP_NAME"
fi

echo "✅ Installed $APP_NAME to $INSTALL_DIR"
