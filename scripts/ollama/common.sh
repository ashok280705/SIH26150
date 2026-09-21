#!/usr/bin/env bash
# Shared configuration + helpers for the PROJECT-LOCAL Ollama runtime.
#
# Everything the offline assistant needs (the Ollama binary and the quantized model)
# lives inside the repo under vendor/ollama/, so the app is self-contained and ships
# with its own local LLM. Nothing is installed system-wide.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

VENDOR_DIR="$PROJECT_ROOT/vendor/ollama"
BIN_DIR="$VENDOR_DIR/bin"
DIST_DIR="$VENDOR_DIR/dist"
MODELS_DIR="$VENDOR_DIR/models"

# The quantized model bundled with the app. Override with ASSISTANT_MODEL=...
MODEL="${ASSISTANT_MODEL:-llama3.2:3b}"

# Local daemon endpoint. The frontend's Vite proxy forwards /ollama here.
export OLLAMA_HOST="${OLLAMA_HOST:-127.0.0.1:11434}"
# Keep the model store INSIDE the project so the runtime is self-contained.
export OLLAMA_MODELS="$MODELS_DIR"

# Locate the vendored binary (bin/ollama, or ollama at the vendor root).
ollama_bin() {
  if [ -x "$BIN_DIR/ollama" ]; then echo "$BIN_DIR/ollama";
  elif [ -x "$VENDOR_DIR/ollama" ]; then echo "$VENDOR_DIR/ollama";
  else echo ""; fi
}

# The correct standalone release asset for this OS/arch (stable names on GitHub).
detect_asset() {
  local os arch
  os="$(uname -s)"; arch="$(uname -m)"
  case "$os" in
    Darwin) echo "ollama-darwin.tgz" ;;
    Linux)
      case "$arch" in
        x86_64|amd64) echo "ollama-linux-amd64.tar.zst" ;;
        aarch64|arm64) echo "ollama-linux-arm64.tar.zst" ;;
        *) echo "" ;;
      esac ;;
    *) echo "" ;;
  esac
}

wait_for_daemon() {
  local i
  for i in $(seq 1 60); do
    if curl -fsS "http://$OLLAMA_HOST/api/tags" >/dev/null 2>&1; then return 0; fi
    printf '.'; sleep 0.5
  done
  return 1
}
