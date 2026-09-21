#!/usr/bin/env bash
# One-time bootstrap: download the Ollama runtime into the project and pull the
# quantized assistant model into the project-local model store. macOS / Linux.
#
# Usage:
#   scripts/ollama/setup.sh                 # default model (llama3.2:3b, quantized)
#   ASSISTANT_MODEL=qwen2.5:3b-instruct scripts/ollama/setup.sh
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

mkdir -p "$BIN_DIR" "$DIST_DIR" "$MODELS_DIR"

BIN="$(ollama_bin)"
if [ -z "$BIN" ]; then
  ASSET="$(detect_asset)"
  if [ -z "$ASSET" ]; then
    echo "Unsupported OS/arch ($(uname -s)/$(uname -m)) for the bundled binary." >&2
    echo "Install Ollama manually and point the assistant's base URL at it." >&2
    exit 1
  fi
  URL="https://github.com/ollama/ollama/releases/latest/download/$ASSET"
  echo "==> Downloading Ollama runtime"
  echo "    $URL"
  curl -fSL --progress-bar "$URL" -o "$DIST_DIR/$ASSET"

  echo "==> Extracting into $VENDOR_DIR"
  case "$ASSET" in
    *.tgz)
      tar -xzf "$DIST_DIR/$ASSET" -C "$VENDOR_DIR" ;;
    *.tar.zst)
      if tar --help 2>/dev/null | grep -q -- '--zstd'; then
        tar --zstd -xf "$DIST_DIR/$ASSET" -C "$VENDOR_DIR"
      elif command -v zstd >/dev/null 2>&1; then
        zstd -dc "$DIST_DIR/$ASSET" | tar -x -C "$VENDOR_DIR"
      else
        echo "Need zstd (or GNU tar with --zstd) to extract $ASSET." >&2
        echo "Install zstd (e.g. 'brew install zstd' / 'apt install zstd') and re-run." >&2
        exit 1
      fi ;;
  esac

  BIN="$(ollama_bin)"
  if [ -z "$BIN" ]; then
    echo "Extraction did not produce an 'ollama' binary under $VENDOR_DIR." >&2
    exit 1
  fi
  chmod +x "$BIN" 2>/dev/null || true
fi
echo "==> Ollama binary: $BIN"

# Start a temporary daemon (using the project-local model store) just to pull.
"$BIN" serve >"$DIST_DIR/setup-daemon.log" 2>&1 &
DAEMON_PID=$!
cleanup() { kill "$DAEMON_PID" 2>/dev/null || true; }
trap cleanup EXIT

printf '==> Starting local daemon'
if ! wait_for_daemon; then
  echo
  echo "Daemon did not become ready. See $DIST_DIR/setup-daemon.log" >&2
  exit 1
fi
echo " ready"

echo "==> Pulling quantized model into the project store: $MODEL"
"$BIN" pull "$MODEL"

echo
echo "Done."
echo "  Binary : $BIN"
echo "  Models : $MODELS_DIR"
echo "  Model  : $MODEL"
echo
echo "Start the assistant runtime any time with:  scripts/ollama/serve.sh"
echo "(The forensic API also auto-starts it if the bundled binary is present.)"
