#!/usr/bin/env bash
# Start the PROJECT-LOCAL Ollama daemon (bound to localhost, using the in-project
# model store). macOS / Linux. Run scripts/ollama/setup.sh first.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

BIN="$(ollama_bin)"
if [ -z "$BIN" ]; then
  echo "Bundled Ollama not found under $VENDOR_DIR." >&2
  echo "Run scripts/ollama/setup.sh first." >&2
  exit 1
fi

echo "Serving bundled Ollama on http://$OLLAMA_HOST"
echo "  binary : $BIN"
echo "  models : $OLLAMA_MODELS"
exec "$BIN" serve
