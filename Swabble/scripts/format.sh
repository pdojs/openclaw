#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="${ROOT}/config/dev/swiftformat"
swiftformat --config "$CONFIG" "$ROOT/Sources"
