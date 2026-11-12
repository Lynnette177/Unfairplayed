#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
exec /bin/bash "$ROOT/build_desktop.sh" --package
