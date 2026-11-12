#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
APP="$ROOT/desktop/build/Unfairplayed.app"
if [ ! -x "$APP/Contents/MacOS/Unfairplayed" ]; then
  /bin/bash "$ROOT/build_desktop.sh"
fi
open "$APP"
