#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
INSTALL=0
PACKAGE=0
for option in "$@"; do
  case "$option" in
    --install) INSTALL=1 ;;
    --package) PACKAGE=1 ;;
    *) echo "Usage: $0 [--install] [--package]" >&2; exit 2 ;;
  esac
done
OUT="$ROOT/desktop/build"
mkdir -p "$OUT"
STAGE="$(mktemp -d "$OUT/desktop-package.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT
APP="$STAGE/Unfairplayed.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
if [ ! -f "$ROOT/desktop/Assets/Unfairplayed.icns" ] || \
   [ "$ROOT/desktop/Assets/UnfairplayedLogo.png" -nt "$ROOT/desktop/Assets/Unfairplayed.icns" ]; then
  /bin/bash "$ROOT/desktop/build_icon.sh"
fi
# Both executables and Info.plist declare the same deployment target.
# Prefix maps also remove the builder's home and checkout path from Mach-O strings.
SWIFT_FLAGS=(-swift-version 5 -target arm64-apple-macos15.0 -O
  -file-prefix-map "$ROOT=/UnfairplayedSource" -file-prefix-map "$HOME=/User"
  -debug-prefix-map "$ROOT=/UnfairplayedSource" -debug-prefix-map "$HOME=/User")
xcrun swiftc "${SWIFT_FLAGS[@]}" -parse-as-library -framework SwiftUI -framework AppKit -framework CryptoKit \
  "$ROOT/desktop/Unfairplayed.swift" "$ROOT/desktop/TaskLogStore.swift" \
  "$ROOT/desktop/WorkspaceBootstrap.swift" -o "$APP/Contents/MacOS/Unfairplayed"
xcrun swiftc "${SWIFT_FLAGS[@]}" -framework Security -framework CryptoKit \
  "$ROOT/desktop/SigningHelper.swift" -o "$STAGE/SigningHelper"
python3 -B "$ROOT/desktop/release_tools.py" stage --root "$ROOT" --helper "$STAGE/SigningHelper" \
  --destination "$APP/Contents/Resources/WorkspaceTemplate"
cp "$ROOT/desktop/Assets/UnfairplayedLogo.png" "$APP/Contents/Resources/UnfairplayedLogo.png"
cp "$ROOT/desktop/Assets/Unfairplayed.icns" "$APP/Contents/Resources/Unfairplayed.icns"
python3 -B - "$APP" <<'PY'
from pathlib import Path
import plistlib, sys
info = {
    'CFBundleName': 'Unfairplayed', 'CFBundleDisplayName': 'Unfairplayed',
    'CFBundleIdentifier': 'dev.unfairplayed.desktop', 'CFBundleExecutable': 'Unfairplayed',
    'CFBundleIconFile': 'Unfairplayed.icns', 'CFBundlePackageType': 'APPL',
    'CFBundleShortVersionString': '1.0', 'CFBundleVersion': '1',
    'LSMinimumSystemVersion': '15.0', 'LSArchitecturePriority': ['arm64'],
    'NSHighResolutionCapable': True,
}
Path(sys.argv[1], 'Contents/Info.plist').write_bytes(plistlib.dumps(info))
PY
/usr/bin/codesign --force --sign - "$APP"
/usr/bin/codesign --verify --strict "$APP"
# Audit a fresh bundle, never a previous installation with caches or old resources.
python3 -B - "$ROOT" "$APP" <<'PY'
from pathlib import Path
import sys
sys.path.insert(0, str(Path(sys.argv[1]) / 'desktop'))
from release_tools import audit_tree, private_patterns
audit_tree(Path(sys.argv[2]), private_patterns(Path(sys.argv[1])))
PY
TARGET="$OUT/Unfairplayed.app"
if [ -e "$TARGET" ]; then mv "$TARGET" "$STAGE/Previous.app"; fi
mv "$APP" "$TARGET"
if [ "$PACKAGE" = 1 ]; then
  python3 -B "$ROOT/desktop/release_tools.py" package --root "$ROOT" --app "$TARGET" --destination "$ROOT/desktop/dist"
fi
if [ "$INSTALL" = 1 ]; then
  mkdir -p "$HOME/Applications"
  /usr/bin/ditto "$TARGET" "$STAGE/Install.app"
  if [ -e "$HOME/Applications/Unfairplayed.app" ]; then
    mv "$HOME/Applications/Unfairplayed.app" "$STAGE/Previously-installed.app"
  fi
  mv "$STAGE/Install.app" "$HOME/Applications/Unfairplayed.app"
  echo "Installed: $HOME/Applications/Unfairplayed.app"
else
  echo "Built: $TARGET"
fi
