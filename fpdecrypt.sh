#!/bin/bash
# Download (optional), embed, build, sign, install, decrypt, pull, and verify an IPA.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./fpdecrypt.sh path/to/encrypted.ipa [options]
  ./fpdecrypt.sh --download <target-app-bundle-id> [options]
  ./fpdecrypt.sh --build-only [options]
  ./fpdecrypt.sh --install-only [options]

Options:
  --download <id>              Download the target app with ipatool first.
  --device <udid>              Physical iPhone UDID. Auto-detected when exactly one is connected.
  --unfairplayed-bundle-id <id>  Bundle ID of the Unfairplayed helper app.
                               Default: dev.unfairplayed.helper
  --team-id <id>               Override the Team selected in Xcode (mainly for CI).
  --platform <name>            ipatool platform (iphone, ipad, etc.) for --download.
  --skip-trust-prompt          Do not pause after installation to verify the developer certificate.
  --build-only                 Build/sign the current helper without connecting a device.
  --install-only               Build/install the current helper without running decryption.
  -h, --help                   Show this help.

Environment equivalents:
  DEVICE, UNFAIRPLAYED_BUNDLE_ID, TEAM_ID, PLATFORM, SKIP_TRUST_PROMPT=1

Important:
  The target app bundle ID is used only with --download. Unfairplayed must use its
  own bundle ID; never use the target app's bundle ID as UNFAIRPLAYED_BUNDLE_ID.
EOF
}

fail() {
  echo "error: $*" >&2
  exit 1
}

HERE="$(cd "$(dirname "$0")" && pwd)"
LOCAL_CONFIG="$HERE/.unfairplayed.env"
SAVED_TEAM_ID=""
config_value() {
  [ ! -f "$LOCAL_CONFIG" ] || sed -n "s/^$1=//p" "$LOCAL_CONFIG" | tail -1
}
if [ -f "$LOCAL_CONFIG" ]; then
  SAVED_TEAM_ID="$(sed -n 's/^TEAM_ID=//p' "$LOCAL_CONFIG" | tail -1)"
fi

IPA=""
TARGET_BUNDLE_ID=""
DEVICE="${DEVICE:-$(config_value DEVICE)}"
UNFAIRPLAYED_BUNDLE_ID="${UNFAIRPLAYED_BUNDLE_ID:-$(config_value UNFAIRPLAYED_BUNDLE_ID)}"
SAVE_HELPER_ID=0
if [ -z "$UNFAIRPLAYED_BUNDLE_ID" ]; then
  UNFAIRPLAYED_BUNDLE_ID="dev.unfairplayed.helper.$(uuidgen | tr '[:upper:]' '[:lower:]' | tr -d '-')"
  SAVE_HELPER_ID=1
fi
TEAM_ID_FROM_ENV="${TEAM_ID:-}"
TEAM_ID="${TEAM_ID_FROM_ENV:-$SAVED_TEAM_ID}"
HELPER_SIGNER_ID="${HELPER_SIGNER_ID:-$(config_value HELPER_SIGNER_ID)}"
IMPORTED_SIGNING=0
case "$HELPER_SIGNER_ID" in imported:*) IMPORTED_SIGNING=1 ;; esac
TEAM_ID_EXPLICIT=0
[ -z "$TEAM_ID_FROM_ENV" ] || TEAM_ID_EXPLICIT=1
# Persist the first helper ID even when the Team came from an environment variable.
SAVE_TEAM_ID="$SAVE_HELPER_ID"
PLATFORM="${PLATFORM:-}"
SKIP_TRUST_PROMPT="${SKIP_TRUST_PROMPT:-$(config_value SKIP_TRUST_PROMPT)}"
SKIP_TRUST_PROMPT="${SKIP_TRUST_PROMPT:-0}"
BUILD_ONLY=0
INSTALL_ONLY=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --download)
      [ "$#" -ge 2 ] || fail "--download requires the target app bundle ID"
      TARGET_BUNDLE_ID="$2"; shift 2 ;;
    --device)
      [ "$#" -ge 2 ] || fail "--device requires a UDID"
      DEVICE="$2"; shift 2 ;;
    --unfairplayed-bundle-id)
      [ "$#" -ge 2 ] || fail "--unfairplayed-bundle-id requires a value"
      UNFAIRPLAYED_BUNDLE_ID="$2"; shift 2 ;;
    --team-id)
      [ "$#" -ge 2 ] || fail "--team-id requires a value"
      TEAM_ID="$2"; TEAM_ID_EXPLICIT=1; SAVE_TEAM_ID=1; shift 2 ;;
    --platform)
      [ "$#" -ge 2 ] || fail "--platform requires a value"
      PLATFORM="$2"; shift 2 ;;
    --skip-trust-prompt)
      SKIP_TRUST_PROMPT=1; shift ;;
    --build-only)
      BUILD_ONLY=1; shift ;;
    --install-only)
      INSTALL_ONLY=1; shift ;;
    -h|--help)
      usage; exit 0 ;;
    --)
      shift
      [ "$#" -eq 1 ] && [ -z "$IPA" ] || fail "provide exactly one IPA after --"
      IPA="$1"; shift ;;
    -*)
      fail "unknown option: $1 (run ./fpdecrypt.sh --help)" ;;
    *)
      [ -z "$IPA" ] || fail "provide only one IPA path"
      IPA="$1"; shift ;;
  esac
done

[ -z "$IPA" ] || [ -z "$TARGET_BUNDLE_ID" ] || \
  fail "provide an IPA path or --download, not both"
[ "$BUILD_ONLY" = 0 ] || [ "$INSTALL_ONLY" = 0 ] || fail "choose --build-only or --install-only"
[ -n "$IPA" ] || [ -n "$TARGET_BUNDLE_ID" ] || [ "$BUILD_ONLY" = 1 ] || [ "$INSTALL_ONLY" = 1 ] || { usage >&2; exit 2; }


PROJ="$HERE/iOS"
OUT="$HOME/Downloads/Unfairplayed-Output"
mkdir -p "$OUT"

PROJECT_FILE="$PROJ/Unfairplayed.xcodeproj/project.pbxproj"
PROJECT_TEAM_IDS="$(sed -nE 's/^[[:space:]]*DEVELOPMENT_TEAM = ([[:alnum:]]{10});$/\1/p' \
  "$PROJECT_FILE" | sort -u)"
PROJECT_TEAM_COUNT="$(printf '%s\n' "$PROJECT_TEAM_IDS" | sed '/^$/d' | wc -l | tr -d ' ')"

if [ "$PROJECT_TEAM_COUNT" -gt 1 ]; then
  printf 'Multiple development teams are configured in Xcode:\n%s\n' "$PROJECT_TEAM_IDS" >&2
  fail "select one Team for every Unfairplayed build configuration, then close Xcode"
elif [ "$PROJECT_TEAM_COUNT" = "1" ]; then
  if [ "$TEAM_ID_EXPLICIT" = "0" ]; then
    TEAM_ID="$PROJECT_TEAM_IDS"
    SAVE_TEAM_ID=1
    echo "==> Imported the Team selected in Xcode"
  elif [ "$TEAM_ID" != "$PROJECT_TEAM_IDS" ]; then
    echo "warning: --team-id/TEAM_ID overrides the different Team selected in Xcode" >&2
  fi

  SANITIZED_PROJECT="$(mktemp "${TMPDIR:-/tmp}/unfairplayed-project.XXXXXX")"
  sed -E '/^[[:space:]]*DEVELOPMENT_TEAM = [[:alnum:]]{10};$/d' \
    "$PROJECT_FILE" > "$SANITIZED_PROJECT"
  cp "$SANITIZED_PROJECT" "$PROJECT_FILE"
  rm -f "$SANITIZED_PROJECT"
  echo "==> Removed the private Team ID from project.pbxproj"
fi

if [ -z "$TEAM_ID" ] && [ "$IMPORTED_SIGNING" = 0 ]; then
  echo "No local Apple Development Team is configured." >&2
  echo "Open iOS/Unfairplayed.xcodeproj in Xcode, select the Unfairplayed target," >&2
  echo "enable Signing & Capabilities > Automatically manage signing, choose your Team," >&2
  echo "save the project, close Xcode, and run this command again." >&2
  fail "Team setup is required once before the first run"
fi

if [ -n "$TEAM_ID" ]; then
  [[ "$TEAM_ID" =~ ^[[:alnum:]]{10}$ ]] || fail "Team ID must contain exactly 10 letters or digits"
fi
if [ "$SAVE_TEAM_ID" = "1" ]; then
  CONFIG_TMP="$(mktemp "$HERE/.unfairplayed.env.XXXXXX")"
  if [ -f "$LOCAL_CONFIG" ]; then
    sed '/^TEAM_ID=/d' "$LOCAL_CONFIG" > "$CONFIG_TMP"
  fi
  printf 'TEAM_ID=%s\n' "$TEAM_ID" >> "$CONFIG_TMP"
  mv "$CONFIG_TMP" "$LOCAL_CONFIG"
  chmod 600 "$LOCAL_CONFIG"
  echo "==> Saved Team locally in $LOCAL_CONFIG (ignored by Git)"
fi

for tool in xcodebuild xcrun unzip ditto otool python3; do
  command -v "$tool" >/dev/null || fail "required tool not found: $tool"
done

if [ -n "$TARGET_BUNDLE_ID" ]; then
  command -v ipatool >/dev/null || fail "ipatool is required for --download (brew install ipatool)"
  DOWNLOAD_DIR="$(mktemp -d "$OUT/download-XXXXXX")"
  IPA="$DOWNLOAD_DIR/encrypted.ipa"
  echo "==> Downloading target app: $TARGET_BUNDLE_ID"
  DOWNLOAD_ARGS=(download --bundle-identifier "$TARGET_BUNDLE_ID" --purchase --output "$IPA")
  [ -z "$PLATFORM" ] || DOWNLOAD_ARGS+=(--platform "$PLATFORM")
  ipatool --non-interactive "${DOWNLOAD_ARGS[@]}"
fi

[ -z "$IPA" ] || [ -f "$IPA" ] || fail "IPA not found: $IPA"

if [ -z "$DEVICE" ] && [ "$BUILD_ONLY" = 0 ]; then
  echo "==> Detecting a connected physical iPhone"
  DEVICE_LIST="$(xcrun devicectl list devices --filter "Reality = 'physical' AND (Model CONTAINS 'iPhone' OR Model CONTAINS 'iPad') AND State != 'unavailable'" 2>/dev/null || true)"
  DEVICE_CANDIDATES="$(printf '%s\n' "$DEVICE_LIST" | grep -Eo '0000[[:xdigit:]]{4}-[[:xdigit:]]{16}' | sort -u || true)"
  DEVICE_COUNT="$(printf '%s\n' "$DEVICE_CANDIDATES" | sed '/^$/d' | wc -l | tr -d ' ')"
  if [ "$DEVICE_COUNT" = "1" ]; then
    DEVICE="$DEVICE_CANDIDATES"
  elif [ "$DEVICE_COUNT" = "0" ]; then
    fail "no physical iPhone found; connect and unlock it, then use --device <udid>"
  else
    printf 'Multiple physical devices found:\n%s\n' "$DEVICE_CANDIDATES" >&2
    fail "select one with --device <udid>"
  fi
fi

# devicectl also accepts a physical device's CoreDevice UUID. Do not mistake
# every UUID for a simulator identifier.

echo "==> Configuration"
echo "    Device:              $DEVICE"
echo "    Unfairplayed bundle:   $UNFAIRPLAYED_BUNDLE_ID"
echo "    Development team:    $TEAM_ID"
echo "    Encrypted IPA:       $IPA"

if [ -n "$IPA" ]; then
  echo "==> Embedding IPA"
  "$HERE/embed_ipa.sh" "$IPA"
fi
NAME=""
if [ "$BUILD_ONLY" = 0 ] && [ "$INSTALL_ONLY" = 0 ]; then
  NAME="$(find "$PROJ/payload" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | head -1)"
  [ -n "$NAME" ] || fail "embedded payload name could not be determined"
fi

BUILD_LOG="$OUT/build.log"
echo "==> Building and signing Unfairplayed (full log: $BUILD_LOG)"
set +e
DESTINATION="id=$DEVICE"
[ "$BUILD_ONLY" = 0 ] || DESTINATION="generic/platform=iOS"
SIGN_ARGS=(DEVELOPMENT_TEAM="$TEAM_ID" -allowProvisioningUpdates)
if [ "$IMPORTED_SIGNING" = 1 ]; then
  SIGN_ARGS=(CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO)
fi
xcodebuild -project "$PROJ/Unfairplayed.xcodeproj" -scheme Unfairplayed -configuration Debug \
  -destination "$DESTINATION" -derivedDataPath "$PROJ/build" \
  PRODUCT_BUNDLE_IDENTIFIER="$UNFAIRPLAYED_BUNDLE_ID" "${SIGN_ARGS[@]}" build \
  2>&1 | tee "$BUILD_LOG"
BUILD_STATUS=${PIPESTATUS[0]}
set -e
if [ "$BUILD_STATUS" -ne 0 ]; then
  echo "Build failed. Relevant diagnostics:" >&2
  grep -E '(^| )error:|BUILD FAILED|provisioning profile|Signing' "$BUILD_LOG" | tail -30 >&2 || true
  if grep -q 'No Account for Team' "$BUILD_LOG"; then
    echo "Xcode has no signed-in Apple account for this Team ID." >&2
    echo "Open Xcode > Settings > Apple Accounts and add or re-authenticate that Apple account." >&2
    echo "Keep $LOCAL_CONFIG unless the Team ID itself is incorrect." >&2
  fi
  exit "$BUILD_STATUS"
fi

APP_PATH="$PROJ/build/Build/Products/Debug-iphoneos/Unfairplayed.app"
[ -d "$APP_PATH" ] || fail "built app not found: $APP_PATH"
if [ "$IMPORTED_SIGNING" = 1 ]; then
  echo "==> Signing Unfairplayed with imported identity"
  python3 "$HERE/desktop/debug_ipa.py" sign-helper --root "$HERE" --app "$APP_PATH" \
    --signer "$HELPER_SIGNER_ID" --device "$DEVICE" --bundle "$UNFAIRPLAYED_BUNDLE_ID"
fi
[ "$BUILD_ONLY" = 0 ] || { echo "==> Built $APP_PATH"; exit 0; }

echo "==> Installing Unfairplayed"
xcrun devicectl device install app --device "$DEVICE" "$APP_PATH"
[ "$INSTALL_ONLY" = 0 ] || { echo "==> Installed. Trust the developer certificate before launching."; exit 0; }

if [ "$SKIP_TRUST_PROMPT" != "1" ]; then
  echo
  echo "==> Verify the developer certificate on the iPhone"
  echo "    Keep the iPhone unlocked and connected. Open:"
  echo "    Settings > General > VPN & Device Management > Developer App"
  echo "    Select your developer account and tap Trust/Verify if it is shown."
  echo
  if [ -t 0 ]; then
    read -r -p "Press Enter after the developer certificate is trusted... " _
  else
    fail "certificate verification requires an interactive terminal; rerun normally or use --skip-trust-prompt"
  fi
fi

exec /bin/bash "$HERE/export_ipa.sh" "$DEVICE" "$UNFAIRPLAYED_BUNDLE_ID" "$NAME"
