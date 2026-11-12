#!/bin/bash
# Launch an already installed helper, then pull and verify its exported IPA.
# Kept separate so trusting the developer certificate does not require a rebuild.
set -euo pipefail
DEVICE="${1:?usage: export_ipa.sh device helper-bundle-id payload-name}"
UNFAIRPLAYED_BUNDLE_ID="${2:?missing helper bundle ID}"
NAME="${3:?missing payload name}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HOME/Downloads/Unfairplayed-Output"
mkdir -p "$OUT"
EXPORT_LOG="$OUT/export-$NAME.txt"

echo "==> Decrypting embedded payload"
set +e
xcrun devicectl device process launch --console --terminate-existing --device "$DEVICE" \
  --environment-variables '{"FPD_AUTORUN":"export","FPD_EXIT":"1"}' \
  "$UNFAIRPLAYED_BUNDLE_ID" 2>&1 | tee "$EXPORT_LOG"
LAUNCH_STATUS=${PIPESTATUS[0]}
set -e
if [ "$LAUNCH_STATUS" -ne 0 ]; then
  # CoreDevice's Security message can also mention invalid signatures or
  # entitlements, so the UI describes trust as a possible cause, not certainty.
  if grep -Eiq 'profile has not been explicitly trusted|untrusted (application|developer)|developer (certificate|profile).*(not trusted|untrusted)|开发者.*未.*信任|未信任.*开发者' "$EXPORT_LOG"; then
    python3 - "$DEVICE" "$UNFAIRPLAYED_BUNDLE_ID" "$NAME" <<'PY'
import json, sys
print('FPD_TRUST_REQUIRED=' + json.dumps(dict(zip(('device', 'bundle', 'name'), sys.argv[1:])), ensure_ascii=False))
PY
    exit 78
  fi
  exit "$LAUNCH_STATUS"
fi

echo "==> Pulling decrypted IPA"
for suffix in decrypted PARTIAL; do
  DESTINATION="$OUT/$NAME-$suffix.ipa"
  rm -f "$DESTINATION"
  if xcrun devicectl device copy from --device "$DEVICE" \
       --domain-type appDataContainer --domain-identifier "$UNFAIRPLAYED_BUNDLE_ID" \
       --source "Documents/Decrypted/$NAME-$suffix.ipa" --destination "$DESTINATION" \
       >/dev/null 2>&1; then
    echo "pulled $DESTINATION"
    "$HERE/verify_ipa.sh" "$DESTINATION"
    if [ "$suffix" = PARTIAL ]; then
      echo "error: device reported a partial export; inspect $EXPORT_LOG" >&2
      exit 1
    fi
    python3 - "$DEVICE" "$UNFAIRPLAYED_BUNDLE_ID" "$NAME" "$DESTINATION" <<'PY'
import json, sys
print('FPD_EXPORT_COMPLETE=' + json.dumps(dict(zip(('device', 'bundle', 'name', 'ipa'), sys.argv[1:])), ensure_ascii=False))
PY
    exit 0
  fi
done

echo "error: no output IPA found on device; inspect $EXPORT_LOG" >&2
exit 1
