#!/bin/bash
# Report the encryption state of every Mach-O in an IPA. Exit 1 if any 64-bit slice is still encrypted.
set -euo pipefail
IPA="${1:?usage: verify_ipa.sh app.ipa}"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
unzip -q "$IPA" -d "$TMP"
[ -d "$TMP/Payload" ] || { echo "error: no Payload directory" >&2; exit 1; }

enc=0; dec=0; plain=0
while IFS= read -r -d '' f; do
  file -b "$f" | grep -q 'Mach-O' || continue
  rel="${f#$TMP/Payload/}"
  # Inspect every architecture, including arm64e, and fail on parsing errors.
  loads="$(otool -arch all -l "$f" 2>&1)" || { echo "error: cannot inspect $rel: $loads" >&2; exit 1; }
  ids="$(printf '%s\n' "$loads" | awk '$1 == "cryptid" {print $2}')"
  if [ -z "$ids" ]; then
    plain=$((plain + 1))
  elif printf '%s\n' "$ids" | awk '$1 != 0 {found=1} END {exit !found}'; then
    enc=$((enc + 1)); echo "ENCRYPTED  $rel"
  else
    dec=$((dec + 1)); echo "cryptid=0  $rel"
  fi
done < <(find "$TMP/Payload" -type f -print0)
echo "summary: $dec with cryptid 0, $enc still encrypted, $plain without LC_ENCRYPTION_INFO_64"
[ "$((dec + enc + plain))" -gt 0 ] || { echo "error: no Mach-O files found" >&2; exit 1; }
[ "$enc" -eq 0 ]
