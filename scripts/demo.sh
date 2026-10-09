#!/usr/bin/env bash
# End-to-end demo: a compromised diagnostic-side unit attacks the truck three ways, and the
# three defensive layers this project builds stop it. Everything here runs offline on the
# deterministic simulator (fixed seeds), so it reproduces byte-for-byte and runs in CI.
#
#   M3 (detect)      - the passive IDS raises alerts inside the attack window
#   M4 (authenticate)- SecOC rejects the spoofed and replayed safety messages
#   M5 (contain)     - the default-deny gateway keeps the diagnostic-side command off the
#                      powertrain bus
#
# Usage: scripts/demo.sh [BUILD_DIR]   (default: build)
set -euo pipefail

BUILD="${1:-build}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT

# Colour only on a terminal (and not when NO_COLOR is set), so CI logs stay clean.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then B=$'\033[1m'; G=$'\033[32m'; R=$'\033[31m'; Z=$'\033[0m'
else B=''; G=''; R=''; Z=''; fi
say()  { printf '\n%s== %s ==%s\n' "$B" "$*" "$Z"; }
ok()   { printf '  %sPASS%s  %s\n' "$G" "$Z" "$*"; }
fail() { printf '  %sFAIL%s  %s\n' "$R" "$Z" "$*"; exit 1; }

for b in vn-sim vn-attack vn-ids vn-secoc vn-gateway; do
  [ -x "$BUILD/$b" ] || fail "missing binary $BUILD/$b (build first: cmake --build $BUILD)"
done

say "Baseline: 180 s of normal traffic from the simulated truck (seed 42)"
"$BUILD/vn-sim" --duration 180 --seed 42 --out "$W/clean.log" 2>/dev/null
printf '  %s frames of clean powertrain + body traffic\n' "$(grep -c . "$W/clean.log")"

# ---------------------------------------------------------------------------
say "Threat 1 - Spoofing a safety message (STRIDE: Spoofing / Tampering)"
# The attacker forges engine/brake-class frames from a source that should not send them.
"$BUILD/vn-attack" "$W/clean.log" --attack spoof --start 110 --duration 20 \
  --out "$W/spoofed.log" --labels "$W/spoofed.labels" --seed 42 >/dev/null

echo "  M3 (detect): run the passive IDS over the attacked log"
if python3 tools/evaluate_ids.py "$BUILD/vn-ids" "$W/spoofed.log" "$W/spoofed.labels" \
     --train-frac 0.4 | tee "$W/ids.out" | grep -q "detected 1/1"; then
  ok "IDS raised alerts inside the spoof window ($(grep -oE '[0-9]+ alerts' "$W/ids.out" | head -1))"
else
  fail "IDS did not detect the spoof"
fi

echo "  M4 (authenticate): protect the two safety PGNs, then replay the attack against them"
"$BUILD/vn-secoc" protect "$W/clean.log" --pgn 65265 --pgn 61441 --out "$W/prot.log" >/dev/null
if "$BUILD/vn-secoc" verify "$W/prot.log" --pgn 65265 --pgn 61441 >/dev/null 2>&1; then
  ok "genuine authenticated traffic all verifies"
else
  fail "genuine traffic failed to verify (false reject)"
fi
"$BUILD/vn-attack" "$W/prot.log" --attack spoof --start 60 --duration 20 --out "$W/spoof_prot.log" >/dev/null
if "$BUILD/vn-secoc" verify "$W/spoof_prot.log" --pgn 65265 --pgn 61441 >/dev/null 2>&1; then
  fail "SecOC accepted a spoofed safety message"
else
  ok "SecOC rejected the spoofed safety message (no valid tag)"
fi

# ---------------------------------------------------------------------------
say "Threat 2 - Replaying a captured authenticated message (STRIDE: Tampering / replay)"
"$BUILD/vn-attack" "$W/prot.log" --attack replay --start 60 --duration 20 --out "$W/replay_prot.log" >/dev/null
if "$BUILD/vn-secoc" verify "$W/replay_prot.log" --pgn 65265 --pgn 61441 >/dev/null 2>&1; then
  fail "SecOC accepted a replayed message"
else
  ok "SecOC rejected the replay (stale freshness)"
fi

# ---------------------------------------------------------------------------
say "Threat 3 - Command injection + flood from the diagnostic side (STRIDE: Elevation / DoS)"
# Stream powertrain traffic toward the diagnostic bus through the default-deny gateway, while
# an attacker on the diagnostic side injects a command (PGN 0) aimed at the powertrain.
"$BUILD/vn-sim" --duration 20 --seed 42 --out "$W/gw_in.log" 2>/dev/null
printf '(1700000020.000000) can0 0C0000F9#0102030405060708\n' >> "$W/gw_in.log"   # attacker command
"$BUILD/vn-gateway" offline "$W/gw_in.log" --policy deploy/gateway.policy --direction 'B>A' \
  --out "$W/gw_out.log" 2>"$W/gw.err"
echo "  $(cat "$W/gw.err")"
echo "  M5 (contain): check what crossed to the protected bus"
if python3 tools/check_gateway.py "$W/gw_out.log" deploy/gateway.policy | tee "$W/gw.check" | grep -q "^PASS"; then
  ok "only the allowlisted powertrain PGNs crossed; the attacker's command was dropped"
else
  cat "$W/gw.check"; fail "gateway let something through it should not have"
fi

say "All three layers held. Detect (M3), authenticate (M4), contain (M5)."
