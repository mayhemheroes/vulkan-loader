#!/usr/bin/env bash
#
# vulkan-loader/mayhem/test.sh — RUN the golden manifest-parse oracle (built by mayhem/build.sh)
# and emit a CTRF summary. exit 0 iff no check failed.
#
# PATCH-grade oracle: mayhem/oracle/manifest_oracle.c drives the SAME function json_load_fuzzer
# fuzzes (loader_get_json + the loader's cJSON) and asserts known answers over it — well-formed
# ICD/layer/nested manifests parse and their nested string values read back byte-exactly, AND a
# malformed manifest is rejected. A no-op / "always succeed" patch to the parser fails T1/T2/T4
# (values won't round-trip) or T3 (garbage would be accepted). This script only RUNS the prebuilt
# binary; it never compiles.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

ORACLE="$SRC/mayhem-build/manifest_oracle"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if [ ! -x "$ORACLE" ]; then
  echo "missing $ORACLE — run mayhem/build.sh first" >&2
  emit_ctrf "manifest-oracle" 0 1 0; exit 2
fi

echo "=== running manifest-parse oracle ==="
out="$("$ORACLE" 2>&1)"; rc=$?
echo "$out"

# TAP-ish: count "ok N - ..." (but not "not ok") as passes, "not ok N - ..." as failures.
PASSED=$(printf '%s\n' "$out" | grep -cE '^ok ')
FAILED=$(printf '%s\n' "$out" | grep -cE '^not ok ')
: "${PASSED:=0}" "${FAILED:=0}"

# If we couldn't parse any lines, fall back to the oracle's exit code (= failure count).
if [ "$(( PASSED + FAILED ))" -eq 0 ]; then
  echo "could not parse oracle output; using exit code $rc" >&2
  [ "$rc" -eq 0 ] && { emit_ctrf "manifest-oracle" 1 0 0; exit 0; }
  emit_ctrf "manifest-oracle" 0 1 0; exit 1
fi

# The oracle returns its failure count as the exit code; treat a nonzero rc as authoritative too.
if [ "$rc" -ne 0 ] && [ "$FAILED" -eq 0 ]; then FAILED=1; fi

emit_ctrf "manifest-oracle" "$PASSED" "$FAILED"
