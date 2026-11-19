#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
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

# Runs upstream's two suites, built by mayhem/build.sh with upstream's normal flags:
#   * tests/test_rhash.sh --full against the oracle CLI (what upstream CI's `make test-full` runs):
#     26 known-answer test groups of digests, hash-file verification/update, templates,
#     magnet/torrent output, and every hash option. Each check prints "Ok" or "Failed"; the script
#     ends with "Failed N checks" on failure.
#   * tests/test_template_*.py: upstream's regression tests for --template file loading (BOM skip,
#     hash names, 64 KiB size limit); each asserts rhash's output/exit code and exits 0 on pass.
#   * librhash/test_static: known-answer vectors for every algorithm, chunked updates,
#     export/import round-trips; prints "All sums are working properly!" on success.
ORACLE="$SRC/mayhem/out/oracle"
passed=0 failed=0
for b in rhash test_static; do
  [ -x "$ORACLE/$b" ] || { echo "missing $ORACLE/$b (build.sh did not produce it)" >&2; emit_ctrf rhash-tests 0 1; exit 1; }
done

out=$(HOME=/nonexistent XDG_CONFIG_HOME=/nonexistent /bin/sh "$SRC/tests/test_rhash.sh" --full "$ORACLE/rhash" 2>&1); rc=$?
printf '%s\n' "$out"
ok=$(printf '%s\n' "$out" | grep -c 'Ok$' || true)
bad=$(printf '%s\n' "$out" | grep -c 'Failed' || true)
# a run that stops early (crash / smoke-test failure) or reports nothing is a failure
if [ "$rc" -ne 0 ] || [ "$ok" -lt 26 ]; then bad=$((bad > 0 ? bad : 1)); fi
passed=$((passed + ok)); failed=$((failed + bad))

command -v python3 >/dev/null || { echo "python3 missing (needed by tests/test_template_*.py)" >&2; emit_ctrf rhash-tests 0 1; exit 1; }
nt=0
for f in "$SRC"/tests/test_template_*.py; do
  [ -f "$f" ] || continue
  nt=$((nt + 1))
  # bounded: test_template_limit.py opens a FIFO for writing, which blocks forever if rhash exits
  # without opening it (e.g. a no-op patch); a timeout counts as a failure.
  if HOME=/nonexistent XDG_CONFIG_HOME=/nonexistent timeout 120 python3 "$f" "$ORACLE/rhash"; then
    passed=$((passed + 1))
  else
    echo "Failed: $f" >&2; failed=$((failed + 1))
  fi
done
[ "$nt" -gt 0 ] || { echo "no tests/test_template_*.py found" >&2; failed=$((failed + 1)); }

tmp=$(mktemp -d); lib=$(cd "$tmp" && "$ORACLE/test_static" 2>&1); rc=$?
printf '%s\n' "$lib"
if [ "$rc" -eq 0 ] && printf '%s\n' "$lib" | grep -q '^All sums are working properly!$'; then
  passed=$((passed + 1))
else
  failed=$((failed + 1))
fi

emit_ctrf rhash-tests "$passed" "$failed"
