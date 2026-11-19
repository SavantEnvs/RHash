#!/usr/bin/env bash
#
# mayhem/build.sh — build RHash's fuzz targets and its functional suite.
#
# Runs inside the commit image as `mayhem` in /mayhem (SRC). Three in-tree builds with upstream's own
# ./configure + Makefile, one after another (each starts from `make distclean`, so re-runs are
# idempotent); the products are copied to mayhem/out/ (gitignored via mayhem/.gitignore):
#   1. oracle: normal flags  -> out/oracle/rhash + out/oracle/test_static (used by mayhem/test.sh)
#   2. CLI under AFL++ (afl-clang-fast) + ASan/UBSan -> out/rhash (afl: true targets rhash-check,
#      rhash-template; the CLI parses hash files/templates in static functions and exit()s on
#      errors, so it is fuzzed as a whole program)
#   3. librhash with ASan/UBSan + SanCov -> librhash.a, linked into the libFuzzer harnesses in
#      mayhem/harnesses/ (+ a -standalone reproducer of each)
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT="$SRC/mayhem/out"
mkdir -p "$OUT/oracle"

$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$OUT/lsan_off.o"

COMMON_CONF=(--disable-gettext --disable-openssl --disable-lib-shared --enable-lib-static --enable-static=librhash)

clean_tree() { if [ -f config.mak ]; then make distclean >/dev/null 2>&1 || true; fi; }

# 1) Oracle build: upstream's normal flags (plus optional coverage flags).
clean_tree
./configure --cc="$CC" "${COMMON_CONF[@]}" ${COVERAGE_FLAGS:+--extra-cflags="$COVERAGE_FLAGS" --extra-ldflags="$COVERAGE_FLAGS"}
make -j"$MAYHEM_JOBS" rhash
make -j"$MAYHEM_JOBS" -C librhash test_static
cp -f rhash "$OUT/oracle/rhash"
cp -f librhash/test_static "$OUT/oracle/test_static"

# 2) CLI instrumented with AFL++ + sanitizers (asserts kept: --enable-debug drops -DNDEBUG).
# UBSan's -fsanitize=function is relaxed (only that check): librhash dispatches every algorithm
# through generic `void (*)(void*)` / `void (*)(void*, const void*, size_t)` pointers to functions
# declared with typed context pointers (rhash.c, algorithms.c), so it fires on every rhash_init()
# of every input. All other ASan/UBSan checks stay on and halting.
FUZZ_CFLAGS="$SANITIZER_FLAGS -fno-sanitize=function $DEBUG_FLAGS"
clean_tree
./configure --cc=afl-clang-fast --enable-debug "${COMMON_CONF[@]}" \
  --extra-cflags="$FUZZ_CFLAGS" --extra-ldflags="$SANITIZER_FLAGS $DEBUG_FLAGS $OUT/lsan_off.o"
make -j"$MAYHEM_JOBS" rhash
cp -f rhash "$OUT/rhash"

# 3) librhash with sanitizers + SanCov (fuzzer-no-link always, even with empty SANITIZER_FLAGS).
clean_tree
./configure --cc="$CC" --enable-debug "${COMMON_CONF[@]}" \
  --extra-cflags="$FUZZ_CFLAGS -fsanitize=fuzzer-no-link"
make -j"$MAYHEM_JOBS" -C librhash lib-static
cp -f librhash/librhash.a "$OUT/librhash-fuzz.a"

$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/standalone_main.o"
for h in fuzz_hash_update fuzz_import fuzz_torrent; do
  $CC $FUZZ_CFLAGS -I"$SRC/librhash" -c "$SRC/mayhem/harnesses/$h.c" -o "$OUT/$h.o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/$h.o" "$OUT/lsan_off.o" \
    "$OUT/librhash-fuzz.a" -o "$OUT/$h"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "$OUT/standalone_main.o" "$OUT/$h.o" "$OUT/lsan_off.o" \
    "$OUT/librhash-fuzz.a" -o "$OUT/$h-standalone"
done

# leave the tree unconfigured-equivalent for upstream's own make (objects are gitignored anyway)
clean_tree
ls -l "$OUT"
