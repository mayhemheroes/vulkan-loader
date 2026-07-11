#!/usr/bin/env bash
#
# vulkan-loader/mayhem/build.sh — build KhronosGroup/Vulkan-Loader's OSS-Fuzz manifest-JSON
# harnesses as sanitized libFuzzer targets (+ standalone reproducers), and a small golden
# oracle over the same parse path for mayhem/test.sh.
#
# Fuzzed surface = the Vulkan loader's ICD / layer / loader-settings MANIFEST JSON parser:
#   json_load_fuzzer — feeds the raw input to loader_get_json() (loader/loader_json.c), which
#                       reads the file and parses it with the loader's vendored cJSON
#                       (loader/cJSON.c), then loader_cJSON_Print()s and frees it. Pure
#                       parse/serialize round-trip over an attacker-controlled manifest.
#   settings_fuzzer  — writes the input as $HOME/.local/share/vulkan/loader_settings.d/
#                       vk_loader_settings.json and drives the loader-settings parser
#                       (update_global_loader_settings / get_settings_layers in loader/settings.c),
#                       which parses that manifest via the same cJSON path.
# Inputs ARE JSON manifest text (not a binary struct encoding).
#
# Build contract comes from the org base ENV (CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/SRC/
# STANDALONE_FUZZ_MAIN). We compile the loader ITSELF with $SANITIZER_FLAGS (+fuzzer-no-link for
# coverage) so the parser code — not just the harness — is instrumented. The full loader is built
# the way OSS-Fuzz does (CMake; UPDATE_DEPS=ON fetches Vulkan-Headers), with the WSI backends
# (X11/xcb/wayland) turned OFF since the fuzzed manifest path never touches them — this keeps the
# apt footprint to the base image alone.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS: explicit DWARF-3 so Mayhem triage can read symbols (clang-19 defaults to DWARF-5).
# Must come AFTER $SANITIZER_FLAGS in compile lines so -gdwarf-3 wins over any -g in SANITIZER_FLAGS.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS SRC

cd "$SRC"

HARNESS_DIR="$SRC/mayhem/harnesses"
BUILD="$SRC/mayhem-build"

# The OSS-Fuzz harnesses call loader-internal functions (loader_get_json, update_global_loader_settings,
# …) WITHOUT including their declaring headers — they rely on the old implicit-declaration behavior.
# clang 19 makes that a hard error, so relax it for the harness translation units only. (This is the
# single, benign compat relax the integration is allowed; the loader library itself is built clean.)
RELAX_IMPLICIT="-Wno-error=implicit-function-declaration -Wno-implicit-function-declaration"

# ── 1) Build the Vulkan loader as a sanitized static lib (the fuzzed parser is instrumented) ───────
# -fsanitize=fuzzer-no-link gives the loader code SanitizerCoverage without pulling the libFuzzer
# main(); FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION matches the OSS-Fuzz build of the loader.
LOADER_C_FLAGS="-fsanitize=fuzzer-no-link $SANITIZER_FLAGS $DEBUG_FLAGS -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"

# Air-gapped re-run (§6.5): UPDATE_DEPS=ON fetches Vulkan-Headers from the network on the first run.
# On subsequent re-runs (PATCH tier / offline), the build tree and static lib already exist in the
# image — skip cmake/ninja entirely and jump straight to recompiling the harnesses against the
# cached libvulkan.a and headers.
LIBVULKAN="$BUILD/libvulkan.a"
if [ -f "$LIBVULKAN" ]; then
  echo "re-run: reusing cached $LIBVULKAN (offline-safe)"
else
  # First run — fetch Vulkan-Headers via UPDATE_DEPS (requires network), build the loader.
  cmake -S "$SRC" -B "$BUILD" -G Ninja \
    -DUPDATE_DEPS=ON \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_WSI_XCB_SUPPORT=OFF \
    -DBUILD_WSI_XLIB_SUPPORT=OFF \
    -DBUILD_WSI_WAYLAND_SUPPORT=OFF \
    -DBUILD_TESTS=OFF \
    -DCMAKE_C_FLAGS="$LOADER_C_FLAGS"
  ninja -C "$BUILD" -j"$MAYHEM_JOBS" vulkan

  # Archive the loader objects into a static lib (matches OSS-Fuzz's `ar rcs $OUT/libvulkan.a ...`).
  rm -f "$LIBVULKAN"
  ar rcs "$LIBVULKAN" "$BUILD"/loader/CMakeFiles/vulkan.dir/*.o
fi

# Vulkan-Headers were fetched by UPDATE_DEPS; locate the include dir.
VK_HEADERS_INC="$(dirname "$(find "$SRC/external" -path '*Vulkan-Headers/include/vulkan/vulkan_core.h' | head -1)")/.."
INC="-I$SRC/loader -I$SRC/loader/generated -I$VK_HEADERS_INC -I$HARNESS_DIR"

# ── 2) Build each harness twice: libFuzzer (-> /mayhem/<name>) + standalone reproducer ─────────────
for harness in json_load_fuzzer settings_fuzzer instance_create_fuzzer instance_enumerate_fuzzer instance_enumerate_fuzzer_split_input instance_create_advanced_fuzzer; do
  # Determine any extra flags and source file specific to each harness.
  # instance_enumerate_fuzzer_split_input is the same source as instance_enumerate_fuzzer
  # compiled with -DSPLIT_INPUT (matching the OSS-Fuzz build).
  EXTRA_FLAGS=""
  SRC_FILE="$HARNESS_DIR/$harness.c"
  case "$harness" in
    instance_enumerate_fuzzer_split_input)
      EXTRA_FLAGS="-DSPLIT_INPUT"
      SRC_FILE="$HARNESS_DIR/instance_enumerate_fuzzer.c"
      ;;
    instance_create_advanced_fuzzer) EXTRA_FLAGS="-DENABLE_FILE_CALLBACK" ;;
  esac

  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link $RELAX_IMPLICIT $INC $EXTRA_FLAGS \
      -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION \
      -c "$SRC_FILE" -o "$BUILD/$harness.o"

  # libFuzzer target -> /mayhem/<name>
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$BUILD/$harness.o" \
      -o "/mayhem/$harness" -lpthread "$LIBVULKAN"

  # standalone reproducer (run-once, no libFuzzer runtime) -> /mayhem/<name>-standalone.
  # Link with $CC (C linkage): the harness object is C-compiled, so its LLVMFuzzerTestOneInput is
  # an unmangled C symbol. The StandaloneFuzzTargetMain.c driver is compiled as C here too so the
  # extern declaration matches (compiling it via $CXX would give the call C++ linkage and fail to
  # resolve the C symbol).
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -x c "$STANDALONE_FUZZ_MAIN" -x none "$BUILD/$harness.o" \
      -o "/mayhem/$harness-standalone" -lpthread "$LIBVULKAN"

  echo "built $harness (+ standalone)"
done

# ── 3) Build the golden manifest-parse oracle for mayhem/test.sh (links the SAME loader lib) ───────
# Compiled clean (no fuzzer instrumentation) so test.sh is an honest functional/PATCH oracle.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $RELAX_IMPLICIT $INC \
    -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION \
    "$SRC/mayhem/oracle/manifest_oracle.c" -o "$BUILD/manifest_oracle" \
    -lpthread "$LIBVULKAN"
echo "built manifest_oracle"

echo "build.sh complete:"
ls -la /mayhem/json_load_fuzzer /mayhem/settings_fuzzer \
       /mayhem/instance_create_fuzzer /mayhem/instance_enumerate_fuzzer \
       /mayhem/instance_enumerate_fuzzer_split_input /mayhem/instance_create_advanced_fuzzer \
       /mayhem/json_load_fuzzer-standalone /mayhem/settings_fuzzer-standalone \
       /mayhem/instance_create_fuzzer-standalone /mayhem/instance_enumerate_fuzzer-standalone \
       /mayhem/instance_enumerate_fuzzer_split_input-standalone \
       /mayhem/instance_create_advanced_fuzzer-standalone \
       "$BUILD/manifest_oracle" 2>&1 || true
