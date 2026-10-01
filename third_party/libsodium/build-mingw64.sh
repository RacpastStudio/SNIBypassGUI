#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: $0 <source-dir> <install-dir> <run-tests:0|1>" >&2
    exit 2
fi

readonly SOURCE_DIR="$(cygpath -u "$1")"
readonly INSTALL_DIR="$(cygpath -u "$2")"
readonly RUN_TESTS="$3"

if [[ "${RUN_TESTS}" != 0 && "${RUN_TESTS}" != 1 ]]; then
    echo "run-tests must be 0 or 1" >&2
    exit 2
fi

cd "${SOURCE_DIR}"
./configure \
    --host=x86_64-w64-mingw32 \
    --disable-shared \
    --enable-static \
    --prefix="${INSTALL_DIR}"

make -j"$(nproc)"
if [[ "${RUN_TESTS}" == 1 ]]; then
    make check
fi
make install

test -f "${INSTALL_DIR}/lib/libsodium.a"
grep -Fx '#define SODIUM_VERSION_STRING "1.0.22"' \
    "${INSTALL_DIR}/include/sodium/version.h" >/dev/null
