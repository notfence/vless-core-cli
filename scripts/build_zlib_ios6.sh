#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
THIRD_PARTY_DIR="${ROOT_DIR}/third_party"
ZLIB_VER="${ZLIB_VER:-1.3.1}"
ZLIB_TGZ="${THIRD_PARTY_DIR}/zlib-${ZLIB_VER}.tar.gz"
ZLIB_SRC_DIR="${THIRD_PARTY_DIR}/zlib-${ZLIB_VER}"
ZLIB_INSTALL_DIR="${ZLIB_INSTALL_DIR:-${THIRD_PARTY_DIR}/zlib-ios6-armv7}"
ZLIB_URL="${ZLIB_URL:-https://zlib.net/fossils/zlib-${ZLIB_VER}.tar.gz}"

IOS_TOOLCHAIN="${IOS_TOOLCHAIN:-${HOME}/toolchains/ios6}"
IOS_SDK="${IOS_SDK:-${IOS_TOOLCHAIN}/SDK/iPhoneOS6.1.sdk}"
IOS_ARCH="${IOS_ARCH:-armv7}"
IOS_MIN_VERSION="${IOS_MIN_VERSION:-6.0}"

require_file() {
  local path="$1"
  local hint="$2"
  if [[ ! -e "${path}" ]]; then
    echo "Missing required path: ${path}"
    echo "${hint}"
    exit 1
  fi
}

require_executable() {
  local path="$1"
  local hint="$2"
  if [[ ! -x "${path}" ]]; then
    echo "Missing required executable: ${path}"
    echo "${hint}"
    exit 1
  fi
}

prepend_ld_library_if_needed() {
  local runtime_lib="libBlocksRuntime.so"
  local candidate=""
  local found=""

  if [[ -n "${LD_LIBRARY_PATH:-}" ]]; then
    IFS=':' read -r -a _ld_paths <<<"${LD_LIBRARY_PATH}"
    for candidate in "${_ld_paths[@]}"; do
      if [[ -n "${candidate}" && -f "${candidate}/${runtime_lib}" ]]; then
        return 0
      fi
    done
  fi

  local candidates=(
    "${IOS_TOOLCHAIN}/lib"
    "${IOS_TOOLCHAIN}/lib64"
  )
  for candidate in "${candidates[@]}"; do
    if [[ -f "${candidate}/${runtime_lib}" ]]; then
      export LD_LIBRARY_PATH="${candidate}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
      return 0
    fi
  done

  found="$(find "${IOS_TOOLCHAIN}" -maxdepth 5 -type f -name "${runtime_lib}" -print -quit 2>/dev/null || true)"
  if [[ -n "${found}" ]]; then
    candidate="$(dirname "${found}")"
    export LD_LIBRARY_PATH="${candidate}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
    return 0
  fi

  echo "Missing required runtime lib: ${runtime_lib}"
  echo "Place it under ${IOS_TOOLCHAIN} or set LD_LIBRARY_PATH to its directory."
  exit 1
}

require_executable "${IOS_TOOLCHAIN}/bin/arm-apple-darwin11-clang" \
  "Set IOS_TOOLCHAIN=/path/to/ios6/toolchain"
require_executable "${IOS_TOOLCHAIN}/bin/arm-apple-darwin11-ar" \
  "Set IOS_TOOLCHAIN=/path/to/ios6/toolchain"
require_executable "${IOS_TOOLCHAIN}/bin/arm-apple-darwin11-ranlib" \
  "Set IOS_TOOLCHAIN=/path/to/ios6/toolchain"
require_file "${IOS_SDK}" "Set IOS_SDK=/path/to/iPhoneOS6.1.sdk"

require_executable "$(command -v make || true)" "Install make"
require_executable "$(command -v tar || true)" "Install tar"
if [[ ! -f "${ZLIB_TGZ}" ]]; then
  require_executable "$(command -v curl || true)" "Install curl for host downloads"
fi

prepend_ld_library_if_needed

mkdir -p "${THIRD_PARTY_DIR}"

if [[ ! -f "${ZLIB_TGZ}" ]]; then
  curl -fL -o "${ZLIB_TGZ}" "${ZLIB_URL}"
fi

rm -rf "${ZLIB_SRC_DIR}" "${ZLIB_INSTALL_DIR}"
tar -xf "${ZLIB_TGZ}" -C "${THIRD_PARTY_DIR}"

export PATH="${IOS_TOOLCHAIN}/bin:${PATH}"
export CC=arm-apple-darwin11-clang
export AR=arm-apple-darwin11-ar
export RANLIB=arm-apple-darwin11-ranlib
export CHOST=arm-apple-darwin11
export CFLAGS="-arch ${IOS_ARCH} -isysroot ${IOS_SDK} -miphoneos-version-min=${IOS_MIN_VERSION} -O2"
export LDFLAGS="-arch ${IOS_ARCH} -isysroot ${IOS_SDK} -miphoneos-version-min=${IOS_MIN_VERSION}"

pushd "${ZLIB_SRC_DIR}" >/dev/null
./configure --static --prefix="${ZLIB_INSTALL_DIR}"
make -j"$(nproc)"
make install
popd >/dev/null

echo "Built zlib for iOS ${IOS_ARCH} at ${ZLIB_INSTALL_DIR}"
