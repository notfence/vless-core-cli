#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
THIRD_PARTY_DIR="${ROOT_DIR}/third_party"
OPENSSL_TGZ="${THIRD_PARTY_DIR}/openssl-1.1.1w.tar.gz"
OPENSSL_SRC_DIR="${THIRD_PARTY_DIR}/openssl-1.1.1w"
OPENSSL_INSTALL_DIR="${THIRD_PARTY_DIR}/openssl-ios6-armv7"
IOS_TOOLCHAIN="${IOS_TOOLCHAIN:-${HOME}/toolchains/ios6}"
IOS_SDK="${IOS_SDK:-${IOS_TOOLCHAIN}/SDK/iPhoneOS6.1.sdk}"

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

require_executable "$(command -v perl || true)" "Install perl"
require_executable "$(command -v make || true)" "Install make"
require_executable "$(command -v tar || true)" "Install tar"
if [[ ! -f "${OPENSSL_TGZ}" ]]; then
  require_executable "$(command -v curl || true)" "Install curl for host downloads"
fi

prepend_ld_library_if_needed

mkdir -p "${THIRD_PARTY_DIR}"

if [[ ! -f "${OPENSSL_TGZ}" ]]; then
  curl -fL -o "${OPENSSL_TGZ}" "https://www.openssl.org/source/openssl-1.1.1w.tar.gz"
fi

if [[ -d "${OPENSSL_SRC_DIR}" ]]; then
  rm -rf "${OPENSSL_SRC_DIR}"
fi
tar -xf "${OPENSSL_TGZ}" -C "${THIRD_PARTY_DIR}"

export PATH="${IOS_TOOLCHAIN}/bin:${PATH}"
export CC=arm-apple-darwin11-clang
export AR=arm-apple-darwin11-ar
export RANLIB=arm-apple-darwin11-ranlib
export CFLAGS="-arch armv7 -isysroot ${IOS_SDK} -miphoneos-version-min=6.0"
export LDFLAGS="${CFLAGS}"

pushd "${OPENSSL_SRC_DIR}" >/dev/null
perl Configure ios-cross no-shared no-dso no-tests no-engine no-asm \
  --prefix="${OPENSSL_INSTALL_DIR}" \
  --openssldir="${OPENSSL_INSTALL_DIR}/ssl"
make -j"$(nproc)" build_libs
make install_sw
popd >/dev/null

echo "Built OpenSSL for iOS armv7 at ${OPENSSL_INSTALL_DIR}"
