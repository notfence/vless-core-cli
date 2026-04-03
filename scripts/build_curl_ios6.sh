#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
THIRD_PARTY_DIR="${ROOT_DIR}/third_party"
CURL_VER="${CURL_VER:-7.88.1}"
CURL_TAR="${THIRD_PARTY_DIR}/curl-${CURL_VER}.tar.xz"
CURL_SRC_DIR="${THIRD_PARTY_DIR}/curl-${CURL_VER}"
CURL_INSTALL_DIR="${THIRD_PARTY_DIR}/curl-ios6-armv7"

IOS_TOOLCHAIN="${IOS_TOOLCHAIN:-${HOME}/toolchains/ios6}"
IOS_SDK="${IOS_SDK:-${IOS_TOOLCHAIN}/SDK/iPhoneOS6.1.sdk}"
OPENSSL_PREFIX="${OPENSSL_PREFIX:-${THIRD_PARTY_DIR}/openssl-ios6-armv7}"

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
require_executable "${IOS_TOOLCHAIN}/bin/arm-apple-darwin11-strip" \
  "Set IOS_TOOLCHAIN=/path/to/ios6/toolchain"
require_file "${IOS_SDK}" "Set IOS_SDK=/path/to/iPhoneOS6.1.sdk"

require_executable "$(command -v make || true)" "Install make"
require_executable "$(command -v tar || true)" "Install tar"
if [[ ! -f "${CURL_TAR}" ]]; then
  require_executable "$(command -v curl || true)" "Install curl for host downloads"
fi

prepend_ld_library_if_needed

mkdir -p "${THIRD_PARTY_DIR}"

if [[ ! -f "${OPENSSL_PREFIX}/lib/libcrypto.a" ]]; then
  echo "Missing ${OPENSSL_PREFIX}/lib/libcrypto.a"
  echo "Run: make openssl-ios6"
  exit 1
fi

if [[ ! -f "${CURL_TAR}" ]]; then
  curl -fL -o "${CURL_TAR}" "https://curl.se/download/curl-${CURL_VER}.tar.xz"
fi

rm -rf "${CURL_SRC_DIR}" "${CURL_INSTALL_DIR}"
tar -xf "${CURL_TAR}" -C "${THIRD_PARTY_DIR}"

export PATH="${IOS_TOOLCHAIN}/bin:${PATH}"
export CC=arm-apple-darwin11-clang
export AR=arm-apple-darwin11-ar
export RANLIB=arm-apple-darwin11-ranlib
export STRIP=arm-apple-darwin11-strip
export CPPFLAGS="-I${OPENSSL_PREFIX}/include"
export CFLAGS="-arch armv7 -isysroot ${IOS_SDK} -miphoneos-version-min=6.0 -O2"
export LDFLAGS="-arch armv7 -isysroot ${IOS_SDK} -miphoneos-version-min=6.0 -L${OPENSSL_PREFIX}/lib"

pushd "${CURL_SRC_DIR}" >/dev/null
./configure \
  --host=arm-apple-darwin11 \
  --prefix="${CURL_INSTALL_DIR}" \
  --with-openssl="${OPENSSL_PREFIX}" \
  --enable-static \
  --disable-shared \
  --disable-ldap \
  --disable-ldaps \
  --without-libidn2 \
  --without-brotli \
  --without-zstd \
  --without-nghttp2 \
  --without-libpsl \
  --without-librtmp \
  --without-ca-bundle \
  --without-ca-path
make -j"$(nproc)"
make install
popd >/dev/null

echo "Built curl for iOS armv7 at ${CURL_INSTALL_DIR}/bin/curl"
