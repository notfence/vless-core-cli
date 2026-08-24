#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
THIRD_PARTY_DIR="${ROOT_DIR}/third_party"
CURL_VER="${CURL_VER:-8.21.0}"
CURL_TAR="${THIRD_PARTY_DIR}/curl-${CURL_VER}.tar.xz"
CURL_SRC_DIR="${THIRD_PARTY_DIR}/curl-${CURL_VER}"
CURL_INSTALL_DIR="${THIRD_PARTY_DIR}/curl-ios6-armv7"

IOS_TOOLCHAIN="${IOS_TOOLCHAIN:-${HOME}/toolchains/ios6}"
IOS_SDK="${IOS_SDK:-${IOS_TOOLCHAIN}/SDK/iPhoneOS6.1.sdk}"
OPENSSL_PREFIX="${OPENSSL_PREFIX:-${THIRD_PARTY_DIR}/openssl-ios6-armv7}"
ZLIB_PREFIX="${ZLIB_PREFIX:-${THIRD_PARTY_DIR}/zlib-ios6-armv7}"

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
require_executable "${IOS_TOOLCHAIN}/bin/arm-apple-darwin11-otool" \
  "Set IOS_TOOLCHAIN=/path/to/ios6/toolchain"
require_file "${IOS_SDK}" "Set IOS_SDK=/path/to/iPhoneOS6.1.sdk"

require_executable "$(command -v make || true)" "Install make"
require_executable "$(command -v tar || true)" "Install tar"
if [[ ! -f "${CURL_TAR}" ]]; then
  require_executable "$(command -v curl || true)" "Install curl for host downloads"
fi

prepend_ld_library_if_needed

mkdir -p "${THIRD_PARTY_DIR}"

for openssl_lib in libssl.a libcrypto.a; do
  if [[ ! -f "${OPENSSL_PREFIX}/lib/${openssl_lib}" ]]; then
    echo "Missing ${OPENSSL_PREFIX}/lib/${openssl_lib}"
    echo "Run: make openssl-ios6"
    echo "If the private asm patch lives elsewhere, set OPENSSL_IOS6_ASM_PATCH=/path/to/openssl-ios6-armv7-asm.patch"
    exit 1
  fi
done

if [[ ! -f "${ZLIB_PREFIX}/lib/libz.a" ]]; then
  echo "Missing ${ZLIB_PREFIX}/lib/libz.a"
  echo "Run: make zlib-ios6"
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
export CPPFLAGS="-I${OPENSSL_PREFIX}/include -I${ZLIB_PREFIX}/include"
export CFLAGS="-arch armv7 -isysroot ${IOS_SDK} -miphoneos-version-min=6.0 -O2 -DNDEBUG"
export LDFLAGS="-arch armv7 -isysroot ${IOS_SDK} -miphoneos-version-min=6.0 -Wl,-pie -L${OPENSSL_PREFIX}/lib -L${ZLIB_PREFIX}/lib"

pushd "${CURL_SRC_DIR}" >/dev/null
./configure \
  --host=arm-apple-darwin11 \
  --prefix="${CURL_INSTALL_DIR}" \
  --with-openssl="${OPENSSL_PREFIX}" \
  --with-zlib="${ZLIB_PREFIX}" \
  --enable-static \
  --disable-shared \
  --disable-docs \
  --disable-manual \
  --disable-alt-svc \
  --disable-aws \
  --disable-bearer-auth \
  --disable-dateparse \
  --disable-dict \
  --disable-digest-auth \
  --disable-doh \
  --disable-ech \
  --disable-file \
  --disable-form-api \
  --disable-ftp \
  --disable-get-easy-options \
  --disable-gopher \
  --disable-headers-api \
  --disable-hsts \
  --disable-imap \
  --disable-ipfs \
  --disable-kerberos-auth \
  --disable-ldap \
  --disable-ldaps \
  --disable-libcurl-option \
  --disable-mime \
  --disable-mqtt \
  --disable-negotiate-auth \
  --disable-netrc \
  --disable-ntlm \
  --disable-openssl-auto-load-config \
  --disable-pop3 \
  --disable-progress-meter \
  --disable-proxy-http3 \
  --disable-rtsp \
  --disable-smb \
  --disable-smtp \
  --disable-socketpair \
  --disable-ssls-export \
  --disable-telnet \
  --disable-tftp \
  --disable-tls-srp \
  --disable-unix-sockets \
  --disable-websockets \
  --disable-httpsrr \
  --without-libidn2 \
  --without-brotli \
  --without-zstd \
  --without-nghttp2 \
  --without-libpsl \
  --without-ca-bundle \
  --without-ca-path
make -j"$(nproc)"
make install
popd >/dev/null

if ! "${IOS_TOOLCHAIN}/bin/arm-apple-darwin11-otool" -hv "${CURL_INSTALL_DIR}/bin/curl" | grep -qw PIE; then
  echo "Refusing non-PIE iOS curl binary: ${CURL_INSTALL_DIR}/bin/curl"
  exit 1
fi

echo "Built curl for iOS armv7 at ${CURL_INSTALL_DIR}/bin/curl"
