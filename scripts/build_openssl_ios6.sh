#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
THIRD_PARTY_DIR="${ROOT_DIR}/third_party"
OPENSSL_TGZ="${THIRD_PARTY_DIR}/openssl-1.1.1w.tar.gz"
OPENSSL_SRC_DIR="${THIRD_PARTY_DIR}/openssl-1.1.1w"
OPENSSL_INSTALL_DIR="${THIRD_PARTY_DIR}/openssl-ios6-armv7"
IOS_TOOLCHAIN="${IOS_TOOLCHAIN:-${HOME}/toolchains/ios6}"
IOS_SDK="${IOS_SDK:-${IOS_TOOLCHAIN}/SDK/iPhoneOS6.1.sdk}"

if [[ ! -x "${IOS_TOOLCHAIN}/bin/arm-apple-darwin11-clang" ]]; then
  echo "Missing iOS toolchain at ${IOS_TOOLCHAIN}"
  echo "Set IOS_TOOLCHAIN=/path/to/ios6/toolchain"
  exit 1
fi

if [[ ! -d "${IOS_SDK}" ]]; then
  echo "Missing iOS SDK at ${IOS_SDK}"
  echo "Set IOS_SDK=/path/to/iPhoneOS6.1.sdk"
  exit 1
fi

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
