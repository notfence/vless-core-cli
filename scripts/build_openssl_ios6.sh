#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
THIRD_PARTY_DIR="${ROOT_DIR}/third_party"
OPENSSL_VER="${OPENSSL_VER:-3.5.7}"
OPENSSL_TGZ="${THIRD_PARTY_DIR}/openssl-${OPENSSL_VER}.tar.gz"
OPENSSL_SRC_DIR="${THIRD_PARTY_DIR}/openssl-${OPENSSL_VER}"
OPENSSL_INSTALL_DIR="${THIRD_PARTY_DIR}/openssl-ios6-armv7"
OPENSSL_PATCH_STATUS_FILE="${OPENSSL_INSTALL_DIR}/VLESS_OPENSSL_PATCH_STATUS"
OPENSSL_IOS6_ASM_PATCH="${OPENSSL_IOS6_ASM_PATCH:-${ROOT_DIR}/patches/openssl-ios6-armv7-asm.patch}"
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
if [[ "${OPENSSL_NO_ASM:-0}" != "1" ]]; then
  require_executable "$(command -v patch || true)" "Install patch"
  require_file "${OPENSSL_IOS6_ASM_PATCH}" \
    "OpenSSL iOS 6 asm rebuilds require the private patch. Set OPENSSL_IOS6_ASM_PATCH=/path/to/openssl-ios6-armv7-asm.patch, or build without asm: OPENSSL_NO_ASM=1 make openssl-ios6"
fi
if [[ ! -f "${OPENSSL_TGZ}" ]]; then
  require_executable "$(command -v curl || true)" "Install curl for host downloads"
fi

prepend_ld_library_if_needed

mkdir -p "${THIRD_PARTY_DIR}"

if [[ ! -f "${OPENSSL_TGZ}" ]]; then
  curl -fL -o "${OPENSSL_TGZ}" "https://www.openssl.org/source/openssl-${OPENSSL_VER}.tar.gz"
fi

rm -rf "${OPENSSL_SRC_DIR}" "${OPENSSL_INSTALL_DIR}"
tar -xf "${OPENSSL_TGZ}" -C "${THIRD_PARTY_DIR}"
if [[ "${OPENSSL_NO_ASM:-0}" != "1" ]]; then
  openssl_patch_status="patched"
  patch -d "${OPENSSL_SRC_DIR}" -p0 < "${OPENSSL_IOS6_ASM_PATCH}"
else
  openssl_patch_status="unpatched"
fi

IOS_CROSS_TOP="${THIRD_PARTY_DIR}/ios-cross-sdk"
rm -rf "${IOS_CROSS_TOP}"
mkdir -p "${IOS_CROSS_TOP}/SDKs"
ln -s "${IOS_SDK}" "${IOS_CROSS_TOP}/SDKs/$(basename "${IOS_SDK}")"

export PATH="${IOS_TOOLCHAIN}/bin:${PATH}"
export CC=arm-apple-darwin11-clang
export AR=arm-apple-darwin11-ar
export RANLIB=arm-apple-darwin11-ranlib
export CFLAGS="-arch armv7 -mfpu=neon -isysroot ${IOS_SDK} -miphoneos-version-min=6.0 -O2 -DNDEBUG -DBROKEN_CLANG_ATOMICS"
export LDFLAGS="${CFLAGS}"
export CROSS_TOP="${IOS_CROSS_TOP}"
export CROSS_SDK="$(basename "${IOS_SDK}")"

pushd "${OPENSSL_SRC_DIR}" >/dev/null
openssl_options=(
  ios-cross
  no-shared
  no-dso
  no-tests
  no-apps
  no-docs
  no-module
  no-async
  no-pinshared
  no-quic
  no-engine
  no-autoload-config
  no-comp
  no-cmp
  no-cms
  no-ct
  no-dgram
  no-dtls
  no-ec2m
  no-legacy
  no-ml-dsa
  no-slh-dsa
  no-multiblock
  no-nextprotoneg
  no-ocsp
  no-rfc3779
  no-srp
  no-srtp
  no-ts
  no-tls-deprecated-ec
  no-aria
  no-bf
  no-camellia
  no-cast
  no-idea
  no-md4
  no-mdc2
  no-rc2
  no-rc4
  no-rmd160
  no-seed
  no-sm2
  no-sm3
  no-sm4
  no-whirlpool
)
if [[ "${OPENSSL_NO_ASM:-0}" == "1" ]]; then
  openssl_options+=(no-asm)
fi

perl Configure "${openssl_options[@]}" \
  --prefix="${OPENSSL_INSTALL_DIR}" \
  --openssldir="${OPENSSL_INSTALL_DIR}/ssl"
make -j"$(nproc)" build_libs
make install_dev
cp "${OPENSSL_SRC_DIR}/LICENSE.txt" "${OPENSSL_INSTALL_DIR}/LICENSE.txt"
printf '%s\n' "${openssl_patch_status}" > "${OPENSSL_PATCH_STATUS_FILE}"
popd >/dev/null

echo "Built OpenSSL for iOS armv7 at ${OPENSSL_INSTALL_DIR}"
