#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${TLS_DECODER_OUTPUT_DIR:-${ROOT_DIR}/third_party}"
CACHE_DIR="${TLS_DECODER_CACHE_DIR:-${ROOT_DIR}/third_party}"
BROTLI_NAME="brotli-1.2.1"
ZSTD_NAME="zstd-1.5.7"
BROTLI_TREE="f7e81123384b78121b9a7a76fa1f0b1b0ea02d8a9ba44ce3335c175f2f82a8a6"
ZSTD_TREE="9d63fd21d2a3afd6f756b61c378a49bafc4019711366337cc4b22b2dbf3676ac"

fail() {
  echo "TLS decoders: $*" >&2
  exit 1
}

verify_tree() {
  local directory="$1" expected="$2" digest
  [[ -d "${directory}" && ! -L "${directory}" ]] || fail "Missing prepared sources: ${directory}. Run make tls-decoders."
  [[ -z "$(find "${directory}" -type l -print -quit)" ]] || fail "Symlink in prepared sources: ${directory}"
  digest="$(cd "${directory}" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum)"
  [[ "${digest%% *}" == "${expected}" ]] || fail "Modified sources: ${directory}. Move them aside before running make tls-decoders."
}

verify_sources() {
  verify_tree "$1/${BROTLI_NAME}" "${BROTLI_TREE}"
  verify_tree "$1/${ZSTD_NAME}" "${ZSTD_TREE}"
}

if [[ "${1:-}" == "--check" && $# == 1 ]]; then
  verify_sources "${ROOT_DIR}/third_party"
  exit 0
fi
[[ $# == 0 ]] || fail "Usage: bash scripts/prepare_tls_decoders.sh [--check]"

if [[ -e "${OUTPUT_DIR}/${BROTLI_NAME}" || -L "${OUTPUT_DIR}/${BROTLI_NAME}" ]]; then
  verify_tree "${OUTPUT_DIR}/${BROTLI_NAME}" "${BROTLI_TREE}"
fi
if [[ -e "${OUTPUT_DIR}/${ZSTD_NAME}" || -L "${OUTPUT_DIR}/${ZSTD_NAME}" ]]; then
  verify_tree "${OUTPUT_DIR}/${ZSTD_NAME}" "${ZSTD_TREE}"
fi
if [[ -d "${OUTPUT_DIR}/${BROTLI_NAME}" && -d "${OUTPUT_DIR}/${ZSTD_NAME}" ]]; then
  echo "TLS decoders are already prepared."
  exit 0
fi

mkdir -p "${OUTPUT_DIR}" "${CACHE_DIR}"
decoder_stage="$(mktemp -d "${OUTPUT_DIR}/tls-decoders.XXXXXX")"
trap 'rm -rf -- "${decoder_stage}"' EXIT

fetch_archive() {
  local name="$1" url="$2" expected="$3" archive="${CACHE_DIR}/$1" digest
  [[ ! -L "${archive}" ]] || fail "Symlink instead of archive: ${archive}"
  if [[ ! -e "${archive}" ]]; then
    [[ "${TLS_DECODER_OFFLINE:-0}" == 0 ]] || fail "Missing cached archive: ${archive}"
    curl -fL --proto '=https' --proto-redir '=https' --connect-timeout 20 --max-time 120 \
      --max-filesize 33554432 -o "${decoder_stage}/${name}" "${url}"
    digest="$(sha256sum -- "${decoder_stage}/${name}")"
    [[ "${digest%% *}" == "${expected}" ]] || fail "Archive checksum mismatch: ${name}"
    mv -- "${decoder_stage}/${name}" "${archive}"
  fi
  [[ -f "${archive}" ]] || fail "Not an archive file: ${archive}"
  [[ "$(stat -c %s -- "${archive}")" -le 33554432 ]] || fail "Archive exceeds size limit: ${name}"
  digest="$(sha256sum -- "${archive}")"
  [[ "${digest%% *}" == "${expected}" ]] || fail "Archive checksum mismatch: ${name}"
}

fetch_archive "brotli-v1.2.1.tar.gz" "https://github.com/google/brotli/archive/refs/tags/v1.2.1.tar.gz" \
  "98d35d11a78dc453aebb7d10c3748f3f73ff78c8267c0dc697b8631f67bf7e8f"
fetch_archive "zstd-v1.5.7.tar.gz" "https://github.com/facebook/zstd/archive/refs/tags/v1.5.7.tar.gz" \
  "37d7284556b20954e56e1ca85b80226768902e2edabd3b649e9e72c0c9012ee3"

tar -xzf "${CACHE_DIR}/brotli-v1.2.1.tar.gz" -C "${decoder_stage}" --no-same-owner --no-same-permissions --wildcards \
  "${BROTLI_NAME}/LICENSE" "${BROTLI_NAME}/c/common/*.c" "${BROTLI_NAME}/c/common/*.h" \
  "${BROTLI_NAME}/c/dec/*.c" "${BROTLI_NAME}/c/dec/*.h" \
  "${BROTLI_NAME}/c/include/brotli/"{decode.h,port.h,shared_dictionary.h,types.h}
tar -xzf "${CACHE_DIR}/zstd-v1.5.7.tar.gz" -C "${decoder_stage}" --no-same-owner --no-same-permissions --wildcards \
  --exclude="${ZSTD_NAME}/lib/common/pool.h" --exclude="${ZSTD_NAME}/lib/common/threading.h" \
  "${ZSTD_NAME}/LICENSE" "${ZSTD_NAME}/COPYING" "${ZSTD_NAME}/lib/"{zstd.h,zstd_errors.h} \
  "${ZSTD_NAME}/lib/common/"{debug.c,entropy_common.c,error_private.c,fse_decompress.c,xxhash.c,zstd_common.c} \
  "${ZSTD_NAME}/lib/common/*.h" "${ZSTD_NAME}/lib/decompress/*.c" "${ZSTD_NAME}/lib/decompress/*.h"
patch --batch --fuzz=0 -p1 -d "${decoder_stage}/${ZSTD_NAME}" < "${ROOT_DIR}/patches/zstd-decoder-namespace.patch"
verify_sources "${decoder_stage}"

for name in "${BROTLI_NAME}" "${ZSTD_NAME}"; do
  if [[ ! -e "${OUTPUT_DIR}/${name}" && ! -L "${OUTPUT_DIR}/${name}" ]]; then
    mv -- "${decoder_stage}/${name}" "${OUTPUT_DIR}/${name}"
  fi
done
verify_sources "${OUTPUT_DIR}"
echo "Prepared Brotli 1.2.1 and Zstandard 1.5.7 decoders."
