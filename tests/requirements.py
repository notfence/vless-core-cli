import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys

XRAY_VERSION = "26.6.27"
XRAY_SHA256 = "8ef87ac07f95617e094b8e9302ea3e0c2d0edaa7045d57b455fdee28b3c9e41e"

def verify():
    compiler = os.environ.get("TEST_FUZZ_CC","clang")
    if not shutil.which(compiler):
        raise RuntimeError(f"Missing local fuzz compiler: {compiler}. Clang with libFuzzer, ASan and UBSan is required; make never installs dependencies.")
    prefix = Path(os.environ["TEST_OPENSSL_PREFIX"])
    required = [prefix / "include/openssl/evp.h", prefix / "lib/libssl.a", prefix / "lib/libcrypto.a", prefix / "bin/openssl"]
    for path in required:
        if not path.is_file():
            raise RuntimeError(f"Missing test OpenSSL dependency: {path}. Set TEST_OPENSSL_PREFIX to a prepared OpenSSL 3.5 prefix; make never installs dependencies.")
    version = subprocess.check_output([str(prefix / "bin/openssl"), "version"], text=True, timeout=5)
    if not version.startswith("OpenSSL 3.5."):
        raise RuntimeError(f"Test OpenSSL 3.5 required, actual: {version.strip()}")
    algorithms = subprocess.check_output([str(prefix / "bin/openssl"), "list", "-kem-algorithms"], text=True, timeout=5)
    if "ML-KEM-768" not in algorithms:
        raise RuntimeError("Test OpenSSL does not provide ML-KEM-768")
    xray = Path(os.environ["TEST_XRAY_BIN"])
    if not xray.is_file() or not os.access(xray, os.X_OK):
        raise RuntimeError(f"Missing test Xray: {xray}. Set TEST_XRAY_BIN to the prepared Xray {XRAY_VERSION}; no automatic download.")
    if hashlib.sha256(xray.read_bytes()).hexdigest() != XRAY_SHA256:
        raise RuntimeError(f"Test Xray checksum mismatch: {xray}")
    actual = subprocess.check_output([str(xray), "version"], text=True, timeout=5)
    if not actual.startswith(f"Xray {XRAY_VERSION} "):
        raise RuntimeError(f"Test Xray {XRAY_VERSION} required, actual: {actual.strip()}")

if __name__ == "__main__":
    try:
        if len(sys.argv) > 1 and sys.argv[1] == "settings":
            path = Path(sys.argv[2]); path.parent.mkdir(parents=True,exist_ok=True)
            content = "\n".join(sys.argv[3:])+"\n"
            if not path.exists() or path.read_text() != content:
                temporary = path.with_suffix(".tmp"); temporary.write_text(content); temporary.replace(path)
        else:
            verify()
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit(f"FAIL requirements: {error}")
