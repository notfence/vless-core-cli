# vless-core-cli

Standalone C CLI client for:

- `VLESS + TCP + Reality + xtls-rprx-vision`
- `VLESS + TCP + TLS + xtls-rprx-vision`
- `VLESS + TLS + XHTTP (mode=packet-up)`
- `VLESS + Reality + XHTTP (mode=stream-one)`

`fp=chrome/firefox/random/randomized/qq`

Protocol semantics are aligned with `xray-core` for the supported transports and URI parameters.

## Tested Device/OS

Tested only on **iOS 6.1.3** on **iPhone 4s**.
Compatibility with other iOS versions/devices is not guaranteed.

## Binaries

Build outputs:

- `vless-core-linux-amd64`
- `vless-core-darwin-armv7`

## Build

```bash
cd vless-core-cli
make clean
make all
```

Build only Linux (amd64):

```bash
make linux
```

Build only iOS:

```bash
make ios
```

## Run

```bash
./vless-core-linux-amd64 --uri '<vless://...>' --listen-port <port>
or
./vless-core-darwin-armv7 --uri '<vless://...>' --listen-port <port>
```

Show CLI help/parameters:

```bash
./vless-core-linux-amd64 --help
./vless-core-darwin-armv7 --help
```

Expected help output:

```text
Usage: vless-core-linux-amd64 --uri <vless://...> --listen-port <port>

Options:
  --uri <vless://...>      VLESS URI (Reality/Vision, TLS/Vision, TLS/XHTTP, or Reality/XHTTP)
  --listen-port <port>     Local SOCKS5 listen port (127.0.0.1)
  -h, --help               Show help
  -v, --version            Show version
```

## XHTTP TLS modes

For `type=xhttp` transport you can control TLS behavior via env:

```bash
VLESS_XHTTP_TLS_MODE=auto|strict|insecure|tofu
```

- `auto` (default): try TLS verify, and if cert-verify fails fallback to insecure TLS with TOFU pin check/store.
- `strict`: only verified TLS, no fallback.
- `insecure`: always insecure TLS.
- `tofu`: Trust-On-First-Use pinning (first cert is saved, next connections must match SHA-256 pin).

`type=tcp&security=tls` uses the same pin storage and falls back to TOFU when strict cert verification fails.

TOFU pin file path:

- `VLESS_XHTTP_PIN_FILE=/path/to/pins.txt` (override)
- default search/write paths:
  - `/var/mobile/Library/Preferences/vless-core/xhttp-pins.txt`
  - `/tmp/vless-core-xhttp-pins.txt`

## iOS toolchain notes

Default toolchain path in `Makefile`:

- `${HOME}/toolchains/ios6`

Override if needed:

```bash
make ios IOS_TOOLCHAIN=/path/to/ios6/toolchain
```

OpenSSL armv7 must exist at:

- `third_party/openssl-ios6-armv7/lib/libcrypto.a`

If missing:

```bash
make openssl-ios6
```

Then:

```bash
make ios
file ./vless-core-darwin-armv7
```

## Legacy curl on iOS 6

Old stock iOS 6 curl/OpenSSL may fail modern TLS. Build replacement curl (armv7 + OpenSSL 1.1.1w):

```bash
make curl-ios6
make curl-ios6-package
```

Archive output:

- `third_party/curl-ios6-with-ca.tar.gz`
