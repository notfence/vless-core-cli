# vless-core-cli

Standalone C CLI client for:

- `VLESS + TCP + Reality (+ xtls-rprx-vision)`
- `VLESS + TCP + TLS (+ xtls-rprx-vision)`
- `VLESS + TCP` (no security)
- `VLESS + XHTTP + Reality`
- `VLESS + XHTTP + TLS`
- `VLESS + XHTTP` (no security)
- `VLESS + gRPC + Reality`
- `VLESS + gRPC + TLS`
- `VLESS + gRPC` (no security)
- `VLESS + WebSocket + TLS`
- `VLESS + WebSocket` (no security)
- `SOCKS5`

`fp=chrome/firefox/edge/random/randomized/qq`

Protocol semantics are aligned with `xray-core` for the supported transports and URI parameters.

For XHTTP, `mode=auto` follows xray's defaults: `packet-up` without security or with TLS, and `stream-one` with Reality.

## Platform Support

- Linux on x86-64 (`vless-core-linux-amd64`)
- iOS 6.x through iOS 10.x on all compatible 32-bit devices (`vless-core-darwin-armv7`)

The iOS binary is built for ARMv7 with iOS 6.0 as the minimum deployment target. 64-bit ARM devices are not supported.

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
./vless-core-linux-amd64 --uri '<vless://...|socks5://...>' --listen-port <port>
or
./vless-core-darwin-armv7 --uri '<vless://...|socks5://...>' --listen-port <port>
```

Show CLI help/parameters:

```bash
./vless-core-linux-amd64 --help
./vless-core-darwin-armv7 --help
```

Expected help output:

```text
Usage: vless-core-linux-amd64 --uri <vless://...|socks5://...> --listen-port <port>

Options:
  --uri <uri>              VLESS URI or SOCKS5 upstream URI
  --listen-port <port>     Local SOCKS5 listen port (127.0.0.1)
  --routing <rules>        Optional Proxy, Direct and Block rules
  --route-control-port <p> Direct-route controller port
  --route-control-socket <path> Direct-route controller Unix socket
  --xray-version <x.y.z>   Xray version reported by vless-core-cli
  -h, --help               Show help
  -v, --version            Show version
```

`vless-core-cli` reports Xray version `26.3.27` by default. Override it with
`--xray-version x.y.z` or the `XRAY_VER` environment variable.

## Routing

Routing is optional and is disabled by default. When enabled, ordered rules can send new connections through the selected proxy, connect directly, or block them. Rules can match domains, domain suffixes, IP/CIDR ranges, and ports.

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

OpenSSL armv7 is generated at:

- `third_party/openssl-ios6-armv7/lib/libssl.a`
- `third_party/openssl-ios6-armv7/lib/libcrypto.a`

If missing:

```bash
make openssl-ios6
```

The script downloads OpenSSL 3.5.7 and builds it locally. By default it applies the ignored private asm patch from `patches/openssl-ios6-armv7-asm.patch`; set `OPENSSL_IOS6_ASM_PATCH=/path/to/openssl-ios6-armv7-asm.patch` if the patch lives elsewhere. 

Public rebuilds can use:
```bash
OPENSSL_NO_ASM=1 make openssl-ios6
```

Then:

```bash
make ios
file ./vless-core-darwin-armv7
```

## Legacy curl on iOS 6

Old stock iOS 6 curl/OpenSSL may fail modern TLS. Build replacement curl (armv7 + OpenSSL 3.5.7 + zlib 1.3.1):

```bash
make zlib-ios6
make openssl-ios6
make curl-ios6
make curl-ios6-package
```

Archive output:

- `third_party/curl-ios6-with-ca.tar.gz`
