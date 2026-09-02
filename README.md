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
- iOS 6.x through iOS 10.x via ARMv7 (`vless-core-darwin-armv7`)
- iOS 11.x through iOS 14.x via ARM64 (`vless-core-darwin-arm64`)

The two iOS outputs are separate thin binaries. The app package deliberately
keeps the ARMv7 runtime on iOS 6–10, including ARM64 devices that still support
32-bit applications, and selects ARM64 only on iOS 11 or newer.

## Binaries

Build outputs:

- `vless-core-linux-amd64`
- `vless-core-darwin-armv7`
- `vless-core-darwin-arm64`

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
make ios-arm64
```

## Run

```bash
./vless-core-linux-amd64 --uri '<vless://...|socks5://...>' --listen-port <port>
or
./vless-core-darwin-armv7 --uri '<vless://...|socks5://...>' --listen-port <port>
or
./vless-core-darwin-arm64 --uri '<vless://...|socks5://...>' --listen-port <port>
```

Show CLI help/parameters:

```bash
./vless-core-linux-amd64 --help
./vless-core-darwin-armv7 --help
./vless-core-darwin-arm64 --help
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

## TLS verification modes

TLS certificate verification is strict by default for TCP, WebSocket, XHTTP, and gRPC transports. It can be changed explicitly via:

```bash
VLESS_TLS_MODE=strict|insecure|tofu
```

- `strict` (default): only verified TLS, no fallback.
- `insecure`: always insecure TLS.
- `tofu`: Trust-On-First-Use pinning (first cert is saved, next connections must match SHA-256 pin).

The legacy `VLESS_XHTTP_TLS_MODE` name remains accepted. `auto` is treated as `strict` and never downgrades certificate verification.

TOFU pin file path:

- `VLESS_XHTTP_PIN_FILE=/absolute/private/path/to/pins.txt` (override)
- iOS default: `/private/var/mobile/Library/Preferences/vless-core/xhttp-pins.txt`
- Linux default: `~/.local/state/vless-core/tls-pins.txt`

The parent directory must not be writable by another user. Pin files are protected with mode `0600`, symlinks are rejected, and updates use locking plus atomic replacement.

## iOS toolchain notes

Default toolchain and SDK paths in `Makefile`:

- `../toolchains/ios6`
- ARMv7 SDK: `../toolchains/ios6/SDK/iPhoneOS6.1.sdk`
- ARM64 SDK: `../toolchains/sdks/iPhoneOS11.4.sdk`

Override if needed:

```bash
make ios IOS_TOOLCHAIN=/path/to/ios6/toolchain
make ios-arm64 IOS_TOOLCHAIN=/path/to/ios6/toolchain IOS_ARM64_SDK=/path/to/iPhoneOS11.4.sdk
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

Build the native iOS 11+ dependencies and CLI separately:

```bash
make openssl-ios-arm64
make zlib-ios-arm64
make curl-ios-arm64
make ios-arm64
file ./vless-core-darwin-arm64
```

The private ARMv7 OpenSSL compatibility patch is not applied to the ARM64
build; its patch status is therefore reported as `unpatched`.

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

The archive includes the combined `THIRD_PARTY_LICENSES.txt` document.

For public CLI releases, package the standalone binaries together with their
notices instead of publishing the bare iOS executable:

```bash
make release-packages
```

Outputs are written to `build/release/`, including separate ARMv7 and ARM64
iOS archives. No universal iOS executable is produced, so iOS 6–10 cannot
accidentally select the iOS 11+ ARM64 slice.

## Third-party software

Third-party licenses apply only to the components identified in
[`THIRD_PARTY_LICENSES.txt`](THIRD_PARTY_LICENSES.txt), not to vless-core-cli
as a whole. Release and optional curl archives each contain this single
combined notices and licenses document. The iOS release binary statically
includes OpenSSL; curl, zlib, and `cacert.pem` belong only to the optional
`curl-ios6-with-ca` archive.
