# vless-core-cli

Standalone C CLI client with a local SOCKS5 listener for TCP applications.

## Supported configurations

The transport matrix below applies to VLESS, Trojan, VMess AEAD, and Shadowsocks:

| Transport | No external security | TLS | REALITY |
|---|---|---|---|
| TCP / raw | ✅ | ✅ | ✅ |
| WebSocket | ✅ | ✅ | ❌ |
| gRPC gun/multi | ✅ | ✅ | ✅ |
| XHTTP | ✅ | ✅ | ✅ |
| HTTPUpgrade | ✅ | ✅ | ❌ |

> [!NOTE]
> WebSocket and HTTPUpgrade combining with REALITY is not supported by xray-core itself

SOCKS5 is a separate upstream protocol with optional username/password
authentication. It does not use the transport matrix above.

### Protocols and encryption

- **VLESS:** `encryption=none` or supported VLESS Encryption settings, with
  applicable `xtls-rprx-vision` flows. Encryption and Vision are VLESS-only.
- **Trojan:** the whole userinfo is the password. TLS is the default outer
  security. Explicit `security=none` exposes the authentication credential
  and produces a warning.
- **VMess AEAD:** `alterId=0` only. Body modes are `auto`, `aes-128-gcm`,
  `chacha20-poly1305`, `none`, and `zero`. `scy` is an alias for
  `encryption`. `auto` selects AES-GCM or ChaCha20-Poly1305 for the
  platform, never `none` or `zero`. Legacy authentication and AES-CFB are
  not supported.
- **Shadowsocks AEAD:** `aes-128-gcm`, `aes-256-gcm`,
  `chacha20-poly1305`, and `xchacha20-poly1305`. The aliases
  `chacha20-ietf-poly1305` and `xchacha20-ietf-poly1305` are accepted.
- **Shadowsocks 2022:** `2022-blake3-aes-128-gcm`,
  `2022-blake3-aes-256-gcm`, and `2022-blake3-chacha20-poly1305`.
  AES methods support SIP023 identity key chains. The ChaCha20 method uses
  a single key.

`security=none|tls|reality` describes the outer transport protection.
VMess `encryption` selects its body mode. For Shadowsocks the method in
userinfo selects the cipher, and `encryption=none` does not disable it.
VLESS Encryption is independent of outer TLS/REALITY.
VMess `none` retains framing without body encryption, while `zero` sends the
body without that framing. Their protocol headers still use AEAD.

### Transports

- TCP accepts the `tcp` and `raw` names.
- WebSocket supports Host, headers, early data, and heartbeat.
- gRPC supports `gun` and `multi` with the existing HTTP/2 pool.
- XHTTP supports `auto`, `packet-up`, `stream-one`, and `stream-up`,
  XMUX, and separate download settings/IP pins. `auto` selects `packet-up`
  with none/TLS. With REALITY, it selects `stream-one`, or `stream-up` when
  a separate download channel is configured. XMUX is used only when its
  settings are present.
- HTTPUpgrade supports `host`, `path`, `headers`, `ed`, and
  `maxEarlyData`. It uses HTTP/1.1.
  With TLS, an explicit ALPN list must include `http/1.1`. REALITY and
  WebSocket heartbeat are not supported. Vision requires VLESS Encryption
  when using HTTPUpgrade.

Supported `fp` values are `chrome`, `firefox`, `edge`, `random`,
`randomized`, and `qq`. There are no `safari` or `ios` fingerprints.

## Platform Support

- Linux on x86-64 (`vless-core-linux-amd64`)
- iOS 5.0 through iOS 10.x via ARMv7 (`vless-core-darwin-armv7`)
- iOS 11.x through iOS 14.x via ARM64 (`vless-core-darwin-arm64`)

The two iOS outputs are separate thin binaries. The app package deliberately
keeps the ARMv7 runtime on iOS 5–10, including ARM64 devices that still support
32-bit applications, and selects ARM64 only on iOS 11 or newer.

## Binaries

Build outputs:

- `vless-core-linux-amd64`
- `vless-core-darwin-armv7`
- `vless-core-darwin-arm64`

## Build

Linux builds need a C compiler, Make, Python 3, and OpenSSL development files.
Build preflight also requires Clang with sanitizers/libFuzzer, a separate test
OpenSSL 3.5 installation, and unchanged Xray 26.6.27. Tests run locally on Linux.
Set `TEST_OPENSSL_PREFIX` and `TEST_XRAY_BIN` if their default paths do not apply.

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
./vless-core-linux-amd64 --uri '<vless://...|trojan://...|vmess://...|ss://...|socks5://...>' --listen-port <port>
or
./vless-core-darwin-armv7 --uri '<vless://...|trojan://...|vmess://...|ss://...|socks5://...>' --listen-port <port>
or
./vless-core-darwin-arm64 --uri '<vless://...|trojan://...|vmess://...|ss://...|socks5://...>' --listen-port <port>
```

To keep credentials out of process arguments, pass a private file containing one
URI without a trailing newline. The reader waits for EOF:

```bash
chmod 600 /path/to/private-uri.txt
./vless-core-linux-amd64 --uri-fd 3 --listen-port 1080 3</path/to/private-uri.txt
./vless-core-linux-amd64 --inspect-config --uri-fd 3 3</path/to/private-uri.txt
```

Inspect validates the configuration and reports server endpoints without DNS,
connections, or TOFU writes. `--connection-fd` accepts the app's URI/IP payload.
The connection budget is not an idle timeout for established connections.

Show CLI help/parameters:

```bash
./vless-core-linux-amd64 --help
./vless-core-darwin-armv7 --help
./vless-core-darwin-arm64 --help
```

Expected help output:

```text
Usage: vless-core-linux-amd64 (--uri <uri> | --uri-fd <fd> | --connection-fd <fd>) --listen-port <port>

Options:
  --uri <uri>              VLESS, VMess, Trojan, Shadowsocks, or SOCKS5 upstream URI
  --uri-fd <fd>            Read the URI from a file descriptor
  --connection-fd <fd>     Read URI and pre-resolved server IPs from a file descriptor
  --inspect-config        Validate --uri-fd and print server endpoints without connecting
  --download-server-ips <list> Pre-resolved download-channel addresses
  --listen-port <port>     Local SOCKS5 listen port (127.0.0.1)
  --connect-timeout-ms <n> Connection budget, 1-300000 ms (default 30000)
  --routing <rules>        Optional Proxy, Direct and Block rules
  --route-control-port <p> Direct-route controller port
  --route-control-socket <path> Direct-route controller Unix socket
  --server-ips <list>      Pre-resolved primary-server IPv4/IPv6 addresses
  --xray-version <x.y.z>   Xray version reported by vless-core-cli
  -h, --help               Show help
  -v, --version            Show version
  --openssl-patch-status   Show OpenSSL patch status
```

`--version` reports the actual core version and build commit. The advertised
Xray version defaults to `26.3.27` and can be overridden with `--xray-version x.y.z`
or `XRAY_VER`. It is separate from the Xray 26.6.27 compatibility reference.

## Routing

Routing is optional and is disabled by default. When enabled, ordered rules can send new connections through the selected proxy, connect directly, or block them. Rules can match domains, domain suffixes, IP/CIDR ranges, and ports.

## TLS verification modes

TLS certificate verification is strict by default for TCP, WebSocket, XHTTP, gRPC, and HTTPUpgrade transports. It can be changed explicitly via:

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

The historical `ios6` names now target iOS 5.0 on ARMv7. ARM64 targets iOS 11.0.
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

## Legacy curl on iOS 5.0+

Old stock iOS curl/OpenSSL may fail modern TLS. Build replacement curl (armv7 + OpenSSL 3.5.7 + zlib 1.3.1):

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
iOS archives. No universal iOS executable is produced, so iOS 5–10 cannot
accidentally select the iOS 11+ ARM64 slice.

## Third-party software

Third-party licenses apply only to the components identified in
[`THIRD_PARTY_LICENSES.txt`](THIRD_PARTY_LICENSES.txt), not to vless-core-cli
as a whole. Release and optional curl archives each contain this single
combined notices and licenses document. The iOS release binary statically
includes OpenSSL; curl, zlib, and `cacert.pem` belong only to the optional
`curl-ios6-with-ca` archive.
