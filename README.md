# vless-core-cli

Standalone C CLI client for `VLESS (Reality + xtls-rprx-vision)`.

## Tested Device/OS

Tested only on **iOS 6.1.3** on **iPhone 4s**.
Compatibility with other iOS versions/devices is not guaranteed.

## Binaries

Build outputs:

- `vless-core-linux-amd64`
- `vless-core-darwin-amrv7`

## Build

```bash
cd vless-core-cli
make clean
make all
```

Build only Linux:

```bash
make linux
```

Build only iOS:

```bash
make ios
```

## Run

```bash
./vless-core-linux-amd64 --uri '<vless://...>' --listen-port 21080
```

Version check:

```bash
./vless-core-linux-amd64 -v
./vless-core-darwin-amrv7 -v
```

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
file ./vless-core-darwin-amrv7
```

## Legacy curl on iOS 6

Old stock iOS 6 curl/OpenSSL may fail modern TLS. Build replacement curl (armv7 + OpenSSL 1.1.1w):

```bash
make curl-ios6
make curl-ios6-package
```

Archive output:

- `third_party/curl-ios6-with-ca.tar.gz`
