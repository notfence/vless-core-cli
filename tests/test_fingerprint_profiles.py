import base64
import json
from pathlib import Path
import subprocess
import unittest
import urllib.parse

from fixtures import BUILD, UUID, CountingProxy, Server, certificate, cli, exchange, socks_connect, uri, xray_client, xray_server
from generate_fingerprint_profiles import render


MODERN = (
    "hellofirefox_120", "hellofirefox_148", "hellochrome_120",
    "hellochrome_131", "hellochrome_133", "helloios_13", "helloios_14",
    "helloedge_106", "hellosafari_26_3", "hello360_11_0", "helloqq_11_1",
)
ALIASES = ("chrome", "firefox", "edge", "qq", "ios", "safari", "360")
NAMES = MODERN + ALIASES + tuple("hello" + name + "_auto" for name in ALIASES) + ("random", "randomized")
ROOT = Path(__file__).resolve().parents[1]
VECTORS = json.loads((ROOT / "tests/fingerprint_vectors.json").read_text())


def grease(value):
    return 0x0a0a if value & 0x0f0f == 0x0a0a and value >> 8 == value & 255 else value


def client_hello(data):
    assert data[0] == 22
    hello = data[5:5 + int.from_bytes(data[3:5], "big")]
    assert hello[0] == 1 and int.from_bytes(hello[1:4], "big") == len(hello)-4
    offset = 39 + hello[38]
    count = int.from_bytes(hello[offset:offset+2], "big")
    ciphers = [grease(int.from_bytes(hello[i:i+2], "big")) for i in range(offset+2, offset+2+count, 2)]
    offset += 2 + count
    offset += 1 + hello[offset]
    end = offset + 2 + int.from_bytes(hello[offset:offset+2], "big")
    assert end == len(hello)
    offset += 2
    extensions = []
    padding = 0
    while offset < end:
        kind = grease(int.from_bytes(hello[offset:offset+2], "big"))
        count = int.from_bytes(hello[offset+2:offset+4], "big")
        value = bytearray(hello[offset+4:offset+4+count])
        assert len(value) == count
        if kind in (10, 43):
            for index in range(1 if kind == 43 else 2, count, 2):
                value[index:index+2] = grease(int.from_bytes(value[index:index+2], "big")).to_bytes(2, "big")
        if kind == 51:
            assert int.from_bytes(value[:2], "big") == len(value)-2
            groups = []
            index = 2
            while index < len(value):
                group = grease(int.from_bytes(value[index:index+2], "big"))
                size = int.from_bytes(value[index+2:index+4], "big")
                key = value[index+4:index+4+size]
                assert len(key) == size and size == {0x0a0a: 1, 29: 32, 23: 65, 4588: 1216}[group]
                assert group == 0x0a0a or any(key)
                groups.append(group)
                index += 4 + size
            assert index == len(value)
            extensions.append({"type": kind, "data": "", "groups": groups})
        else:
            if kind == 0:
                assert bytes(value[5:]) == b"vless-core.test"
                value = b""
            elif kind == 0xfe0d:
                assert value[0] == 0 and value[1:3] == b"\0\1" and value[3:5] in (b"\0\1", b"\0\3")
                assert int.from_bytes(value[6:8], "big") == 32
                assert not value[39] & 128
                assert int.from_bytes(value[40:42], "big") == len(value)-42
                assert len(value)-42 in (144, 176, 208, 239, 240)
                value = b""
            elif kind == 21:
                assert not any(value) and len(value) <= 512
                unpadded = len(hello)-len(value)-4
                assert 255 < unpadded < 512
                expected = 512-unpadded
                assert len(value) == (expected-4 if expected >= 5 else 1)
                padding = len(value)+4
                value = b""
            extensions.append({"type": kind, "data": bytes(value).hex()})
        offset += 4 + count
    assert offset == end
    return {"ciphers": ciphers, "extensions": extensions, "unpadded": len(hello)-padding}


class FingerprintProfileTests(unittest.TestCase):
    def test_configured_fingerprint_name_is_logged(self):
        for name in ("",) + NAMES + ("FIREFOX", "HELLOFIREFOX_AUTO"):
            for kind in ("vless", "trojan", "vmess", "shadowsocks", "vmess-json"):
                if kind == "vmess-json":
                    config = {"add": "127.0.0.1", "port": 443, "id": UUID, "net": "tcp", "tls": "tls"}
                    if name:
                        config["fp"] = name
                    link = "vmess://" + base64.b64encode(json.dumps(config).encode()).decode()
                else:
                    link = uri(443, security="tls", protocol=kind, **({"fp": name} if name else {}))
                with cli(link) as process:
                    self.assertIn(f", fp={name or 'chrome'})", process.log, (kind, name))

    def assert_profile(self, actual, expected):
        self.assertEqual(actual["ciphers"], expected["ciphers"])
        if any(entry["type"] == 21 for entry in expected["extensions"]):
            self.assertEqual(any(entry["type"] == 21 for entry in actual["extensions"]), 255 < actual["unpadded"] < 512)
        actual_extensions = [entry for entry in actual["extensions"] if entry["type"] != 21]
        expected_extensions = [entry for entry in expected["extensions"] if entry["type"] != 21]
        if expected["shuffle"]:
            self.assertEqual(actual_extensions[0]["type"], 0x0a0a)
            self.assertEqual(actual_extensions[-1]["type"], 0x0a0a)
            actual_extensions = sorted(actual_extensions, key=lambda value: (value["type"], value["data"]))
            expected_extensions = sorted(expected_extensions, key=lambda value: (value["type"], value["data"]))
        self.assertEqual(actual_extensions, expected_extensions)

    def test_generated_profiles_match_reference(self):
        self.assertEqual(render(VECTORS), (ROOT / "src/tls_fingerprint_profiles.h").read_text())

    def test_wire_profiles_and_pinned_xray(self):
        environment = {"VLESS_CA_BUNDLE": str(certificate()[0]), "VLESS_TLS_MODE": "strict"}
        with Server() as target:
            for transport in ("tcp", "ws", "httpupgrade"):
                with xray_server(transport, "tls") as server:
                    for profile in VECTORS["profiles"]:
                        name = {"helloedge_85": "edge", "hello360_7_5": "360"}.get(profile["name"], profile["name"])
                        if transport != "tcp":
                            profile = dict(profile, extensions=[dict(entry, data="000908687474702f312e31") if entry["type"] == 16 else entry for entry in profile["extensions"]])
                        for reference in (False, True):
                            with self.subTest(fp=name, transport=transport, reference=reference), CountingProxy(server.port) as proxy:
                                client = xray_client(proxy.port, transport=transport, security="tls", fingerprint=name) if reference else cli(uri(proxy.port, transport=transport, security="tls", fp=name), environment=environment)
                                with client as process, socks_connect(process.port, target.port) as connection:
                                    exchange(connection, b"fingerprint wire fixture")
                                expected = profile
                                if transport != "tcp" and not reference:
                                    expected = dict(profile, extensions=[entry for entry in profile["extensions"] if entry["type"] not in (0x4469,0x44cd)])
                                self.assert_profile(client_hello(proxy.client_data[0]), expected)

    def test_process_random_stays_in_modern_set(self):
        environment = {"VLESS_CA_BUNDLE": str(certificate()[0]), "VLESS_TLS_MODE": "strict"}
        with Server() as target, xray_server("tcp", "tls") as server, CountingProxy(server.port) as proxy, cli(uri(proxy.port, security="tls", fp="random"), environment=environment) as client:
            for _ in range(5):
                with socks_connect(client.port, target.port) as connection:
                    exchange(connection, b"process-stable random fingerprint")
            matches = []
            for data in proxy.client_data:
                actual = client_hello(data)
                found = []
                for profile in VECTORS["profiles"]:
                    if profile["name"] not in MODERN:
                        continue
                    try:
                        self.assert_profile(actual, profile)
                        found.append(profile["name"])
                    except AssertionError:
                        pass
                self.assertEqual(len(found), 1)
                matches.extend(found)
            self.assertEqual(len(matches), 5)
            self.assertEqual(len(set(matches)), 1)

    def test_tls_versions_and_reality(self):
        environment = {"VLESS_CA_BUNDLE": str(certificate()[0]), "VLESS_TLS_MODE": "strict"}
        names = MODERN + ("edge", "360")
        with Server() as target:
            for security, version in (("tls", "1.2"), ("tls", "1.3"), ("reality", None)):
                settings = {"minVersion": version, "maxVersion": version} if version else None
                with xray_server("tcp", security, tls_settings=settings) as server:
                    for name in names:
                        if name == "360" and version != "1.2":
                            continue
                        with self.subTest(fp=name, security=security, version=version), cli(uri(server.port, security=security, fp=name), environment=environment) as client, socks_connect(client.port, target.port) as connection:
                            exchange(connection, b"TLS version and REALITY compatibility")

    def test_random_upload_download_and_pool(self):
        environment = {"VLESS_CA_BUNDLE": str(certificate()[0]), "VLESS_TLS_MODE": "strict"}
        for pooled in (False, True):
            with self.subTest(pooled=pooled), Server() as target, xray_server("xhttp", "tls") as server, CountingProxy(server.port) as upload, CountingProxy(server.port) as download:
                extra = {"downloadSettings": {"address": "127.0.0.1", "port": download.port, "network": "xhttp", "security": "tls",
                         "tlsSettings": {"serverName": "vless-core.test", "fingerprint": "random"}, "xhttpSettings": {"path": "/vless-core"}}}
                if pooled:
                    extra["xmux"] = {"maxConnections": 1}
                with cli(uri(upload.port, transport="xhttp", security="tls", fp="random", extra=json.dumps(extra)), environment=environment) as core:
                    for _ in range(3):
                        with socks_connect(core.port, target.port) as connection:
                            exchange(connection, b"independent random upload and download")
                self.assertTrue(upload.client_data)
                self.assertTrue(download.client_data)
                profiles = []
                first = client_hello(upload.client_data[0])
                for profile in VECTORS["profiles"]:
                    if profile["name"] not in MODERN: continue
                    try: self.assert_profile(first, profile); profiles.append(profile)
                    except AssertionError: pass
                self.assertEqual(len(profiles), 1)
                for data in upload.client_data + download.client_data:
                    self.assert_profile(client_hello(data), profiles[0])

    def test_profiles_over_protocols_and_transports(self):
        environment = {"VLESS_CA_BUNDLE": str(certificate()[0]), "VLESS_TLS_MODE": "strict"}
        with Server() as target:
            for protocol, transport in (("trojan", "tcp"), ("vmess", "tcp"), ("shadowsocks", "tcp"), ("vless", "ws"), ("vless", "httpupgrade"), ("vless", "grpc"), ("vless", "xhttp")):
                with xray_server(transport, "tls", protocol=protocol) as server:
                    for name in MODERN + ("edge", "360"):
                        if name == "360" and transport == "grpc":
                            self.assertNotEqual(self.inspect(uri(server.port, transport=transport, security="tls", fp=name, alpn="h2")).returncode, 0)
                            continue
                        with self.subTest(fp=name, protocol=protocol, transport=transport), cli(uri(server.port, transport=transport, security="tls", protocol=protocol, fp=name), environment=environment) as client, socks_connect(client.port, target.port) as connection:
                            exchange(connection, b"profile protocol and transport fixture")

    def inspect(self, link):
        return subprocess.run([str(BUILD / "vless-core-test"), "--uri-fd", "0", "--inspect-config"],
                              input=link.encode(), capture_output=True, timeout=5)

    def test_profile_names_and_input_forms(self):
        for name in NAMES:
            for kind in ("vless", "trojan", "vmess", "vmess-json", "ss", "download"):
                with self.subTest(fp=name, kind=kind):
                    query = {"security": "tls", "type": "tcp", "sni": "example.test", "fp": name}
                    credentials = "test-password" if kind == "trojan" else UUID
                    scheme = kind
                    if kind == "ss":
                        credentials = base64.urlsafe_b64encode(b"chacha20-ietf-poly1305:test-password").decode().rstrip("=")
                    if kind == "vmess-json":
                        config = {"v": "2", "add": "198.51.100.1", "port": "443", "id": UUID,
                                  "aid": "0", "scy": "auto", "net": "tcp", "tls": "tls", "fp": name}
                        link = "vmess://" + base64.b64encode(json.dumps(config).encode()).decode()
                    else:
                        if kind == "download":
                            scheme = "vless"
                            query.update(type="xhttp", fp="chrome", extra=json.dumps({"downloadSettings": {
                                "address": "198.51.100.2", "port": 443, "network": "xhttp", "security": "tls",
                                "tlsSettings": {"serverName": "example.test", "fingerprint": name}}}))
                        link = f"{scheme}://{credentials}@198.51.100.1:443?" + urllib.parse.urlencode(query)
                    result = self.inspect(link)
                    self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_excluded_profiles_remain_rejected(self):
        for name in ("android", "helloandroid_11_okhttp", "hellofirefox_55", "hellochrome_120_pq",
                     "hellochrome_155", "hellogolang", "hellorandomized", "randomizednoalpn", "unsafe", "unknown"):
            with self.subTest(fp=name):
                result = self.inspect(f"vless://{UUID}@198.51.100.1:443?security=tls&fp={name}")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"unsupported fp", result.stderr)
