import base64
import json
import os
import ssl
import subprocess
import unittest
from unittest import mock
import fixtures
from fixtures import BUILD, OPENSSL, XRAY, PRIVATE, KEY, PUBLIC_KEY, Process, Server, certificate, cli, exchange, port, socks_connect, uri, xray_server

class XrayTests(unittest.TestCase):
    def test_reference_listener_collision_recovery(self):
        original = fixtures.port
        with Server() as occupied:
            selected = []
            def choose():
                value = occupied.port if not selected else original()
                selected.append(value)
                return value
            with mock.patch("fixtures.port",side_effect=choose), xray_server("tcp","none") as reference:
                self.assertNotEqual(reference.port,occupied.port)
                self.assertGreaterEqual(len(selected),2)
                self.assertIsNone(reference.process.poll(),reference.log)

    def transfer(self, transport, security, mode=None, flow="", encryption=None, decryption="none", tls_target=False, extra=None, server_extra=None, alpn=None):
        with Server(tls=tls_target) as target, xray_server(transport, security, mode, flow, decryption, **(server_extra or {})) as reference:
            parameters = {"flow":flow}
            if mode:
                parameters["mode"] = mode
            if encryption:
                parameters["encryption"] = encryption
            if extra:
                parameters["extra"] = json.dumps(extra)
            if alpn:
                parameters["alpn"] = alpn
            cert, _ = certificate()
            with cli(uri(reference.port, transport, security, **parameters), environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                try:
                    with socks_connect(core.port, target.port) as tunnel:
                        if tls_target:
                            context = ssl.create_default_context(cafile=str(cert))
                            tunnel = context.wrap_socket(tunnel, server_hostname="vless-core.test")
                        with tunnel:
                            exchange(tunnel, b"vless-core initial payload\x00")
                            exchange(tunnel, bytes(range(251))*1045)
                except BaseException as error:
                    raise AssertionError(f"{transport}/{security}/{mode}/{flow}: {error}\n{core.log}\n{reference.log}") from error
                self.assertIsNone(core.process.poll(), core.log)

    def test_transport_matrix(self):
        for transport in ("tcp","ws","xhttp","grpc"):
            for security in ("none","tls","reality"):
                if transport == "ws" and security == "reality":
                    continue
                modes = ("packet-up","stream-one","stream-up","auto") if transport == "xhttp" else (("gun","multi") if transport == "grpc" else (None,))
                for mode in modes:
                    with self.subTest(transport=transport, security=security, mode=mode):
                        self.transfer(transport, security, mode)

    def test_vision(self):
        for security in ("tls","reality"):
            with self.subTest(security=security):
                self.transfer("tcp", security, flow="xtls-rprx-vision", tls_target=True)

    def test_vision_short_reads_after_padding(self):
        cert, _ = certificate()
        for security in ("tls","reality"):
            for fingerprint in ("chrome","firefox"):
                with self.subTest(security=security,fingerprint=fingerprint):
                    with Server() as target, xray_server("tcp",security,flow="xtls-rprx-vision") as reference:
                        with cli(uri(reference.port,"tcp",security,flow="xtls-rprx-vision",fp=fingerprint),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                            with socks_connect(core.port,target.port) as tunnel:
                                tunnel.settimeout(5)
                                for sequence in range(12):
                                    exchange(tunnel,bytes([sequence])+b"vless-core")
                            self.assertIsNone(core.process.poll(),core.log)

    def test_xhttp_h1_packet_up(self):
        for attempt in range(3):
            with self.subTest(attempt=attempt):
                self.transfer("xhttp", "tls", "packet-up", alpn="http/1.1")

    def test_xhttp_placements(self):
        for placement in ("path","header","query","cookie"):
            extra = {"sessionIDPlacement":placement,"sessionIDKey":"X-Session" if placement == "header" else "x_session","seqPlacement":placement,"seqKey":"X-Seq" if placement == "header" else "x_seq","xPaddingPlacement":"header" if placement == "path" else placement,"xPaddingObfsMode":True,"xPaddingKey":"x_padding","xPaddingHeader":"X-Padding","xPaddingBytes":"8-16","scMaxEachPostBytes":1024}
            with self.subTest(placement=placement):
                self.transfer("xhttp","none","packet-up",extra=extra,server_extra=extra)

    def test_xhttp_get(self):
        extra = {"uplinkHTTPMethod":"GET", "scMaxEachPostBytes":1024, "xPaddingBytes":8}
        self.transfer("xhttp","none","packet-up",extra=extra,server_extra=extra)

    def test_encryption_modes(self):
        seed = base64.urlsafe_b64encode(bytes(range(64))).decode().rstrip("=")
        output = subprocess.check_output([str(XRAY), "mlkem768", "-i", seed], text=True, timeout=5)
        mlkem_public = next(line.split(": ",1)[1] for line in output.splitlines() if line.startswith("Client:"))
        for relay_public, relay_private in ((PUBLIC_KEY, KEY),(mlkem_public, seed)):
            for mode in ("native","xorpub","random"):
                for rtt in ("0rtt","1rtt"):
                    with self.subTest(relay="x25519" if relay_private == KEY else "mlkem",mode=mode,rtt=rtt):
                        self.transfer("tcp","none",encryption=f"mlkem768x25519plus.{mode}.{rtt}.{relay_public}",decryption=f"mlkem768x25519plus.{mode}.0s.{relay_private}")

    def test_encryption_transports_and_vision(self):
        for transport, security, flow in (("tcp","tls","xtls-rprx-vision"),("tcp","reality","xtls-rprx-vision"),("ws","tls",""),("xhttp","tls",""),("xhttp","reality",""),("grpc","tls","")):
            with self.subTest(transport=transport,security=security,flow=flow):
                self.transfer(transport,security,flow=flow,encryption=f"mlkem768x25519plus.random.1rtt.{PUBLIC_KEY}",decryption=f"mlkem768x25519plus.random.0s.{KEY}",tls_target=bool(flow))

    def test_tls_security_policy(self):
        cert, _ = certificate()
        for transport in ("tcp","ws","xhttp","grpc"):
            with Server() as target, xray_server(transport,"tls") as reference:
                for mode in ("strict","auto","insecure","tofu"):
                    with self.subTest(transport=transport,mode=mode):
                        environment = {"VLESS_TLS_MODE":mode,"VLESS_XHTTP_PIN_FILE":str(PRIVATE/f"e2e-tofu-{transport}")}
                        with cli(uri(reference.port,transport,"tls"),environment=environment) as core:
                            if mode in ("strict","auto"):
                                with self.assertRaises((AssertionError,EOFError,ConnectionError)):
                                    with socks_connect(core.port,target.port) as tunnel:
                                        exchange(tunnel,b"vless-core")
                            else:
                                with socks_connect(core.port,target.port) as tunnel:
                                    exchange(tunnel,b"vless-core")
                with self.subTest(transport=transport,name="wrong"), cli(uri(reference.port,transport,"tls",sni="wrong.test"),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                    with self.assertRaises((AssertionError,EOFError,ConnectionError)):
                        with socks_connect(core.port,target.port) as tunnel:
                            exchange(tunnel,b"vless-core")

    def test_expired_certificate(self):
        cert,key = certificate(); expired = PRIVATE/"expired.pem"
        result = subprocess.run([str(OPENSSL),"x509","-in",str(cert),"-signkey",str(key),"-not_before","20000101000000Z","-not_after","20010101000000Z","-out",str(expired)],capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr)
        with Server() as target, xray_server("tcp","tls",tls_certificate=expired) as reference, cli(uri(reference.port,"tcp","tls"),environment={"VLESS_CA_BUNDLE":str(expired)}) as core:
            with self.assertRaises((AssertionError,EOFError,ConnectionError)):
                with socks_connect(core.port,target.port) as tunnel:
                    exchange(tunnel,b"vless-core")
            self.assertIn("expired",core.log.lower())

    def test_reality_bad_key(self):
        with Server() as target, xray_server("tcp","reality") as reference:
            config = uri(reference.port,"tcp","reality").replace(PUBLIC_KEY,"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            with cli(config) as core:
                with self.assertRaises((AssertionError,EOFError,ConnectionError)):
                    with socks_connect(core.port,target.port) as tunnel:
                        exchange(tunnel,b"vless-core")

    def test_fingerprints(self):
        for fp in ("chrome","firefox","edge","random","randomized","qq"):
            with self.subTest(fingerprint=fp):
                with Server() as target, xray_server("tcp","reality") as reference, cli(uri(reference.port,"tcp","reality",fp=fp)) as core:
                    with socks_connect(core.port,target.port) as tunnel:
                        exchange(tunnel,b"vless-core fingerprint")

    def test_live_aes_fallback_and_cache(self):
        cert,key = certificate(); listen_port = port()
        command = [str(OPENSSL),"s_server","-accept",f"127.0.0.1:{listen_port}","-cert",str(cert),"-key",str(key),"-tls1_3","-groups","X25519","-ciphersuites","TLS_AES_128_GCM_SHA256","-www"]
        with Process(command,"aes-server",{"OPENSSL_CONF":"/dev/null"},ready="ACCEPT") as server:
            result = subprocess.run([str(BUILD/"test_tls"),uri(listen_port,"tcp","tls")],env=dict(os.environ,VLESS_CA_BUNDLE=str(cert)),capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr+server.log)

    def test_reference_vision_fixture(self):
        cert,_ = certificate()
        with Server(tls=True) as target, xray_server("tcp","tls",flow="xtls-rprx-vision") as reference:
            listen_port = port()
            config = {"log":{"loglevel":"info"},"inbounds":[{"listen":"127.0.0.1","port":listen_port,"protocol":"socks","settings":{"auth":"noauth","udp":False}}],"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":reference.port,"users":[{"id":"00000000-0000-0000-0000-000000000001","encryption":"none","flow":"xtls-rprx-vision"}]}]},"streamSettings":{"network":"raw","security":"tls","tlsSettings":{"serverName":"vless-core.test","certificates":[{"certificateFile":str(cert),"usage":"verify"}]}}}]}
            path = PRIVATE/"reference-client.json"; path.write_text(json.dumps(config))
            with Process([str(XRAY),"run","-c",str(path)],"reference-client",ready="started") as client:
                try:
                    with socks_connect(listen_port,target.port) as tunnel:
                        context = ssl.create_default_context(cafile=str(cert))
                        with context.wrap_socket(tunnel,server_hostname="vless-core.test") as secure:
                            exchange(secure,b"vless-core reference"*100)
                except BaseException as error:
                    raise AssertionError(f"reference fixture failure: {error}\n{client.log}\n{reference.log}") from error
