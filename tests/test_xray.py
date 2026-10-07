import base64
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import threading
import time
import unittest
from unittest import mock
import fixtures
from fixtures import BUILD, OPENSSL, XRAY, PRIVATE, KEY, PUBLIC_KEY, Process, Server, certificate, cli, exact, exchange, port, socks_connect, uri, xray_client, xray_server

SUBSCRIPTION_EXTRA = {
    "mode":"stream-one", "seqKey":"x-amz-cf-pop", "seqPlacement":"header",
    "sessionIDKey":"x-amz-cf-id", "sessionIDLength":"16-32",
    "sessionIDPlacement":"header", "sessionIDTable":"Base62",
    "sessionKey":"x-amz-cf-id", "sessionPlacement":"header",
    "uplinkHTTPMethod":"POST", "xPaddingBytes":"128-1280",
    "xPaddingHeader":"X-Cache", "xPaddingKey":"x-padding",
    "xPaddingMethod":"tokenish", "xPaddingObfsMode":True, "xPaddingPlacement":"header",
    "xmux":{"cMaxReuseTimes":"300-600", "hKeepAlivePeriod":600,
            "hMaxRequestTimes":"1000-2000", "hMaxReusableSecs":"1200-2400",
            "maxConcurrency":"0", "maxConnections":"1-3"},
}

class XrayTests(unittest.TestCase):
    def test_reality_hybrid_target(self):
        for transport in ("tcp", "xhttp"):
            for fingerprint in ("firefox", "chrome"):
                with self.subTest(transport=transport, fingerprint=fingerprint):
                    self.transfer(transport, "reality", "stream-one" if transport == "xhttp" else None,
                                  fingerprint=fingerprint, server_extra={"reality_target_groups":["X25519MLKEM768"]})

    def test_reference_hybrid_fixture(self):
        for transport in ("tcp", "xhttp"):
            with self.subTest(transport=transport):
                with Server() as target, xray_server(transport, "reality", reality_target_groups=["X25519MLKEM768"]) as reference:
                    with xray_client(reference.port, transport) as client:
                        with socks_connect(client.port, target.port) as tunnel:
                            exchange(tunnel, b"vless-core reference hybrid" * 3000)

    def test_xhttp_encryption_vision_large_payload(self):
        for mode in ("auto", "stream-one", "stream-up", "packet-up"):
            with self.subTest(mode=mode):
                self.transfer("xhttp", "reality", mode, flow="xtls-rprx-vision",
                              encryption=f"mlkem768x25519plus.native.0rtt.{PUBLIC_KEY}",
                              decryption=f"mlkem768x25519plus.native.0s.{KEY}", fingerprint="firefox")

    def test_xhttp_custom_subscription_options(self):
        for fingerprint in ("firefox", "edge"):
            with self.subTest(fingerprint=fingerprint):
                self.transfer("xhttp", "reality", "stream-one", flow="xtls-rprx-vision",
                              encryption=f"mlkem768x25519plus.native.0rtt.{PUBLIC_KEY}",
                              decryption=f"mlkem768x25519plus.native.0s.{KEY}", fingerprint=fingerprint,
                              extra=SUBSCRIPTION_EXTRA, server_extra=SUBSCRIPTION_EXTRA)

    def test_xhttp_repeated_parallel_duplex(self):
        upload = bytes(range(251)) * 16711
        download = bytes(range(250, -1, -1)) * 16711
        digest = hashlib.sha256(upload).digest()
        completed = []
        lock = threading.Lock()
        def handler(connection):
            self.assertEqual(exact(connection, 1), b"D")
            connection.sendall(download)
            self.assertEqual(hashlib.sha256(exact(connection, len(upload))).digest(), digest)
            connection.sendall(digest)
            with lock:
                completed.append(True)
        cases = [(mode, fingerprint, False) for mode in ("auto", "stream-one", "stream-up", "packet-up") for fingerprint in ("edge", "chrome")]
        cases.append(("stream-one", "firefox", True))
        for mode, fingerprint, encrypted in cases:
            with self.subTest(mode=mode, fingerprint=fingerprint, encrypted=encrypted):
                completed.clear()
                extra = dict(SUBSCRIPTION_EXTRA) if encrypted else {"mode":mode, "xPaddingBytes":"100-1000"}
                decryption = f"mlkem768x25519plus.native.0s.{KEY}" if encrypted else "none"
                encryption = f"mlkem768x25519plus.native.0rtt.{PUBLIC_KEY}" if encrypted else "none"
                flow = "xtls-rprx-vision" if encrypted else ""
                server_extra = dict(extra)
                server_extra.pop("mode")
                with Server(handler) as target, xray_server("xhttp", "reality", flow=flow, decryption=decryption,
                        reality_target_groups=["X25519MLKEM768"] if encrypted else None, **server_extra) as reference:
                    config = uri(reference.port, "xhttp", "reality", mode=mode, fp=fingerprint,
                                 flow=flow, encryption=encryption, extra=json.dumps(extra))
                    with cli(config) as core:
                        descriptors = Path(f"/proc/{core.process.pid}/fd")
                        tasks = Path(f"/proc/{core.process.pid}/task")
                        baseline_fds = len(list(descriptors.iterdir()))
                        baseline_tasks = len(list(tasks.iterdir()))
                        def transfer(index):
                            with socks_connect(core.port, target.port) as tunnel:
                                tunnel.settimeout(8)
                                errors = []
                                def send():
                                    try:
                                        tunnel.sendall(b"D" + upload)
                                    except BaseException as error:
                                        errors.append(error)
                                sender = threading.Thread(target=send, daemon=True)
                                sender.start()
                                try:
                                    self.assertEqual(exact(tunnel, len(download)), download)
                                    self.assertEqual(exact(tunnel, len(digest)), digest)
                                    self.assertEqual(tunnel.recv(1), b"")
                                finally:
                                    tunnel.shutdown(socket.SHUT_RDWR)
                                    sender.join(timeout=2)
                                self.assertFalse(sender.is_alive())
                                self.assertFalse(errors, errors)
                        try:
                            for repetition in range(3):
                                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as workers:
                                    list(workers.map(transfer, range(4)))
                            self.assertEqual(len(completed), 12)
                            deadline = time.monotonic() + 3
                            while len(list(descriptors.iterdir())) > baseline_fds or len(list(tasks.iterdir())) > baseline_tasks:
                                if time.monotonic() >= deadline:
                                    self.fail(f"connections did not release resources: fds={len(list(descriptors.iterdir()))}, threads={len(list(tasks.iterdir()))}")
                                time.sleep(0.02)
                        except BaseException as error:
                            raise AssertionError(f"{mode}/{fingerprint}: {error}\n{core.log}\n{reference.log}") from error
                        self.assertIsNone(core.process.poll(), core.log)

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

    def transfer(self, transport, security, mode=None, flow="", encryption=None, decryption="none", tls_target=False, extra=None, server_extra=None, alpn=None, fingerprint=None):
        server_parameters = dict(server_extra or {})
        server_mode = server_parameters.pop("mode", mode)
        with Server(tls=tls_target) as target, xray_server(transport, security, server_mode, flow, decryption, **server_parameters) as reference:
            parameters = {"flow":flow}
            if mode:
                parameters["mode"] = mode
            if encryption:
                parameters["encryption"] = encryption
            if extra:
                parameters["extra"] = json.dumps(extra)
            if alpn:
                parameters["alpn"] = alpn
            if fingerprint:
                parameters["fp"] = fingerprint
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
            for fingerprint in ("chrome","firefox","edge","random","randomized","qq"):
                with self.subTest(security=security,fingerprint=fingerprint):
                    self.transfer("tcp", security, flow="xtls-rprx-vision", tls_target=True, fingerprint=fingerprint)

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

    def test_vision_repeated_download(self):
        payload = bytes(range(251)) * 16711
        cert, _ = certificate()
        for encrypted_target, reference_client in ((False, False), (True, True), (True, False)):
            with self.subTest(encrypted_target=encrypted_target, reference_client=reference_client):
                def handler(connection):
                    self.assertEqual(exact(connection, 1), b"D")
                    connection.sendall(payload)
                    if encrypted_target:
                        connection.unwrap().close()
                with Server(handler, tls=encrypted_target) as target, xray_server("tcp", "reality", flow="xtls-rprx-vision") as reference:
                    client = xray_client(reference.port, flow="xtls-rprx-vision") if reference_client else cli(uri(reference.port, "tcp", "reality", flow="xtls-rprx-vision", fp="firefox"))
                    with client as core:
                        def download(index):
                            with socks_connect(core.port, target.port) as tunnel:
                                tunnel.settimeout(8)
                                if encrypted_target:
                                    context = ssl.create_default_context(cafile=str(cert))
                                    tunnel = context.wrap_socket(tunnel, server_hostname="vless-core.test")
                                with tunnel:
                                    tunnel.sendall(b"D")
                                    self.assertEqual(exact(tunnel, len(payload)), payload)
                                    self.assertEqual(tunnel.recv(1), b"")
                                    if encrypted_target:
                                        tunnel.unwrap().close()
                        for repetition in range(3):
                            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as workers:
                                list(workers.map(download, range(4)))
                        self.assertIsNone(core.process.poll(), core.log)

    def test_xhttp_h1_packet_up(self):
        for attempt in range(3):
            with self.subTest(attempt=attempt):
                self.transfer("xhttp", "tls", "packet-up", alpn="http/1.1")

    def test_xhttp_stream_upload(self):
        block = bytes(range(256))*128
        reply = b"vless-core upload complete"
        def handler(connection):
            for _ in range(128):
                self.assertEqual(exact(connection,len(block)),block)
            connection.sendall(reply)
        cert, _ = certificate()
        for security in ("tls","reality"):
            for mode in ("stream-one","stream-up"):
                with self.subTest(security=security,mode=mode):
                    with Server(handler) as target, xray_server("xhttp",security,mode) as reference:
                        with cli(uri(reference.port,"xhttp",security,mode=mode,fp="edge"),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                            with socks_connect(core.port,target.port) as tunnel:
                                for _ in range(128):
                                    tunnel.sendall(block)
                                self.assertEqual(exact(tunnel,len(reply)),reply)
                            self.assertIsNone(core.process.poll(),core.log)

    def test_h2_huffman_status_responses(self):
        cases = ((200,bytes.fromhex("48821001")),(302,bytes.fromhex("48826402")),
                 (403,bytes.fromhex("4883680cff")),(429,bytes.fromhex("4883684fff")),
                 (503,bytes.fromhex("48836c0cff")),(None,bytes.fromhex("48821000")))
        cases = [(status,block,fragmented) for status,block in cases for fragmented in (False,True)]
        request = b"vless-core request"
        reply = b"vless-core huffman response"
        def frame(kind, flags, payload, stream=1):
            return len(payload).to_bytes(3,"big")+bytes([kind,flags])+stream.to_bytes(4,"big")+payload
        def read_frame(connection):
            header = exact(connection,9)
            size = int.from_bytes(header[:3],"big")
            self.assertLessEqual(size,1048576)
            return header[3],header[4],int.from_bytes(header[5:],"big"),exact(connection,size)
        cert, _ = certificate()
        for transport in ("xhttp","grpc"):
            parameters = {"mode":"stream-one"} if transport == "xhttp" else {}
            for status, block, fragmented in cases:
                with self.subTest(transport=transport,status=status,fragmented=fragmented):
                    def handler(connection):
                        self.assertEqual(exact(connection,24),b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
                        received = bytearray()
                        while not received.endswith(request):
                            kind, _, stream, payload = read_frame(connection)
                            if kind == 0:
                                self.assertEqual(stream,1)
                                if not received:
                                    self.assertTrue(payload.startswith(b"\x00"))
                                received.extend(payload)
                        data = b"\x00\x00"+reply
                        trailer = b""
                        if transport == "grpc":
                            message = b"\x0a"+bytes([len(data)])+data
                            data = b"\x00"+len(message).to_bytes(4,"big")+message
                            trailer = frame(1,5,b"\x00\x0bgrpc-status\x010")
                        headers = frame(1,0,block[:1])+frame(9,4,block[1:]) if fragmented else frame(1,4,block)
                        response = frame(4,0,b"",0)+headers+frame(0,0 if trailer else 1,data)+trailer
                        for offset in range(0,len(response),3):
                            connection.sendall(response[offset:offset+3])
                        if transport == "grpc":
                            while True:
                                kind, flags, _, _ = read_frame(connection)
                                if kind == 0 and flags & 1:
                                    break
                        connection.unwrap()
                    with Server(handler,tls=True) as server, cli(uri(server.port,transport,"tls",**parameters),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                        with socks_connect(core.port,80) as tunnel:
                            tunnel.settimeout(3)
                            tunnel.sendall(request)
                            if status == 200:
                                self.assertEqual(exact(tunnel,len(reply)),reply)
                                self.assertEqual(tunnel.recv(1),b"")
                            else:
                                try:
                                    self.assertEqual(tunnel.recv(1),b"")
                                except ConnectionError:
                                    pass
                        if status != 200:
                            expected = "invalid h2 header block" if status is None else f"{transport} h2 stream 1 returned non-200: {status}"
                            self.assertIn(expected,core.log)
                        self.assertIsNone(core.process.poll(),core.log)

    def test_xhttp_h2_header_only_response(self):
        first = threading.Event()
        first_payload, second_payload = b"vless-core first", b"vless-core second"
        reply = b"vless-core complete"
        def frame(kind, flags, payload, stream=1):
            return len(payload).to_bytes(3,"big")+bytes([kind,flags])+stream.to_bytes(4,"big")+payload
        def read_data(connection):
            while True:
                header = exact(connection,9)
                size = int.from_bytes(header[:3],"big")
                self.assertLessEqual(size,1048576)
                payload = exact(connection,size)
                if header[3] == 0:
                    self.assertEqual(int.from_bytes(header[5:],"big"),1)
                    return payload
        def handler(connection):
            self.assertEqual(exact(connection,24),b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            self.assertTrue(read_data(connection).startswith(b"\x00"))
            connection.sendall(frame(4,0,b"",0)+frame(1,4,b"\x88")+frame(0,0,b"\x00\x00"))
            self.assertEqual(read_data(connection),first_payload)
            first.set()
            self.assertEqual(read_data(connection),second_payload)
            connection.sendall(frame(0,0,reply)+frame(0,1,b""))
        cert, _ = certificate()
        with Server(handler,tls=True) as target:
            with cli(uri(target.port,"xhttp","tls",mode="stream-one"),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                with socks_connect(core.port,80) as tunnel:
                    tunnel.settimeout(3)
                    tunnel.sendall(first_payload)
                    self.assertTrue(first.wait(3))
                    tunnel.sendall(second_payload)
                    self.assertEqual(exact(tunnel,len(reply)),reply)
                    self.assertEqual(tunnel.recv(1),b"")
                self.assertIsNone(core.process.poll(),core.log)

    def test_xhttp_h1_fragmented_metadata(self):
        def handler(connection):
            headers = bytearray()
            while not headers.endswith(b"\r\n\r\n"):
                headers.extend(exact(connection,1))
                self.assertLess(len(headers),8192)
            self.assertTrue(headers.startswith(b"GET /vless-core/"))
            connection.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n")
            for part in (b"4",b"\r",b"\n",b"v",b"pn!\r\n",b"0\r\n\r\n"):
                self.assertEqual(exact(connection,3),b"ack")
                connection.sendall(part)
        cert, _ = certificate()
        with Server(handler,tls=True) as server:
            result = subprocess.run([str(BUILD/"test_tls"),"--xhttp-chunks",uri(server.port,"xhttp","tls",mode="packet-up",alpn="http/1.1")],env=dict(os.environ,VLESS_CA_BUNDLE=str(cert)),capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)

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
