import base64
import concurrent.futures
import json
from pathlib import Path
import socket
import threading
import time
import unittest

from fixtures import Server, certificate, cli, exact, exchange, shadowsocks_password, socks_connect, uri, xray_server, SHADOWSOCKS_METHODS, UUID

RESPONSE=b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"

def request(connection):
    data=bytearray()
    while b"\r\n\r\n" not in data:
        block=connection.recv(4096)
        if not block:
            raise EOFError("HTTPUpgrade request truncated")
        data.extend(block)
        if len(data)>16384:
            raise AssertionError("HTTPUpgrade request too large")
    head,body=bytes(data).split(b"\r\n\r\n",1)
    return head,body

class HTTPUpgradeTests(unittest.TestCase):
    def test_xray_protocol_security_matrix(self):
        cert,_=certificate()
        for protocol in ("vless","trojan","vmess","shadowsocks"):
            methods=SHADOWSOCKS_METHODS if protocol=="shadowsocks" else (None,)
            for security in ("none","tls"):
                for method in methods:
                    algorithms=("auto","aes-128-gcm","chacha20-poly1305","none","zero") if protocol=="vmess" else (None,)
                    for algorithm in algorithms:
                        options={"protocol":protocol}
                        if method: options.update(ss_method=method,password=shadowsocks_password(method))
                        parameters={"encryption":algorithm} if algorithm else {}
                        with self.subTest(protocol=protocol,security=security,method=method,algorithm=algorithm), Server() as target, xray_server("httpupgrade",security,**options) as reference:
                            with cli(uri(reference.port,"httpupgrade",security,**options,**parameters),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                                with socks_connect(core.port,target.port) as connection:
                                    exchange(connection,b"\x00\x00vless-core HTTPUpgrade exact echo"*500)
                                self.assertIsNone(core.process.poll(),core.log)

    def test_early_data_fragmented_upgrade_and_remaining_data(self):
        for security in ("none","tls"):
            for early in (0,1,4294967295):
                observed=[]
                def handler(connection):
                    head,body=request(connection)
                    observed.append(head)
                    self.assertIn(b"Connection: Upgrade",head)
                    self.assertIn(b"Upgrade: websocket",head)
                    self.assertNotIn(b"Sec-WebSocket-Key:",head)
                    self.assertNotIn(b"Sec-WebSocket-Protocol:",head)
                    if early:
                        while len(body)<26: body+=connection.recv(4096)
                    else:
                        self.assertEqual(body,b"")
                        connection.settimeout(.03)
                        with self.assertRaises(TimeoutError): connection.recv(1)
                        connection.settimeout(20)
                    for byte in RESPONSE[:-2]: connection.sendall(bytes([byte]))
                    connection.sendall(RESPONSE[-2:]+b"\x00\x00\x00\x00server first")
                    while len(body)<26: body+=connection.recv(4096)
                    self.assertEqual(body[0],0)
                    extra=body[26:]
                    if extra: connection.sendall(extra)
                    while True:
                        block=connection.recv(8192)
                        if not block: return
                        connection.sendall(block)
                cert,_=certificate()
                with self.subTest(security=security,early=early), Server(handler,tls=security=="tls") as server:
                    with cli(uri(server.port,"httpupgrade",security,ed=early),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                        with socks_connect(core.port,80) as connection:
                            self.assertEqual(exact(connection,len(b"\x00\x00server first")),b"\x00\x00server first")
                            exchange(connection,b"vless-core raw stream, not WS framing"*1000)
                self.assertEqual(len(observed),1)

    def test_invalid_upgrade_does_not_expose_payload(self):
        for early in (0,1):
            for response in (b"HTTP/1.1 200 OK\r\n\r\n",RESPONSE.replace(b"Upgrade: websocket",b"Upgrade: other"),RESPONSE.replace(b"Connection: Upgrade",b"Connection: close"),b"HTTP/1.1 101 Switching Protocols\r\nX-Large: "+b"x"*32768):
                def handler(connection):
                    request(connection)
                    connection.sendall(response+b"\x00\x00must not be delivered")
                with self.subTest(early=early,response=response[:30]), Server(handler) as server, cli(uri(server.port,"httpupgrade","none",ed=early)) as core:
                    try:
                        with socks_connect(core.port,80) as connection: self.assertEqual(connection.recv(100),b"")
                    except (ConnectionError,EOFError,AssertionError) as error:
                        if "SOCKS CONNECT failed" not in str(error) and not isinstance(error,(ConnectionError,EOFError)): raise

    def test_pending_upgrade_deadline_is_not_paused(self):
        def stalled(connection):
            request(connection)
            try:
                while connection.recv(8192): pass
            except OSError: pass
        for protocol in ("vless","trojan","vmess","shadowsocks"):
            with self.subTest(protocol=protocol), Server(stalled) as server, cli(uri(server.port,"httpupgrade","none",protocol=protocol,ed=1),extra=["--connect-timeout-ms","150"]) as core:
                started=time.monotonic()
                with socks_connect(core.port,80) as connection:
                    connection.settimeout(2)
                    self.assertEqual(connection.recv(1),b"")
                self.assertLess(time.monotonic()-started,1.5)

    def test_half_close_and_last_data(self):
        last=b"\x00\x00vless-core final reply"*1000
        for security in ("none","tls"):
            def finish(connection):
                request(connection); connection.sendall(RESPONSE)
                received=bytearray()
                while True:
                    block=connection.recv(8192)
                    if not block: break
                    received.extend(block)
                self.assertEqual(bytes(received)[26:],b"vless-core upload"*1000)
                connection.sendall(b"\x00\x00"+last)
            cert,_=certificate()
            with self.subTest(security=security), Server(finish,tls=security=="tls") as server:
                with cli(uri(server.port,"httpupgrade",security),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                    with socks_connect(core.port,80) as connection:
                        connection.sendall(b"vless-core upload"*1000); connection.shutdown(socket.SHUT_WR)
                        self.assertEqual(exact(connection,len(last)),last)
                        self.assertEqual(connection.recv(1),b"")

    def test_xray_last_reply_after_client_fin(self):
        payload=b"vless-core upload before FIN"*1024
        def finish(connection):
            self.assertEqual(exact(connection,len(payload)),payload)
            time.sleep(.05); connection.sendall(payload[::-1])
        cert,_=certificate()
        for security in ("none","tls"):
            with self.subTest(security=security),Server(finish) as target,xray_server("httpupgrade",security) as reference:
                with cli(uri(reference.port,"httpupgrade",security),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                    with socks_connect(core.port,target.port) as connection:
                        connection.sendall(payload); connection.shutdown(socket.SHUT_WR)
                        self.assertEqual(exact(connection,len(payload)),payload[::-1])
                        self.assertEqual(connection.recv(1),b"")

    def test_vmess_json_httpupgrade(self):
        config=dict(v="2",add="127.0.0.1",port=0,id=UUID,aid=0,scy="auto",net="httpupgrade",tls="",path="/vless-core",headers={"X-Fixture":"present"},ed=0)
        with Server() as target,xray_server("httpupgrade","none",protocol="vmess") as reference:
            config["port"]=reference.port
            value="vmess://"+base64.b64encode(json.dumps(config).encode()).decode()
            with cli(value) as core:
                with socks_connect(core.port,target.port) as connection: exchange(connection,b"\x00\x00VMess JSON HTTPUpgrade")

    def test_xray_server_first_without_application_upload(self):
        banner=b"\x00\x00vless-core server first"
        def greet(connection):
            connection.sendall(banner)
            self.assertEqual(exact(connection,4),b"done")
        cert,_=certificate()
        for protocol in ("vless","trojan","vmess","shadowsocks"):
            for security in ("none","tls"):
                with self.subTest(protocol=protocol,security=security),Server(greet) as target,xray_server("httpupgrade",security,protocol=protocol) as reference:
                    with cli(uri(reference.port,"httpupgrade",security,protocol=protocol),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                        with socks_connect(core.port,target.port) as connection:
                            self.assertEqual(exact(connection,len(banner)),banner); connection.sendall(b"done")

    def test_partial_upgrade_with_blocked_upload_keeps_reading(self):
        response_ready=threading.Event(); release=threading.Event(); sent=threading.Event()
        reply=b"\x00\x00reply while upload is blocked"
        def handler(connection):
            connection.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4096)
            _,body=request(connection)
            while len(body)<26: body+=connection.recv(4096)
            connection.sendall(RESPONSE[:20]); response_ready.set()
            self.assertTrue(sent.wait(2))
            connection.sendall(RESPONSE[20:]+b"\x00\x00"+reply)
            self.assertTrue(release.wait(3))
            while connection.recv(65536): pass
        with Server(handler) as server,cli(uri(server.port,"httpupgrade","none",ed=1)) as core:
            with socks_connect(core.port,80) as connection:
                self.assertTrue(response_ready.wait(2))
                connection.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,4096)
                def upload():
                    sent.set()
                    try: connection.sendall(b"vless-core upload"*262144)
                    except OSError: pass
                worker=threading.Thread(target=upload); worker.start()
                try:
                    self.assertEqual(exact(connection,len(reply)),reply)
                    self.assertTrue(worker.is_alive())
                finally:
                    release.set(); connection.shutdown(socket.SHUT_RDWR); worker.join(3)
                    self.assertFalse(worker.is_alive())

    def test_vless_encryption_and_vision(self):
        from test_xray import XrayTests
        from fixtures import KEY,PUBLIC_KEY
        helper=XrayTests()
        for security in ("none","tls"):
            for flow in ("","xtls-rprx-vision"):
                with self.subTest(security=security,flow=flow):
                    helper.transfer("httpupgrade",security,flow=flow,encryption=f"mlkem768x25519plus.random.1rtt.{PUBLIC_KEY}",decryption=f"mlkem768x25519plus.random.0s.{KEY}",tls_target=bool(flow))

    def test_paths_match_xray_url_path_escaping(self):
        for path in ("/with space/тест","relative","/literal%2Fpart","/query?keep=a%2Fb&other=+","/a!b'c(d)*","/query?z=2&ed=0&a=1","/with space/тест?ed=0","/empty?","/fragment?ed=0#part"):
            with self.subTest(path=path),Server() as target,xray_server("httpupgrade","none",path=path) as reference:
                with cli(uri(reference.port,"httpupgrade","none",path=path)) as core:
                    with socks_connect(core.port,target.port) as connection: exchange(connection,b"vless-core path compatibility")

    def test_tls_versions_fingerprints_and_trust(self):
        cert,_=certificate()
        for version in ("1.2","1.3"):
            with xray_server("httpupgrade","tls",tls_settings={"minVersion":version,"maxVersion":version}) as reference,Server() as target:
                for fingerprint in ("chrome","firefox","edge","qq","random","randomized"):
                    with self.subTest(version=version,fingerprint=fingerprint),cli(uri(reference.port,"httpupgrade","tls",fp=fingerprint),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                        with socks_connect(core.port,target.port) as connection: exchange(connection,b"vless-core HTTPUpgrade verified TLS")
                for policy in ("strict","insecure","tofu"):
                    from fixtures import PRIVATE
                    environment={"VLESS_CA_BUNDLE":str(cert),"VLESS_TLS_MODE":policy,"VLESS_XHTTP_PIN_FILE":str(PRIVATE/f"httpupgrade-pin-{version}")}
                    with self.subTest(version=version,policy=policy),cli(uri(reference.port,"httpupgrade","tls"),environment=environment) as core:
                        with socks_connect(core.port,target.port) as connection: exchange(connection,b"vless-core HTTPUpgrade trust")

    def test_concurrent_slow_client_and_resource_recovery(self):
        cert,_=certificate()
        def echo_once(connection): connection.sendall(exact(connection,65536))
        for protocol in ("vless","trojan","vmess","shadowsocks"):
            for security in ("none","tls"):
                with self.subTest(protocol=protocol,security=security),Server(echo_once) as target,xray_server("httpupgrade",security,protocol=protocol) as reference:
                    with cli(uri(reference.port,"httpupgrade",security,protocol=protocol),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                        descriptors=Path(f"/proc/{core.process.pid}/fd")
                        baseline=len(list(descriptors.iterdir()))
                        def transfer(index):
                            with socks_connect(core.port,target.port) as connection:
                                data=bytes([index])*65536
                                if index==0:
                                    connection.sendall(data); time.sleep(.05); self.assertEqual(exact(connection,len(data)),data)
                                else: exchange(connection,data)
                        for repetition in range(5):
                            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as workers: list(workers.map(transfer,range(16)))
                        until=time.monotonic()+2
                        while len(list(descriptors.iterdir()))>baseline:
                            self.assertLess(time.monotonic(),until,"HTTPUpgrade clients leaked descriptors"); time.sleep(.01)
                        self.assertIsNone(core.process.poll(),core.log)
