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
from fixtures import BUILD, OPENSSL, XRAY, PRIVATE, KEY, PUBLIC_KEY, Process, Server, CountingProxy, certificate, cli, exact, exchange, port, socks_connect, uri, xray_client, xray_server

ENCRYPTION_VISION_CASES = [("tcp",security,None) for security in ("none","tls","reality")]
ENCRYPTION_VISION_CASES += [("ws",security,None) for security in ("none","tls")]
ENCRYPTION_VISION_CASES += [("grpc",security,None) for security in ("none","tls","reality")]
ENCRYPTION_VISION_CASES += [("xhttp","none","packet-up"),("xhttp","tls","packet-up"),("xhttp","reality","stream-one")]

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
    def test_ws_xhttp_escaped_paths_interoperate(self):
        cert,_=certificate()
        server_path="/vless core/тест"
        client_path=server_path+"?name=a b&keep=%2F"
        for transport in ("ws","xhttp"):
            for security in (("none","tls") if transport == "ws" else ("none","tls","reality")):
                protocols=("h2","http/1.1") if transport == "xhttp" and security == "tls" else (None,)
                for protocol in protocols:
                    parameters={"path":client_path}
                    if protocol: parameters["alpn"]=protocol
                    with self.subTest(transport=transport,security=security,alpn=protocol), Server() as target, xray_server(transport,security,path=server_path) as reference:
                        with CountingProxy(reference.port) as captured, cli(uri(captured.port,transport,security,**parameters),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                            with socks_connect(core.port,target.port) as tunnel: exchange(tunnel,b"vless-core escaped path")
                            if security == "none":
                                requests=[bytes(data).split(b"\r\n",1)[0] for data in captured.client_data]
                                self.assertTrue(any(b"/vless%20core/%D1%82%D0%B5%D1%81%D1%82" in request for request in requests),requests)
                                self.assertTrue(any(b"keep=%2F" in request for request in requests),requests)

    def test_ws_xhttp_preserve_encoded_path_separator(self):
        for transport in ("ws","xhttp"):
            with self.subTest(transport=transport), Server() as target, xray_server(transport,"none",path="/vless/core") as reference:
                with cli(uri(reference.port,transport,"none",path="/vless%2Fcore")) as core:
                    with socks_connect(core.port,target.port) as tunnel: exchange(tunnel,b"vless-core encoded separator")

    def test_http1_stream_upload_invalid_ack_aborts_session(self):
        acknowledged=threading.Event()
        def handler(connection):
            request=bytearray()
            while not request.endswith(b"\r\n\r\n"): request.extend(exact(connection,1))
            if request.startswith(b"GET "):
                self.assertTrue(acknowledged.wait(2))
                connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n\x00\x00vless-core")
                connection.recv(1); return
            self.assertTrue(request.startswith(b"POST "))
            connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\nx")
            acknowledged.set()
            while True:
                line=bytearray()
                while not line.endswith(b"\r\n"): line.extend(exact(connection,1))
                size=int(line,16)
                exact(connection,size+2)
                if not size: return
        with Server(handler) as server, cli(uri(server.port,"xhttp","none",mode="stream-up")) as core:
            with self.assertRaises((AssertionError,EOFError,ConnectionError)):
                with socks_connect(core.port,80) as tunnel: exchange(tunnel,b"vless-core")
            self.assertIn("upload response failed",core.log)

    def test_http1_post_response_is_fully_validated(self):
        responses=[
            (True,b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
            (True,b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nvless-core"),
            (False,b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\nx"),
            (False,b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nTransfer-Encoding: chunked\r\n\r\na\r\nvless-core\r\n0\r\n\r\n"),
            (False,b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nvless-core"),
            (False,b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\najunk\r\nvless-core\r\n0\r\n\r\n"),
            (True,b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na;vless-core=yes\r\nvless-core\r\n0\r\nX-Result: ok\r\n\r\n"),
        ]
        cert,_=certificate()
        for security in ("none","tls"):
            for valid,response in responses:
                def handler(connection):
                    request=bytearray()
                    while not request.endswith(b"\r\n\r\n"): request.extend(exact(connection,1))
                    if request.startswith(b"GET "): connection.recv(1); return
                    self.assertTrue(request.startswith(b"POST "))
                    self.assertEqual(exact(connection,10),b"vless-core")
                    for offset in range(0,len(response),3): connection.sendall(response[offset:offset+3])
                    if security == "tls": connection.unwrap()
                with self.subTest(security=security,valid=valid,response=response), Server(handler,tls=security == "tls") as server:
                    result=subprocess.run([str(BUILD/"test_tls"),"--xhttp-post",uri(server.port,"xhttp",security,mode="packet-up",alpn="http/1.1")],env=dict(os.environ,VLESS_CA_BUNDLE=str(cert)),capture_output=True,text=True,timeout=5)
                    self.assertEqual(result.returncode,0 if valid else 1,result.stdout+result.stderr)

    def test_duplex_backpressure_does_not_block_reply(self):
        payload=bytes(range(251))*66842; failures=[]; cert,_=certificate()
        def handler(connection):
            connection.settimeout(5); connection.sendall(payload[::-1])
            self.assertEqual(exact(connection,len(payload)),payload); connection.sendall(b"done")
        for transport,security in (("tcp","none"),("tcp","tls"),("ws","tls"),("xhttp","none"),("xhttp","tls"),("xhttp","reality")):
            with self.subTest(transport=transport,security=security), Server(handler) as target, xray_server(transport,security) as reference:
                with cli(uri(reference.port,transport,security),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                    with socks_connect(core.port,target.port) as tunnel:
                        tunnel.settimeout(5)
                        def upload():
                            try: tunnel.sendall(payload)
                            except OSError as error: failures.append(error)
                        sender=threading.Thread(target=upload); sender.start()
                        try:
                            self.assertEqual(exact(tunnel,len(payload)),payload[::-1]); self.assertEqual(exact(tunnel,4),b"done")
                        finally: sender.join(timeout=6)
                        self.assertFalse(sender.is_alive()); self.assertFalse(failures)

    def test_transport_finish_write_preserves_response(self):
        payload=bytes(range(251))*521
        def handler(connection):
            self.assertEqual(exact(connection,len(payload)),payload)
            time.sleep(0.05)
            connection.sendall(payload[::-1])
        cert,_=certificate()
        cases=[("tcp","none",None,None),("tcp","tls",None,None),("tcp","reality",None,None),
               ("grpc","none",None,None),("grpc","tls",None,None),("grpc","reality",None,None),
               ("xhttp","none","stream-one",None),("xhttp","none","stream-up",None),
               ("xhttp","tls","stream-one",None),("xhttp","reality","stream-one",None),
               ("xhttp","tls","stream-one","http/1.1"),("xhttp","tls","stream-up","http/1.1")]
        for transport,security,mode,alpn in cases:
            with self.subTest(transport=transport,security=security,mode=mode,alpn=alpn), Server(handler) as target, xray_server(transport,security,mode=mode) as reference:
                parameters={}
                if mode: parameters["mode"]=mode
                if alpn: parameters["alpn"]=alpn
                with cli(uri(reference.port,transport,security,**parameters),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                    try:
                        with socks_connect(core.port,target.port) as tunnel:
                            tunnel.settimeout(3); tunnel.sendall(payload); tunnel.shutdown(socket.SHUT_WR)
                            self.assertEqual(exact(tunnel,len(payload)),payload[::-1])
                            self.assertEqual(tunnel.recv(1),b"")
                    except (EOFError,TimeoutError,AssertionError) as error:
                        raise AssertionError(f"{error}\n{core.log}\n{reference.log}") from error

    def test_encryption_fin_preserves_response(self):
        payload=bytes(range(251))*521
        def handler(connection):
            self.assertEqual(exact(connection,len(payload)),payload)
            time.sleep(0.05); connection.sendall(payload[::-1])
        for transport,security,mode,rtt in (("tcp","none",None,"0rtt"),("tcp","none",None,"1rtt"),
                                            ("grpc","none",None,"0rtt"),("xhttp","none","stream-one","0rtt"),
                                            ("xhttp","none","packet-up","1rtt")):
            with self.subTest(transport=transport,mode=mode,rtt=rtt), Server(handler) as target, xray_server(transport,security,mode=mode,decryption=f"mlkem768x25519plus.random.600s.{KEY}") as reference:
                parameters={"encryption":f"mlkem768x25519plus.random.{rtt}.{PUBLIC_KEY}"}
                if mode: parameters["mode"]=mode
                with cli(uri(reference.port,transport,security,**parameters)) as core:
                    for _ in range(2):
                        with socks_connect(core.port,target.port) as tunnel:
                            tunnel.sendall(payload); tunnel.shutdown(socket.SHUT_WR)
                            self.assertEqual(exact(tunnel,len(payload)),payload[::-1])

    def test_vision_fin_preserves_tls_response(self):
        payload=bytes(range(251))*521; cert,_=certificate()
        def handler(connection):
            self.assertEqual(exact(connection,len(payload)),payload)
            time.sleep(0.05); connection.sendall(payload[::-1])
        for security,encrypted in (("tls",False),("reality",False),("reality",True)):
            with self.subTest(security=security,encrypted=encrypted), Server(handler,tls=True) as target, xray_server("tcp",security,flow="xtls-rprx-vision",decryption=f"mlkem768x25519plus.random.0s.{KEY}" if encrypted else "none") as reference:
                parameters={"flow":"xtls-rprx-vision"}
                if encrypted: parameters["encryption"]=f"mlkem768x25519plus.random.1rtt.{PUBLIC_KEY}"
                with cli(uri(reference.port,"tcp",security,**parameters),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                    with socks_connect(core.port,target.port) as tunnel:
                        context=ssl.create_default_context(cafile=str(cert))
                        with context.wrap_socket(tunnel,server_hostname="vless-core.test") as secured:
                            secured.sendall(payload)
                            with socket.socket(fileno=os.dup(secured.fileno())) as ending: ending.shutdown(socket.SHUT_WR)
                            self.assertEqual(exact(secured,len(payload)),payload[::-1])

    def test_packet_upload_fin_keeps_download_channel(self):
        payload=bytes(range(251))*521
        def handler(connection):
            self.assertEqual(exact(connection,len(payload)),payload)
            connection.sendall(payload[::-1])
        cert,_=certificate()
        for security,pooled in (("none",False),("none",True),("tls",False),("tls",True),("reality",False),("reality",True)):
            with self.subTest(security=security,pooled=pooled), Server(handler) as target, xray_server("xhttp",security,mode="packet-up") as reference:
                parameters={"mode":"packet-up"}
                if pooled: parameters["extra"]=json.dumps({"xmux":{"maxConnections":1}})
                with cli(uri(reference.port,"xhttp",security,**parameters),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                    with socks_connect(core.port,target.port) as tunnel:
                        tunnel.settimeout(3); tunnel.sendall(payload); tunnel.shutdown(socket.SHUT_WR)
                        self.assertEqual(exact(tunnel,len(payload)),payload[::-1])

    def test_grpc_reuses_physical_connection(self):
        with Server() as target, xray_server("grpc","none") as reference, CountingProxy(reference.port) as proxy:
            with cli(uri(proxy.port,"grpc","none")) as core:
                for index in range(6):
                    try:
                        with socks_connect(core.port,target.port) as tunnel: exchange(tunnel,b"vless-core pooled gRPC"*20+bytes([index]))
                    except (EOFError,TimeoutError,AssertionError) as error:
                        raise AssertionError(f"{error}\n{core.log}\n{reference.log}\n{proxy.client_data}") from error
                self.assertEqual(len(proxy.client_data),1)

    def test_grpc_pool_parallel_and_small_windows(self):
        cert,_=certificate()
        for security,mode in (("none","gun"),("tls","gun"),("tls","multi"),("reality","gun")):
            with self.subTest(security=security,mode=mode), Server() as target, xray_server("grpc",security,mode=mode) as reference, CountingProxy(reference.port) as proxy:
                with cli(uri(proxy.port,"grpc",security,mode=mode,userAgent="vless-core/grpc"),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                    with socks_connect(core.port,target.port) as tunnel: exchange(tunnel,b"vless-core warm gRPC pool")
                    def transfer(index):
                        with socks_connect(core.port,target.port) as tunnel: exchange(tunnel,bytes(range(251))*1045+bytes([index]))
                    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor: list(executor.map(transfer,range(16)))
                    self.assertEqual(len(proxy.client_data),1)
        for window in (1,1024,262144):
            with self.subTest(window=window), Server() as target, xray_server("grpc","none") as reference:
                with cli(uri(reference.port,"grpc","none",initialWindowsSize=window)) as core:
                    with socks_connect(core.port,target.port) as tunnel: exchange(tunnel,b"vless-core")

    def test_grpc_slow_rpc_does_not_block_sibling(self):
        started=threading.Event()
        def handler(connection):
            command=exact(connection,1)
            if command == b"S":
                started.set(); connection.sendall(b"vless-core slow gRPC"*524288)
            else:
                connection.sendall(command); Server.echo(connection)
        with Server(handler) as target, xray_server("grpc","none") as reference, CountingProxy(reference.port) as proxy:
            with cli(uri(proxy.port,"grpc","none")) as core:
                with socks_connect(core.port,target.port) as slow:
                    slow.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4096); slow.sendall(b"S")
                    self.assertTrue(started.wait(2)); self.assertEqual(exact(slow,1),b"v")
                    time.sleep(0.2)
                    with socks_connect(core.port,target.port) as healthy:
                        for _ in range(3):
                            before=time.monotonic(); exchange(healthy,b"F"+bytes(range(251))*260)
                            self.assertLess(time.monotonic()-before,2)
                    self.assertEqual(len(proxy.client_data),1)

    def test_encryption_resumption_wire(self):
        payload=b"vless-core resumed encrypted connection"*64
        with Server() as target, xray_server("tcp","none",decryption=f"mlkem768x25519plus.native.60s.{KEY}") as reference, CountingProxy(reference.port) as proxy:
            with cli(uri(proxy.port,"tcp","none",encryption=f"mlkem768x25519plus.native.0rtt.{PUBLIC_KEY}")) as core:
                for index in range(3):
                    with socks_connect(core.port,target.port) as tunnel: exchange(tunnel,payload+bytes([index]))
                self.assertEqual(len(proxy.client_data),3)
                first,second,third=map(len,proxy.client_data)
                self.assertGreater(first,1300+len(payload))
                self.assertLess(second,len(payload)+200)
                self.assertLess(third,len(payload)+200)
                self.assertNotEqual(proxy.client_data[1][:48],proxy.client_data[2][:48])

    def test_encryption_resumption_skips_server_handshake_wait(self):
        for rtt in ("0rtt","1rtt"):
            with self.subTest(rtt=rtt), Server() as target, xray_server("tcp","none",decryption=f"mlkem768x25519plus.native.60s.{KEY}") as reference, CountingProxy(reference.port,first_response_delay=0.3) as proxy:
                with cli(uri(proxy.port,"tcp","none",encryption=f"mlkem768x25519plus.native.{rtt}.{PUBLIC_KEY}")) as core:
                    times=[]
                    for index in range(2):
                        started=time.monotonic()
                        with socks_connect(core.port,target.port) as tunnel:
                            times.append(time.monotonic()-started)
                            exchange(tunnel,b"vless-core delayed reference reply")
                    self.assertGreater(times[0],0.25)
                    if rtt == "0rtt": self.assertLess(times[1],0.2)
                    else: self.assertGreater(times[1],0.25)

    def test_encryption_resumption_modes_transports_and_parallel_clients(self):
        cert,_=certificate()
        for transport,security,mode in (("tcp","none","native"),("tcp","none","xorpub"),("tcp","none","random"),("ws","tls","random"),("xhttp","reality","native"),("grpc","tls","random")):
            with self.subTest(transport=transport,security=security,mode=mode), Server() as target, xray_server(transport,security,decryption=f"mlkem768x25519plus.{mode}.60s.{KEY}") as reference:
                with cli(uri(reference.port,transport,security,encryption=f"mlkem768x25519plus.{mode}.0rtt.{PUBLIC_KEY}"),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                    with socks_connect(core.port,target.port) as tunnel: exchange(tunnel,b"vless-core warm resumption cache")
                    def transfer(index):
                        with socks_connect(core.port,target.port) as tunnel: exchange(tunnel,b"vless-core concurrent resumption"*200+bytes([index]))
                    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                        list(executor.map(transfer,range(12)))

    def test_encryption_padding_chunks_and_deadline(self):
        padding="100-35-35.100-80-80.100-100-100"
        with Server() as target, xray_server("tcp","none",decryption=f"mlkem768x25519plus.native.0s.{KEY}") as reference, CountingProxy(reference.port) as proxy:
            with cli(uri(proxy.port,"tcp","none",encryption=f"mlkem768x25519plus.native.1rtt.{padding}.{PUBLIC_KEY}")) as core:
                started=time.monotonic()
                with socks_connect(core.port,target.port) as tunnel:
                    self.assertGreaterEqual(time.monotonic()-started,0.075)
                    exchange(tunnel,b"vless-core padding chunks")
                padding_end=16+32+18+1216+16+35+100
                self.assertEqual(proxy.client_data[0][padding_end:padding_end+3],b"\x17\x03\x03")
            with cli(uri(proxy.port,"tcp","none",encryption=f"mlkem768x25519plus.native.1rtt.100-35-35.100-1000-1000.{PUBLIC_KEY}"),extra=["--connect-timeout-ms","100"]) as core:
                started=time.monotonic()
                with self.assertRaises(AssertionError):
                    with socks_connect(core.port,target.port): pass
                self.assertLess(time.monotonic()-started,0.4)

    def test_manual_tls_hello_retry(self):
        cert,key=certificate()
        for group,fingerprint,stateless in (("P-256","chrome",False),("P-256","firefox",False),("P-384","chrome",False),("P-384","firefox",False),("P-521","firefox",False),("P-256","firefox",True)):
            with self.subTest(group=group,fingerprint=fingerprint,stateless=stateless):
                listen=port()
                command=[str(OPENSSL),"s_server","-accept",f"127.0.0.1:{listen}","-cert",str(cert),"-key",str(key),"-tls1_3","-groups",group,"-ciphersuites","TLS_CHACHA20_POLY1305_SHA256","-www"]
                if stateless: command.append("-stateless")
                with Process(command,"retry-server",{"OPENSSL_CONF":"/dev/null"},ready="ACCEPT") as server:
                    result=subprocess.run([str(BUILD/"test_tls_state"),uri(listen,"tcp","tls",fp=fingerprint)],env=dict(os.environ,VLESS_CA_BUNDLE=str(cert)),capture_output=True,text=True,timeout=15)
                    self.assertEqual(result.returncode,0,result.stdout+result.stderr+server.log)

    def test_xhttp_download_does_not_inherit_insecure_tls(self):
        shared={"sessionIDPlacement":"header","seqPlacement":"header"}
        for pooled in (False,True):
            with self.subTest(pooled=pooled), Server() as target, xray_server("xhttp","tls",path="/",**shared) as reference, CountingProxy(reference.port) as upload, CountingProxy(reference.port,address="127.0.0.2") as download:
                settings={"address":"127.0.0.2","port":download.port,"network":"xhttp","security":"tls","tlsSettings":{"serverName":"wrong-vless-core.test"},"xhttpSettings":{"path":"/download",**shared}}
                extra={"downloadSettings":settings,**shared}
                if pooled: extra["xmux"]={"maxConnections":1}
                cert,_=certificate()
                with cli(uri(upload.port,"xhttp","tls",mode="packet-up",allowInsecure=1,extra=json.dumps(extra)),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                    with self.assertRaises(AssertionError):
                        with socks_connect(core.port,target.port): pass
                    self.assertEqual(len(target.connections),0)

    def test_xhttp_download_independent_security(self):
        cert,_=certificate()
        shared={"sessionIDPlacement":"header","seqPlacement":"header"}
        for upload_tls,download_tls in ((True,False),(False,True)):
            for pooled in (False,True):
                with self.subTest(upload_tls=upload_tls,download_tls=download_tls,pooled=pooled), Server() as target, xray_server("xhttp","none",path="/",**shared) as reference, CountingProxy(reference.port,tls=upload_tls) as upload, CountingProxy(reference.port,address="127.0.0.2",tls=download_tls) as download:
                    settings={"address":"127.0.0.2","port":download.port,"network":"xhttp","security":"tls" if download_tls else "none","xhttpSettings":{"path":"/download",**shared}}
                    if download_tls: settings["tlsSettings"]={"serverName":"vless-core.test","alpn":["http/1.1"]}
                    extra={"downloadSettings":settings,**shared}
                    if pooled: extra["xmux"]={"maxConnections":1}
                    parameters={"mode":"packet-up","path":"/upload","extra":json.dumps(extra)}
                    if upload_tls: parameters["alpn"]="http/1.1"
                    with cli(uri(upload.port,"xhttp","tls" if upload_tls else "none",**parameters),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                        try:
                            with socks_connect(core.port,target.port) as tunnel: exchange(tunnel,b"vless-core separate security policies"*30)
                        except (EOFError,TimeoutError,AssertionError) as error:
                            raise AssertionError(f"{error}\n{core.log}\n{reference.log}") from error
                        self.assertGreaterEqual(len(upload.client_data),1)
                        self.assertGreaterEqual(len(download.client_data),1)

    def test_xhttp_independent_download_channel(self):
        cert,_=certificate()
        for security,alpn in (("none",None),("tls",None),("tls","http/1.1"),("reality",None)):
            for mode in ("packet-up","stream-up"):
                for pooled in (False,True):
                    shared={"sessionIDPlacement":"header","sessionIDKey":"X-vless-core-session","seqPlacement":"header"}
                    with self.subTest(security=security,alpn=alpn,mode=mode,pooled=pooled), Server() as target, xray_server("xhttp",security,path="/",**shared) as reference, CountingProxy(reference.port) as upload, CountingProxy(reference.port,address="127.0.0.2") as download:
                        settings={"address":"127.0.0.2","port":download.port,"network":"xhttp","security":security,"xhttpSettings":{"path":"/download","host":"vless-core-down.test","headers":{"X-vless-core-channel":"download"},"sessionIDTable":"HEX","sessionIDLength":8,**shared}}
                        if security == "tls": settings["tlsSettings"]={"serverName":"vless-core.test",**({"alpn":[alpn]} if alpn else {})}
                        if security == "reality": settings["realitySettings"]={"serverName":"vless-core.test","publicKey":PUBLIC_KEY,"shortId":"01020304","fingerprint":"firefox"}
                        extra={"headers":{"X-vless-core-channel":"upload"},"downloadSettings":settings,"sessionIDTable":"Base62","sessionIDLength":24,**shared}
                        if pooled: extra["xmux"]={"maxConnections":1}
                        parameters={"mode":mode,"path":"/upload","host":"vless-core-up.test","extra":json.dumps(extra)}
                        if alpn: parameters["alpn"]=alpn
                        with cli(uri(upload.port,"xhttp",security,**parameters),extra=["--server-ips","127.0.0.1"],environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                            for index in range(3):
                                with socks_connect(core.port,target.port) as tunnel: exchange(tunnel,b"vless-core independent download"*1000+bytes([index]))
                            self.assertGreaterEqual(len(upload.client_data),1)
                            self.assertGreaterEqual(len(download.client_data),1)
                            if security == "none":
                                up_data=b"\r\n".join(bytes(block).lower() for block in upload.client_data)
                                down_data=b"\r\n".join(bytes(block).lower() for block in download.client_data)
                                self.assertIn(b"host: vless-core-up.test\r\n",up_data)
                                self.assertIn(b"host: vless-core-down.test\r\n",down_data)
                                self.assertIn(b"x-vless-core-channel: download\r\n",down_data)
                                self.assertIn(b"get /download/",down_data)

    def test_xhttp_tokenish_padding_and_existing_query_metadata(self):
        for placement in ("header","queryInHeader","query","cookie"):
            extra={"xPaddingObfsMode":True,"xPaddingPlacement":placement,"xPaddingMethod":"tokenish","xPaddingBytes":"200-300","sessionIDPlacement":"query","seqPlacement":"query"}
            path="/vless-core?x_session=old&%78_session=second&fixed=vless-core"
            for security in ("none","reality"):
                for pooled in (False,True):
                    options={**extra,**({"xmux":{"maxConnections":1}} if pooled else {})}
                    with self.subTest(placement=placement,security=security,pooled=pooled), Server() as target, xray_server("xhttp",security,path=path,**extra) as reference:
                        with cli(uri(reference.port,"xhttp",security,mode="packet-up",path=path,extra=json.dumps(options))) as core:
                            with socks_connect(core.port,target.port) as tunnel: exchange(tunnel,b"vless-core tokenish padding"*1000)

    def test_xhttp_packet_pacing(self):
        for interval in (None,120):
            for pooled in (False,True):
                extra={"scMaxEachPostBytes":511}
                if interval is not None: extra["scMinPostsIntervalMs"]=interval
                if pooled: extra["xmux"]={"maxConnections":1}
                with self.subTest(interval=interval,pooled=pooled), Server() as target, xray_server("xhttp","none",mode="packet-up") as reference, CountingProxy(reference.port) as proxy:
                    with cli(uri(proxy.port,"xhttp","none",mode="packet-up",extra=json.dumps(extra))) as core:
                        with socks_connect(core.port,target.port) as tunnel: exchange(tunnel,b"vless-core paced packets"*150)
                        posts=[]; channels={}
                        for channel,instant,offset,size in proxy.client_reads:
                            previous=channels.get(id(channel),b""); combined=previous+bytes(channel[offset:offset+size])
                            start=0
                            while True:
                                index=combined.find(b"POST /vless-core/",start)
                                if index < 0: break
                                if index+len(b"POST /vless-core/") > len(previous): posts.append(instant)
                                start=index+1
                            channels[id(channel)]=combined
                        self.assertGreaterEqual(len(posts),7)
                        minimum=((interval if interval is not None else 30)-15)/1000
                        self.assertTrue(all(right-left >= minimum for left,right in zip(posts,posts[1:])),posts)

    def test_xhttp_custom_headers_and_grpc_policy(self):
        for mode in ("stream-one","stream-up","packet-up"):
            for no_grpc in (False,True):
                for pooled in (False,True):
                    extra={"headers":{"X-vless-core":"enabled","User-Agent":"vless-core/custom","Content-Type":"application/vless-core"},"noGRPCHeader":no_grpc}
                    if pooled: extra["xmux"]={"maxConnections":1}
                    with self.subTest(mode=mode,no_grpc=no_grpc,pooled=pooled), Server() as target, xray_server("xhttp","none") as reference, CountingProxy(reference.port) as proxy:
                        with cli(uri(proxy.port,"xhttp","none",mode=mode,extra=json.dumps(extra))) as core:
                            with socks_connect(core.port,target.port) as tunnel: exchange(tunnel,b"vless-core request headers"*1000)
                            captured=b"\r\n".join(bytes(block).lower() for block in proxy.client_data)
                            self.assertIn(b"x-vless-core: enabled\r\n",captured)
                            self.assertIn(b"user-agent: vless-core/custom\r\n",captured)
                            expected=b"content-type: application/vless-core\r\n" if no_grpc or mode == "packet-up" else b"content-type: application/grpc\r\n"
                            self.assertIn(expected,captured)
                            if no_grpc: self.assertNotIn(b"content-type: application/grpc\r\n",captured)

    def test_xhttp_extended_uplink_methods(self):
        for method in ("PUT","PATCH","DELETE"):
            for placement in ("body","header","cookie"):
                extra={"uplinkHTTPMethod":method,"uplinkDataPlacement":placement}
                for pooled in (False,True):
                    options={**extra,**({"xmux":{"maxConnections":1}} if pooled else {})}
                    with self.subTest(method=method,placement=placement,pooled=pooled), Server() as target, xray_server("xhttp","none",mode="packet-up",**extra) as reference, CountingProxy(reference.port) as proxy:
                        with cli(uri(proxy.port,"xhttp","none",mode="packet-up",extra=json.dumps(options))) as core:
                            with socks_connect(core.port,target.port) as tunnel: exchange(tunnel,b"vless-core HTTP methods"*500)
                            self.assertTrue(any(bytes(block).startswith(method.encode()+b" ") or b"\r\n"+method.encode()+b" " in bytes(block) for block in proxy.client_data))

    def test_xhttp_secure_custom_headers_and_methods(self):
        cert,_=certificate()
        for security,alpn in (("tls",None),("tls","http/1.1"),("reality",None)):
            for mode in ("stream-one","stream-up","packet-up"):
                for pooled in (False,True):
                    extra={"headers":{"X-vless-core":"enabled","Cookie":"vless-core=custom"},"noGRPCHeader":True,"uplinkHTTPMethod":"PUT","sessionIDPlacement":"cookie","seqPlacement":"cookie"}
                    if pooled: extra["xmux"]={"maxConnections":1}
                    options={"mode":mode,"extra":json.dumps(extra)}
                    if alpn: options["alpn"]=alpn
                    with self.subTest(security=security,alpn=alpn,mode=mode,pooled=pooled), Server() as target, xray_server("xhttp",security,sessionIDPlacement="cookie",seqPlacement="cookie") as reference:
                        with cli(uri(reference.port,"xhttp",security,**options),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                            with socks_connect(core.port,target.port) as tunnel: exchange(tunnel,bytes(range(256))*101)

    def test_xhttp_http1_streams_without_pooling(self):
        cert,_=certificate()
        for mode,channels in (("stream-one",1),("stream-up",2)):
            with self.subTest(mode=mode), Server() as target, xray_server("xhttp","tls") as reference, CountingProxy(reference.port) as proxy:
                with cli(uri(proxy.port,"xhttp","tls",mode=mode,alpn="http/1.1"),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                    for index in range(4):
                        with socks_connect(core.port,target.port) as tunnel: exchange(tunnel,f"vless-core unpooled {index}".encode())
                    self.assertEqual(len(proxy.client_data),channels*4)

    def test_xhttp_http2_connections_without_pooling(self):
        cert,_=certificate()
        for security in ("tls","reality"):
            for mode in ("stream-one","stream-up","packet-up"):
                with self.subTest(security=security,mode=mode), Server() as target, xray_server("xhttp",security,mode=mode) as reference, CountingProxy(reference.port) as proxy:
                    with cli(uri(proxy.port,"xhttp",security,mode=mode),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                        for index in range(4):
                            with socks_connect(core.port,target.port) as tunnel: exchange(tunnel,f"vless-core private {index}".encode())
                        self.assertEqual(len(proxy.client_data),4)

    def test_xhttp_payload_placements(self):
        cert,_=certificate()
        for placement in ("body","auto","header","cookie"):
            extra={"uplinkDataPlacement":placement,"uplinkDataKey":"vless-core-payload","uplinkChunkSize":64,"scMaxEachPostBytes":4093}
            for security,alpn in (("none",None),("tls",None),("tls","http/1.1"),("reality",None)):
                for pooled in (False,True):
                    options={**extra,**({"xmux":{"maxConnections":1}} if pooled else {})}
                    parameters={"mode":"packet-up","extra":json.dumps(options)}
                    if alpn: parameters["alpn"]=alpn
                    with self.subTest(placement=placement,security=security,alpn=alpn,pooled=pooled), Server() as target, xray_server("xhttp",security,mode="packet-up",**extra) as reference:
                        with cli(uri(reference.port,"xhttp",security,**parameters),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                            with socks_connect(core.port,target.port) as tunnel:
                                for size in (1023,1024,1025,12301): exchange(tunnel,(bytes(range(256))*49)[:size])

    def test_xhttp_large_payload_headers(self):
        cert,_=certificate()
        for placement in ("header","cookie"):
            extra={"uplinkDataPlacement":placement,"uplinkDataKey":"vless-core-payload","uplinkChunkSize":64000}
            for security in ("tls","reality"):
                for pooled in (False,True):
                    options={**extra,**({"xmux":{"maxConnections":1}} if pooled else {})}
                    with self.subTest(placement=placement,security=security,pooled=pooled), Server() as target, xray_server("xhttp",security,mode="packet-up",serverMaxHeaderBytes=65536,**extra) as reference:
                        with cli(uri(reference.port,"xhttp",security,mode="packet-up",extra=json.dumps(options)),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                            with socks_connect(core.port,target.port) as tunnel: exchange(tunnel,bytes(range(256))*193)

    def test_xhttp_payload_and_metadata_placements(self):
        for placement in ("header","cookie"):
            for metadata in ("header","query","cookie"):
                extra={"uplinkDataPlacement":placement,"uplinkChunkSize":128,"sessionIDPlacement":metadata,"seqPlacement":metadata}
                for security in ("none","reality"):
                    for pooled in (False,True):
                        options={**extra,**({"xmux":{"maxConnections":1}} if pooled else {})}
                        with self.subTest(placement=placement,metadata=metadata,security=security,pooled=pooled), Server() as target, xray_server("xhttp",security,mode="packet-up",**extra) as reference:
                            with cli(uri(reference.port,"xhttp",security,mode="packet-up",extra=json.dumps(options))) as core:
                                with socks_connect(core.port,target.port) as tunnel: exchange(tunnel,bytes(range(256))*17)

    def test_xhttp_custom_session_identifiers(self):
        extra={"sessionIDTable":"Base62","sessionIDLength":"16-32","sessionIDPlacement":"header","sessionIDKey":"X-vless-core-session"}
        for pooled in (False,True):
            options={**extra,**({"xmux":{"maxConnections":1}} if pooled else {})}
            with self.subTest(pooled=pooled), Server() as target, xray_server("xhttp","none",**extra) as reference, CountingProxy(reference.port) as proxy:
                with cli(uri(proxy.port,"xhttp","none",mode="packet-up",extra=json.dumps(options))) as core:
                    with socks_connect(core.port,target.port) as tunnel: exchange(tunnel,b"vless-core session identifiers"*1000)
                    identifiers=[]
                    for captured in proxy.client_data:
                        identifiers.extend(line.split(b": ",1)[1] for line in bytes(captured).split(b"\r\n") if line.startswith(b"X-vless-core-session: "))
                    self.assertGreaterEqual(len(identifiers),2)
                    self.assertEqual(len(set(identifiers)),1)
                    self.assertTrue(16 <= len(identifiers[0]) <= 32)
                    self.assertTrue(all(chr(byte).isalnum() and byte < 128 for byte in identifiers[0]))

    def test_xhttp_session_metadata_url_encoding(self):
        for placement in ("path","query"):
            extra={"sessionIDTable":"!?%+&","sessionIDLength":16,"sessionIDPlacement":placement,"seqPlacement":placement}
            for security in ("none","reality"):
                for pooled in (False,True):
                    options={**extra,**({"xmux":{"maxConnections":1}} if pooled else {})}
                    with self.subTest(placement=placement,security=security,pooled=pooled), Server() as target, xray_server("xhttp",security,path="/vless-core?fixed=1",**extra) as reference:
                        with cli(uri(reference.port,"xhttp",security,mode="packet-up",path="/vless-core?fixed=1",extra=json.dumps(options))) as core:
                            with socks_connect(core.port,target.port) as tunnel: exchange(tunnel,b"vless-core escaped session metadata"*1000)

    def test_xmux_reuses_physical_http2_connection(self):
        with Server() as target, xray_server("xhttp","reality") as reference:
            with CountingProxy(reference.port) as proxy:
                config=uri(proxy.port,"xhttp","reality",mode="stream-one",extra=json.dumps({"xmux":{"maxConnections":1}}))
                with cli(config) as core:
                    for index in range(4):
                        with socks_connect(core.port,target.port) as tunnel:
                            exchange(tunnel,b"vless-core XMUX reuse"*10000)
                    self.assertEqual(len(proxy.connections),1)

    def test_xmux_http1_packet_reuse(self):
        cert,_=certificate()
        for security in ("none","tls"):
            with self.subTest(security=security), Server() as target, xray_server("xhttp",security) as reference, CountingProxy(reference.port) as proxy:
                config=uri(proxy.port,"xhttp",security,mode="packet-up",alpn="http/1.1",extra=json.dumps({"xmux":{"maxConnections":1}}))
                with cli(config,environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                    with socks_connect(core.port,target.port) as tunnel:
                        for repetition in range(8): exchange(tunnel,b"vless-core HTTP/1.1 reused packet"*1000)
                    self.assertEqual(len(proxy.connections),2)

    def test_xmux_http1_parallel_channels(self):
        cert,_=certificate()
        payload=bytes(range(251))*1024
        for security in ("none","tls"):
            for mode in ("stream-one","stream-up","packet-up"):
                with self.subTest(security=security,mode=mode), Server() as target, xray_server("xhttp",security) as reference:
                    config=uri(reference.port,"xhttp",security,mode=mode,alpn="http/1.1",extra=json.dumps({"xmux":{"maxConnections":1}}))
                    with cli(config,environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                        def transfer(index):
                            with socks_connect(core.port,target.port) as tunnel:
                                exchange(tunnel,payload+bytes([index]))
                        for repetition in range(2):
                            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as workers:
                                list(workers.map(transfer,range(3)))
                        successes=[line.split(" id=",1)[1].split()[0] for line in core.log.splitlines() if "[probe] v=1" in line and "success=1" in line]
                        self.assertEqual(len(successes),6)
                        self.assertEqual(len(set(successes)),6)

    def test_reference_http1_fixture(self):
        for mode in ("stream-one","stream-up","packet-up"):
            with self.subTest(mode=mode), Server() as target, xray_server("xhttp","tls") as reference:
                with xray_client(reference.port,"xhttp","tls",mode=mode,alpn=["http/1.1"],fingerprint="unsafe") as client:
                    with socks_connect(client.port,target.port) as tunnel:
                        exchange(tunnel,b"vless-core reference HTTP/1.1"*10000)

    def test_xmux_rotation_limits(self):
        for settings, expected in (({"maxConnections":3},3),({"maxConnections":1,"cMaxReuseTimes":2},3),({"maxConnections":1,"hMaxRequestTimes":2},3)):
            with self.subTest(settings=settings), Server() as target, xray_server("xhttp","reality") as reference, CountingProxy(reference.port) as proxy:
                with cli(uri(proxy.port,"xhttp","reality",mode="stream-one",extra=json.dumps({"xmux":settings}))) as core:
                    for index in range(5):
                        with socks_connect(core.port,target.port) as tunnel: exchange(tunnel,b"vless-core rotation"*1024)
                    self.assertEqual(len(proxy.connections),expected)

    def test_xmux_rotation_keeps_active_streams(self):
        for settings, delay in (({"maxConnections":1,"cMaxReuseTimes":1},0),({"maxConnections":1,"hMaxReusableSecs":1},1.1),({"maxConcurrency":1},0)):
            with self.subTest(settings=settings), Server() as target, xray_server("xhttp","reality") as reference, CountingProxy(reference.port) as proxy:
                with cli(uri(proxy.port,"xhttp","reality",mode="stream-one",extra=json.dumps({"xmux":settings}))) as core:
                    with socks_connect(core.port,target.port) as first:
                        exchange(first,b"vless-core first active stream")
                        if delay: time.sleep(delay)
                        with socks_connect(core.port,target.port) as second:
                            exchange(second,b"vless-core second active stream")
                            exchange(first,b"vless-core first stream survives rotation")
                    self.assertEqual(len(proxy.connections),2)

    def test_xmux_slow_download_does_not_block_another_stream(self):
        payload=b"vless-core slow stream"*400000
        def handler(connection):
            marker=exact(connection,1)
            if marker == b"S": connection.sendall(payload)
            else: connection.sendall(marker); Server.echo(connection)
        with Server(handler) as target, xray_server("xhttp","reality") as reference:
            with cli(uri(reference.port,"xhttp","reality",mode="stream-one",extra=json.dumps({"xmux":{"maxConnections":1}}))) as core:
                with socks_connect(core.port,target.port) as slow:
                    slow.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,65536); slow.sendall(b"S")
                    time.sleep(0.1)
                    with socks_connect(core.port,target.port) as fast:
                        fast.settimeout(2); exchange(fast,b"vless-core fast stream"*10000)
                    self.assertEqual(exact(slow,len(payload)),payload)

    def test_xmux_transport_modes(self):
        for security in ("tls","reality"):
            for mode in ("stream-one","stream-up","packet-up"):
                with self.subTest(security=security,mode=mode):
                    self.transfer("xhttp",security,mode,extra={"xmux":{"maxConnections":1}})

    def test_xmux_parallel_clients(self):
        payload=bytes(range(251))*4096
        cert,_=certificate()
        for security in ("tls","reality"):
            for mode in ("stream-one","stream-up","packet-up"):
                with self.subTest(security=security,mode=mode), Server() as target, xray_server("xhttp",security) as reference:
                    config=uri(reference.port,"xhttp",security,mode=mode,extra=json.dumps({"xmux":{"maxConnections":1}}))
                    with cli(config,environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                        def transfer(index):
                            with socks_connect(core.port,target.port) as tunnel:
                                exchange(tunnel,payload+bytes([index]))
                        for repetition in range(3):
                            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as workers:
                                list(workers.map(transfer,range(4)))

    def test_xmux_new_clients_during_continuous_upload(self):
        def receive(connection):
            while connection.recv(16384): time.sleep(0.001)
        cert,_=certificate()
        for security in ("tls","reality"):
            with self.subTest(security=security), Server(receive) as receiver, Server() as target, xray_server("xhttp",security) as reference:
                config=uri(reference.port,"xhttp",security,mode="stream-one",extra=json.dumps({"xmux":{"maxConnections":1}}))
                with cli(config,extra=["--connect-timeout-ms","1000"],environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                    with socks_connect(core.port,receiver.port) as background:
                        stopped=threading.Event(); started=threading.Event(); errors=[]
                        def upload():
                            try:
                                while not stopped.is_set(): background.sendall(b"vless-core continuous upload"*4000); started.set()
                            except OSError as error:
                                if not stopped.is_set(): errors.append(error)
                        worker=threading.Thread(target=upload,daemon=True); worker.start()
                        try:
                            self.assertTrue(started.wait(2)); time.sleep(0.05)
                            for repetition in range(5):
                                with socks_connect(core.port,target.port) as tunnel: exchange(tunnel,b"vless-core independent setup")
                        finally:
                            stopped.set(); background.shutdown(socket.SHUT_RDWR); worker.join(timeout=2)
                        self.assertFalse(worker.is_alive())
                        self.assertFalse(errors,errors)
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
                        if "xmux" in extra:
                            for warmup in range(3):
                                with socks_connect(core.port,target.port): pass
                            previous=None; stable=time.monotonic(); end=stable+2
                            while True:
                                now=time.monotonic(); state=(len(list(descriptors.iterdir())),len(list(tasks.iterdir())))
                                if state != previous: previous=state; stable=now
                                if now-stable >= 0.1: break
                                self.assertLess(now,end,"XMUX warmup did not release client workers")
                                time.sleep(0.01)
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

                reports = [line.split("[probe] ",1)[1] for line in core.log.splitlines() if "[probe] " in line]
                self.assertTrue(reports,core.log)
                result = dict(field.split("=",1) for field in reports[-1].split())
                self.assertEqual((result["v"],result["success"],result["stage"]),("1","1","none"))
                for field in ("dns_ms","tcp_ms","transport_ms","protocol_ms","carry_ms","total_ms"):
                    self.assertGreaterEqual(int(result[field]),0,(field,core.log))

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
                        received = bytearray(); response_stream=None
                        while not received.endswith(request):
                            kind, _, stream, payload = read_frame(connection)
                            if kind == 0:
                                if response_stream is None: response_stream=stream
                                self.assertEqual(stream,response_stream)
                                self.assertTrue(stream&1)
                                if not received:
                                    self.assertTrue(payload.startswith(b"\x00"))
                                received.extend(payload)
                        def frame(kind, flags, payload, stream=None):
                            return len(payload).to_bytes(3,"big")+bytes([kind,flags])+(response_stream if stream is None else stream).to_bytes(4,"big")+payload
                        data = b"\x00\x00"+reply
                        trailer = b""
                        response_block=block
                        if transport == "grpc":
                            message = b"\x0a"+bytes([len(data)])+data
                            data = b"\x00"+len(message).to_bytes(4,"big")+message
                            trailer = frame(1,5,b"\x00\x0bgrpc-status\x010")
                            response_block += b"\x00\x0ccontent-type\x10application/grpc"
                        headers = frame(1,0,response_block[:1])+frame(9,4,response_block[1:]) if fragmented else frame(1,4,response_block)
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
                            expected = "invalid h2 header block" if status is None else f"non-200: {status}"
                            self.assertIn(expected,core.log)
                        self.assertIsNone(core.process.poll(),core.log)

    def test_xhttp_h2_header_only_response(self):
        first = threading.Event()
        first_payload, second_payload = b"vless-core first", b"vless-core second"
        reply = b"vless-core complete"
        def handler(connection):
            pending=bytearray(); response_stream=None
            def read_data(length):
                nonlocal response_stream
                while len(pending) < length:
                    header=exact(connection,9); size=int.from_bytes(header[:3],"big")
                    self.assertLessEqual(size,16384)
                    payload=exact(connection,size)
                    if header[3] == 0:
                        stream=int.from_bytes(header[5:],"big")
                        if response_stream is None: response_stream=stream
                        self.assertEqual(stream,response_stream); pending.extend(payload)
                result=bytes(pending[:length]); del pending[:length]; return result
            self.assertEqual(exact(connection,24),b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            self.assertEqual(read_data(26)[0],0)
            def frame(kind, flags, payload, stream=None):
                return len(payload).to_bytes(3,"big")+bytes([kind,flags])+(response_stream if stream is None else stream).to_bytes(4,"big")+payload
            connection.sendall(frame(4,0,b"",0)+frame(1,4,b"\x88")+frame(0,0,b"\x00\x00"))
            self.assertEqual(read_data(len(first_payload)),first_payload)
            first.set()
            self.assertEqual(read_data(len(second_payload)),second_payload)
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

    def test_encryption_vision_transport_matrix(self):
        cert,_=certificate(); context=ssl.create_default_context(cafile=str(cert)); payload=bytes(range(251))*1045
        def finish(connection):
            while True:
                data=connection.recv(65536)
                if not data: break
                connection.sendall(data)
            raw=connection.unwrap(); raw.shutdown(socket.SHUT_WR); raw.close()
        for transport,security,mode in ENCRYPTION_VISION_CASES:
            for encryption_mode in ("native","xorpub","random"):
                for rtt in ("0rtt","1rtt"):
                    with self.subTest(transport=transport,security=security,mode=mode,encryption=encryption_mode,rtt=rtt):
                        with Server(finish,tls=True) as target, xray_server(transport,security,mode,flow="xtls-rprx-vision",decryption=f"mlkem768x25519plus.{encryption_mode}.60s.{KEY}") as reference:
                            config=uri(reference.port,transport,security,mode=mode or "auto",flow="xtls-rprx-vision",encryption=f"mlkem768x25519plus.{encryption_mode}.{rtt}.{PUBLIC_KEY}")
                            with cli(config,environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                                try:
                                    for connection_index in range(2):
                                        with socks_connect(core.port,target.port) as connection:
                                            with context.wrap_socket(connection,server_hostname="vless-core.test") as tunnel:
                                                exchange(tunnel,b"vless-core encryption vision")
                                                exchange(tunnel,payload)
                                                raw=tunnel.unwrap(); raw.shutdown(socket.SHUT_WR)
                                                with raw: self.assertEqual(raw.recv(1),b"")
                                    self.assertIsNone(core.process.poll(),core.log)
                                except BaseException as error: raise AssertionError(f"{transport}/{security}/{mode}/{encryption_mode}/{rtt}: {error}\n{core.log}\n{reference.log}") from error

    def test_encryption_vision_reference_matrix(self):
        cert,_=certificate(); context=ssl.create_default_context(cafile=str(cert))
        for transport,security,mode in ENCRYPTION_VISION_CASES:
            with self.subTest(transport=transport,security=security,mode=mode), Server(tls=True) as target:
                with xray_server(transport,security,mode,flow="xtls-rprx-vision",decryption=f"mlkem768x25519plus.native.60s.{KEY}") as reference:
                    with xray_client(reference.port,transport,security,mode,flow="xtls-rprx-vision",encryption=f"mlkem768x25519plus.native.0rtt.{PUBLIC_KEY}") as client:
                        for connection_index in range(2):
                            with socks_connect(client.port,target.port) as connection, context.wrap_socket(connection,server_hostname="vless-core.test") as tunnel:
                                exchange(tunnel,b"vless-core reference encryption vision")
                                exchange(tunnel,bytes(range(251))*1045)

    def test_packet_up_encryption_repeated_handshakes(self):
        cert,_=certificate(); context=ssl.create_default_context(cafile=str(cert)); payload=bytes(range(251))*1045
        def finish(connection):
            while True:
                data=connection.recv(65536)
                if not data: break
                connection.sendall(data)
            raw=connection.unwrap(); raw.shutdown(socket.SHUT_WR); raw.close()
        for rtt in ("0rtt","1rtt"):
            with self.subTest(rtt=rtt), Server(finish,tls=True) as target:
                with xray_server("xhttp","tls","packet-up",flow="xtls-rprx-vision",decryption=f"mlkem768x25519plus.native.60s.{KEY}") as reference:
                    with cli(uri(reference.port,"xhttp","tls",mode="packet-up",flow="xtls-rprx-vision",encryption=f"mlkem768x25519plus.native.{rtt}.{PUBLIC_KEY}"),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                        try:
                            for connection_index in range(32):
                                with socks_connect(core.port,target.port) as connection, context.wrap_socket(connection,server_hostname="vless-core.test") as tunnel:
                                    exchange(tunnel,payload)
                                    raw=tunnel.unwrap(); raw.shutdown(socket.SHUT_WR)
                                    with raw: self.assertEqual(raw.recv(1),b"")
                            self.assertIsNone(core.process.poll(),core.log)
                        except BaseException as error: raise AssertionError(f"packet-up/{rtt}/{connection_index}: {error}\n{core.log}\n{reference.log}") from error

    def test_encryption_vision_stream_modes_and_finish(self):
        cert,_=certificate(); context=ssl.create_default_context(cafile=str(cert)); payload=bytes(range(251))*1045
        cases=[("grpc",security,"multi",None,False) for security in ("none","tls","reality")]
        cases += [("xhttp",security,mode,alpn,pooled) for security,alpn in (("tls",None),("tls","http/1.1"),("reality",None)) for mode in ("stream-one","stream-up","packet-up") for pooled in (False,True)]
        cases += [("tcp","none",None,None,False),("ws","none",None,None,False),("ws","tls",None,None,False)]
        def finish(connection):
            while True:
                data=connection.recv(65536)
                if not data: break
                connection.sendall(data)
            raw=connection.unwrap(); raw.shutdown(socket.SHUT_WR); raw.close()
        for transport,security,mode,alpn,pooled in cases:
            with self.subTest(transport=transport,security=security,mode=mode,alpn=alpn,pooled=pooled), Server(finish,tls=True) as target:
                with xray_server(transport,security,mode,flow="xtls-rprx-vision",decryption=f"mlkem768x25519plus.random.60s.{KEY}") as reference:
                    parameters={"flow":"xtls-rprx-vision","encryption":f"mlkem768x25519plus.random.0rtt.{PUBLIC_KEY}"}
                    if mode: parameters["mode"]=mode
                    if alpn: parameters["alpn"]=alpn
                    if pooled: parameters["extra"]=json.dumps({"xmux":{"maxConnections":1}})
                    with cli(uri(reference.port,transport,security,**parameters),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                        try:
                            for connection_index in range(2):
                                with socks_connect(core.port,target.port) as connection, context.wrap_socket(connection,server_hostname="vless-core.test") as tunnel:
                                    exchange(tunnel,payload)
                                    raw=tunnel.unwrap(); raw.shutdown(socket.SHUT_WR)
                                    with raw: self.assertEqual(raw.recv(1),b"")
                        except BaseException as error: raise AssertionError(f"{transport}/{security}/{mode}/{alpn}/{pooled}: {error}\n{core.log}\n{reference.log}") from error

    def test_parallel_protocol_load_and_resource_recovery(self):
        cert,_=certificate(); context=ssl.create_default_context(cafile=str(cert)); payload=bytes(range(251))*523
        cases=[("tcp","tls",None,{}),("ws","tls",None,{}),("grpc","tls","gun",{}),("grpc","tls","multi",{})]
        cases += [("xhttp","tls","packet-up",{"xmux":{"maxConnections":size}}) for size in (1,2,3)]
        cases += [("xhttp","reality","stream-one",dict(SUBSCRIPTION_EXTRA,
                   xmux=dict(SUBSCRIPTION_EXTRA["xmux"],maxConnections=size))) for size in (1,2,3)]
        def finish(connection):
            while True:
                data=connection.recv(65536)
                if not data: break
                connection.sendall(data)
            raw=connection.unwrap(); raw.shutdown(socket.SHUT_WR); raw.close()
        for transport,security,mode,extra in cases:
            pool_size=extra.get("xmux",{}).get("maxConnections",1)
            with self.subTest(transport=transport,security=security,mode=mode,pool_size=pool_size), Server(finish,tls=True) as target:
                server_extra=dict(extra); server_extra.pop("mode",None)
                with xray_server(transport,security,mode,flow="xtls-rprx-vision",decryption=f"mlkem768x25519plus.native.60s.{KEY}",**server_extra) as reference:
                    parameters={"flow":"xtls-rprx-vision","encryption":f"mlkem768x25519plus.native.0rtt.{PUBLIC_KEY}"}
                    if mode: parameters["mode"]=mode
                    if extra: parameters["extra"]=json.dumps(extra)
                    with cli(uri(reference.port,transport,security,**parameters),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                        descriptors=Path(f"/proc/{core.process.pid}/fd"); tasks=Path(f"/proc/{core.process.pid}/task")
                        def transfer(index):
                            with socks_connect(core.port,target.port) as connection, context.wrap_socket(connection,server_hostname="vless-core.test") as tunnel:
                                tunnel.settimeout(8); exchange(tunnel,payload)
                                raw=tunnel.unwrap(); raw.shutdown(socket.SHUT_WR)
                                with raw: self.assertEqual(raw.recv(1),b"")
                        for warmup in range(pool_size): transfer(warmup)
                        previous=None; stable=time.monotonic(); end=stable+3
                        while True:
                            now=time.monotonic(); state=(len(list(descriptors.iterdir())),len(list(tasks.iterdir())))
                            if state != previous: previous=state; stable=now
                            if now-stable >= 0.2: break
                            self.assertLess(now,end,"warmup did not release client resources"); time.sleep(0.02)
                        baseline_fds,baseline_tasks=state
                        try:
                            for repetition in range(5):
                                with concurrent.futures.ThreadPoolExecutor(max_workers=16) as workers: list(workers.map(transfer,range(16)))
                                end=time.monotonic()+3
                                while True:
                                    state=(len(list(descriptors.iterdir())),len(list(tasks.iterdir())))
                                    if state[0] <= baseline_fds and state[1] <= baseline_tasks: break
                                    self.assertLess(time.monotonic(),end,
                                                    f"parallel clients did not release resources after round {repetition+1}: "
                                                    f"fds={state[0]} (baseline={baseline_fds}), threads={state[1]} (baseline={baseline_tasks})")
                                    time.sleep(0.02)
                                self.assertIsNone(core.process.poll(),core.log)
                        except BaseException as error: raise AssertionError(f"{transport}/{security}/{mode}/pool={pool_size}: {error}\n{core.log}\n{reference.log}") from error

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

    def test_certificate_purpose_and_ip_identity(self):
        _,key=certificate()
        cases=(("DNS:vless-core.test","serverAuth","vless-core.test",True),
               ("DNS:vless-core.test","clientAuth","vless-core.test",False),
               ("IP:127.0.0.1","serverAuth","127.0.0.1",True),
               ("IP:::1","serverAuth","::1",True),
               ("IP:127.0.0.2","serverAuth","127.0.0.1",False))
        for index,(san,purpose,identity,accepted) in enumerate(cases):
            cert=PRIVATE/f"identity-{index}.pem"
            result=subprocess.run([str(OPENSSL),"req","-config","/dev/null","-new","-x509","-key",str(key),"-days","2","-subj","/CN=wrong-cn.test","-addext",f"subjectAltName={san}","-addext",f"extendedKeyUsage={purpose}","-addext","keyUsage=digitalSignature","-out",str(cert)],capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            for transport in ("tcp","ws","xhttp","grpc"):
                parameters={"sni":identity}
                with self.subTest(transport=transport,identity=identity,purpose=purpose), Server() as target, xray_server(transport,"tls",tls_certificate=cert) as reference, cli(uri(reference.port,transport,"tls",**parameters),environment={"VLESS_CA_BUNDLE":str(cert),"VLESS_TLS_MODE":"strict"}) as core:
                    if accepted:
                        with socks_connect(core.port,target.port) as tunnel: exchange(tunnel,b"vless-core identity")
                    else:
                        with self.assertRaises((AssertionError,EOFError,ConnectionError)):
                            with socks_connect(core.port,target.port) as tunnel: exchange(tunnel,b"vless-core identity")

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

    def test_optional_tls_client_certificate_request(self):
        cert,key=certificate(); listen_port=port()
        command=[str(OPENSSL),"s_server","-accept",f"127.0.0.1:{listen_port}","-cert",str(cert),"-key",str(key),"-tls1_3","-groups","X25519","-verify","1","-www"]
        with Process(command,"optional-client-certificate",ready="ACCEPT") as server:
            result=subprocess.run([str(BUILD/"test_tls_state"),uri(listen_port,"tcp","tls",fp="qq")],env=dict(os.environ,VLESS_CA_BUNDLE=str(cert)),capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr+server.log)

    def test_tls_failure_advances_to_next_pinned_address(self):
        cert,_=certificate()
        def broken(connection):
            connection.recv(4096); connection.sendall(b"not a TLS server"); connection.shutdown(socket.SHUT_WR)
        for transport,pooled in (("ws",False),("xhttp",False),("xhttp",True),("grpc",True)):
            parameters={"extra":json.dumps({"xmux":{"maxConnections":1}})} if pooled and transport == "xhttp" else {}
            with self.subTest(transport=transport,pooled=pooled), Server() as target, xray_server(transport,"tls") as reference, Server(broken) as bad, CountingProxy(reference.port,address="127.0.0.2",listen_port=bad.port) as good:
                with cli(uri(bad.port,transport,"tls",**parameters),extra=["--server-ips","127.0.0.1,127.0.0.2"],environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                    with socks_connect(core.port,target.port) as tunnel: exchange(tunnel,b"vless-core TLS address fallback")
                    self.assertTrue(bad.connections); self.assertTrue(good.connections)

    def test_tls_address_fallback_does_not_extend_deadline(self):
        cert,_=certificate()
        def stalled(connection):
            connection.recv(4096); time.sleep(0.3)
        with Server() as target, xray_server("ws","tls") as reference, Server(stalled) as bad, CountingProxy(reference.port,address="127.0.0.2",listen_port=bad.port) as good:
            with cli(uri(bad.port,"ws","tls"),extra=["--server-ips","127.0.0.1,127.0.0.2","--connect-timeout-ms","100"],environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                started=time.monotonic()
                with self.assertRaises((AssertionError,EOFError,ConnectionError)):
                    with socks_connect(core.port,target.port) as tunnel: exchange(tunnel,b"vless-core bounded TLS fallback")
                self.assertLess(time.monotonic()-started,0.6)
                self.assertFalse(good.connections)

    def test_required_tls_client_certificate_is_not_supported(self):
        cert,key=certificate(); listen_port=port()
        command=[str(OPENSSL),"s_server","-accept",f"127.0.0.1:{listen_port}","-cert",str(cert),"-key",str(key),"-tls1_3","-groups","X25519","-Verify","1","-www"]
        with Process(command,"required-client-certificate",ready="ACCEPT"), cli(uri(listen_port,"tcp","tls",fp="qq"),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
            with self.assertRaises((AssertionError,EOFError,ConnectionError)):
                with socks_connect(core.port,80) as tunnel: exchange(tunnel,b"vless-core no client certificate")

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
