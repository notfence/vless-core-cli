import base64
import hashlib
import json
import struct
import threading
import time
import unittest
from fixtures import Server, certificate, cli, exact, exchange, socks_connect, uri, xray_server

def frame(opcode, payload=b"", final=True):
    header=bytes([(128 if final else 0)|opcode])
    if len(payload) < 126: header+=bytes([len(payload)])
    elif len(payload) <= 65535: header+=b"\x7e"+struct.pack("!H",len(payload))
    else: header+=b"\x7f"+struct.pack("!Q",len(payload))
    return header+payload

def client_frame(connection):
    header=exact(connection,2)
    if not header[0]&128 or not header[1]&128: raise AssertionError("invalid client WebSocket header")
    length=header[1]&127
    if length == 126: length=int.from_bytes(exact(connection,2),"big")
    elif length == 127: length=int.from_bytes(exact(connection,8),"big")
    if length > 16*1024*1024: raise AssertionError("excessive WebSocket payload")
    mask=exact(connection,4); payload=exact(connection,length)
    return header[0]&15,bytes(byte^mask[index%4] for index,byte in enumerate(payload))

def upgrade(connection, response=None):
    request=bytearray()
    while not request.endswith(b"\r\n\r\n"):
        request.extend(exact(connection,1))
        if len(request) > 32768: raise AssertionError("excessive upgrade headers")
    lines=request.decode().split("\r\n")
    headers=dict((key.lower(),value.strip()) for key,value in (line.split(":",1) for line in lines[1:] if line))
    key=headers["sec-websocket-key"]
    accept=base64.b64encode(hashlib.sha1((key+"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
    reply=b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "+accept+b"\r\n\r\n"
    connection.sendall(response(reply,headers,accept) if response else reply)
    return lines[0],headers

class WebSocketTests(unittest.TestCase):
    def test_invalid_upgrade_responses_are_rejected(self):
        cases={
            "version":lambda reply,headers,accept: reply.replace(b"HTTP/1.1",b"HTTP/potato"),
            "http10":lambda reply,headers,accept: reply.replace(b"HTTP/1.1",b"HTTP/1.0"),
            "connection-substring":lambda reply,headers,accept: reply.replace(b"Connection: Upgrade",b"Connection: notupgrade"),
            "upgrade-substring":lambda reply,headers,accept: reply.replace(b"Upgrade: websocket",b"Upgrade: notwebsocket"),
            "duplicate-accept":lambda reply,headers,accept: reply.replace(b"Sec-WebSocket-Accept: ",b"Sec-WebSocket-Accept: invalid\r\nSec-WebSocket-Accept: "),
            "extensions":lambda reply,headers,accept: reply[:-2]+b"Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n",
            "protocol":lambda reply,headers,accept: reply[:-2]+b"Sec-WebSocket-Protocol: unrequested\r\n\r\n",
            "invalid-header":lambda reply,headers,accept: reply[:-2]+b"Bad Header: value\r\n\r\n",
            "folded-header":lambda reply,headers,accept: reply[:-2]+b" X-Other: value\r\n\r\n",
            "accept-prefix":lambda reply,headers,accept: reply.replace(accept,accept+b"extra"),
            "nul":lambda reply,headers,accept: reply[:-2]+b"X-Other: value\x00tail\r\n\r\n",
        }
        for name,response in cases.items():
            def handler(connection):
                upgrade(connection,response)
                connection.sendall(frame(2,b"\x00\x00vless-core"))
                connection.recv(65536)
            with self.subTest(response=name), Server(handler) as server, cli(uri(server.port,"ws","none")) as core:
                with self.assertRaises((AssertionError,EOFError,ConnectionError)):
                    with socks_connect(core.port,80) as tunnel: exchange(tunnel,b"vless-core")
                self.assertIn("invalid WebSocket upgrade response",core.wait_log("invalid WebSocket upgrade response"))

    def test_upgrade_token_lists_and_subprotocol_agreement(self):
        for early in (0,16384):
            def response(reply,headers,accept):
                reply=reply.replace(b"Connection: Upgrade",b"Connection: keep-alive, UpGrAdE")
                if "sec-websocket-protocol" in headers:
                    reply=reply[:-2]+b"Sec-WebSocket-Protocol: "+headers["sec-websocket-protocol"].encode()+b"\r\n\r\n"
                return reply
            def handler(connection):
                _,headers=upgrade(connection,response)
                encoded=headers.get("sec-websocket-protocol")
                if encoded: request=base64.urlsafe_b64decode(encoded+"="*(-len(encoded)%4))
                else: _,request=client_frame(connection)
                self.assertEqual(request[26:],b"vless-core")
                connection.sendall(frame(2,b"\x00\x00"+request[26:]))
                opcode,data=client_frame(connection)
                self.assertEqual(opcode,8); connection.sendall(frame(8,data))
            with self.subTest(early=early), Server(handler) as server, cli(uri(server.port,"ws","none",ed=early)) as core:
                with socks_connect(core.port,80) as tunnel: exchange(tunnel,b"vless-core")

    def test_close_handshake_drains_existing_message(self):
        closed=threading.Event(); payload=b"vless-core upload before Close"*5000
        def handler(connection):
            upgrade(connection); opcode,request=client_frame(connection)
            self.assertEqual(opcode,2); self.assertEqual(request[26:],b"init")
            connection.sendall(frame(2,b"\x00\x00init")+frame(2,b"vless-core ",final=False))
            received=bytearray()
            while True:
                opcode,data=client_frame(connection)
                if opcode == 8:
                    self.assertEqual(bytes(received),payload)
                    connection.sendall(frame(0,b"final message")+frame(8,data)); closed.set(); return
                self.assertEqual(opcode,2); received.extend(data)
        with Server(handler) as server, cli(uri(server.port,"ws","none")) as core:
            with socks_connect(core.port,80) as tunnel:
                exchange(tunnel,b"init")
                tunnel.sendall(payload); tunnel.shutdown(1)
                self.assertEqual(exact(tunnel,len(b"vless-core final message")),b"vless-core final message")
                self.assertEqual(tunnel.recv(1),b"")
            self.assertTrue(closed.wait(1))
    def test_xray_early_data_and_headers(self):
        cert,_=certificate()
        for security in ("none","tls"):
            for early in (0,1,16384):
                with self.subTest(security=security,early=early), Server() as target, xray_server("ws",security) as reference:
                    parameters={"ed":early,"headers":json.dumps({"X-vless-core":"custom","User-Agent":"vless-core/ws"})}
                    with cli(uri(reference.port,"ws",security,**parameters),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                        with socks_connect(core.port,target.port) as tunnel:
                            exchange(tunnel,b"vless-core WebSocket early data"*1000)
                        self.assertIsNone(core.process.poll(),core.log)

    def test_heartbeat_uses_tls_owner(self):
        cert,_=certificate(); ping=threading.Event()
        def handler(connection):
            self.assertEqual(connection.selected_alpn_protocol(),"http/1.1")
            upgrade(connection); opcode,request=client_frame(connection)
            self.assertEqual(opcode,2)
            connection.sendall(frame(2,b"\x00\x00"+request[26:]))
            opcode,payload=client_frame(connection)
            self.assertEqual(opcode,9); ping.set(); connection.sendall(frame(10,payload))
            opcode,payload=client_frame(connection)
            self.assertEqual(opcode,2); connection.sendall(frame(2,payload))
        with Server(handler,tls=True) as server, cli(uri(server.port,"ws","tls",heartbeatPeriod=1,alpn="http/1.1"),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
            with socks_connect(core.port,80) as tunnel:
                exchange(tunnel,b"init")
                self.assertTrue(ping.wait(3))
                exchange(tunnel,b"vless-core TLS heartbeat")

    def test_early_data_boundaries_are_not_duplicated(self):
        payload=b"vless-core no duplicate data"
        for early in (0,1,26+len(payload)-1,26+len(payload),26+len(payload)+1,16384):
            captured=[]
            def handler(connection):
                line,headers=upgrade(connection); captured.append(headers)
                self.assertEqual(line,"GET /vless-core?custom=1 HTTP/1.1")
                self.assertEqual(headers["x-vless-core"],"custom")
                self.assertEqual(headers["user-agent"],"vless-core/ws")
                encoded=headers.get("sec-websocket-protocol")
                if encoded:
                    self.assertNotIn("=",encoded)
                    request=base64.urlsafe_b64decode(encoded+"="*(-len(encoded)%4))
                else:
                    opcode,request=client_frame(connection); self.assertEqual(opcode,2)
                self.assertEqual(request[26:],payload)
                self.assertEqual(bool(encoded),early >= len(request))
                connection.sendall(frame(2,b"\x00\x00"+request[26:]))
                while True:
                    opcode,data=client_frame(connection)
                    if opcode == 2: connection.sendall(frame(2,data))
                    elif opcode == 8: connection.sendall(frame(8,data)); return
            with self.subTest(early=early), Server(handler) as server:
                parameters={"ed":early,"path":"/vless-core?ed=4096&custom=1","headers":json.dumps({"X-vless-core":"custom","User-Agent":"vless-core/ws"})}
                with cli(uri(server.port,"ws","none",**parameters)) as core:
                    with socks_connect(core.port,80) as tunnel:
                        exchange(tunnel,payload)
                        exchange(tunnel,b"vless-core second message")
                self.assertEqual(len(captured),1)

    def test_heartbeat_and_fragmented_input_do_not_block_upload(self):
        ping=threading.Event(); part=threading.Event()
        def handler(connection):
            upgrade(connection); opcode,request=client_frame(connection)
            self.assertEqual(opcode,2); self.assertTrue(request.startswith(b"\x00"))
            self.assertEqual(request[26:],b"init")
            connection.sendall(frame(2,b"\x00\x00"+request[26:]))
            opcode,payload=client_frame(connection)
            self.assertEqual(opcode,9); self.assertEqual(payload,b""); ping.set()
            connection.sendall(frame(10)+b"\x82\x05a"); part.set()
            opcode,payload=client_frame(connection)
            self.assertEqual((opcode,payload),(2,b"vless-core upload"))
            connection.sendall(b"bcde")
        with Server(handler) as server, cli(uri(server.port,"ws","none",heartbeatPeriod=1)) as core:
            with socks_connect(core.port,80) as tunnel:
                exchange(tunnel,b"init")
                self.assertTrue(ping.wait(3)); self.assertTrue(part.wait(1))
                self.assertEqual(exact(tunnel,1),b"a")
                tunnel.sendall(b"vless-core upload")
                self.assertEqual(exact(tunnel,4),b"bcde")

    def test_delayed_upgrade_stays_within_deadline(self):
        def handler(connection):
            exact(connection,1); time.sleep(0.3)
        with Server(handler) as server, cli(uri(server.port,"ws","none",ed=16384),extra=["--connect-timeout-ms","100"]) as core:
            started=time.monotonic()
            with socks_connect(core.port,80) as tunnel:
                tunnel.sendall(b"vless-core start upgrade")
                self.assertEqual(tunnel.recv(1),b"")
            self.assertLess(time.monotonic()-started,0.5)
