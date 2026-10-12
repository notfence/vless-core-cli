import struct
import json
import socket
import threading
import time
import unittest
from fixtures import Server, cli, exact, exchange, socks_connect, uri

def frame(kind, flags=0, stream=0, payload=b""):
    return len(payload).to_bytes(3,"big")+bytes([kind,flags])+stream.to_bytes(4,"big")+payload

def envelope(payload):
    length=len(payload); varint=bytearray()
    while length >= 128: varint.append((length&127)|128); length>>=7
    varint.append(length)
    message=b"\x0a"+varint+payload
    return b"\x00"+len(message).to_bytes(4,"big")+message

def data_frames(stream, payload):
    return b"".join(frame(0,stream=stream,payload=payload[offset:offset+16384]) for offset in range(0,len(payload),16384))

def literal(name, value):
    name=name.encode(); value=value.encode()
    def size(length):
        if length < 127: return bytes([length])
        result=bytearray([127]); length-=127
        while length >= 128: result.append((length&127)|128); length>>=7
        return bytes(result+bytes([length]))
    return b"\x00"+size(len(name))+name+size(len(value))+value

GRPC_HEADERS=b"\x88"+literal("content-type","application/grpc")

def integer(data, offset, bits):
    value=data[offset]&((1<<bits)-1); offset+=1
    if value < (1<<bits)-1: return value,offset
    shift=0
    while True:
        byte=data[offset]; offset+=1; value+=(byte&127)<<shift
        if not byte&128: return value,offset
        shift+=7

def headers(block):
    values={}; offset=0
    while offset < len(block):
        if block[offset]&128:
            _,offset=integer(block,offset,7); continue
        if block[offset] != 0: raise AssertionError("unexpected client header representation")
        offset+=1; size,offset=integer(block,offset,7); name=block[offset:offset+size].decode(); offset+=size
        size,offset=integer(block,offset,7); value=block[offset:offset+size].decode(); offset+=size
        values[name]=value
    return values

def varint(data, offset):
    value=0; shift=0
    while True:
        byte=data[offset]; offset+=1; value|=(byte&127)<<shift
        if not byte&128: return value,offset
        shift+=7

class GrpcPeer(Server):
    def __init__(self, maximum=100, acknowledge=True, settings=None, responses=None):
        self.maximum=maximum; self.acknowledge=acknowledge
        self.server_settings=settings
        self.responses=responses or {}
        self.requests=[]; self.windows=[]; self.ping=threading.Event(); self.finished=threading.Event(); self.uploads=[]
        super().__init__(self.handle)

    def handle(self, connection):
        if exact(connection,24) != b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n": raise AssertionError("missing HTTP/2 preface")
        if self.server_settings is not False:
            connection.sendall(frame(4,payload=struct.pack("!HI",3,self.maximum) if self.server_settings is None else self.server_settings))
        streams={}
        while True:
            header=exact(connection,9); size=int.from_bytes(header[:3],"big")
            kind,flags=header[3:5]; stream=int.from_bytes(header[5:],"big")&0x7fffffff
            payload=exact(connection,size)
            if kind == 4 and not flags&1:
                settings=dict(struct.unpack("!HI",payload[i:i+6]) for i in range(0,size,6))
                with self.lock: self.windows.append(settings[4])
                connection.sendall(frame(4,1))
            elif kind == 1:
                with self.lock: self.requests.append((connection,stream,headers(payload)))
                streams[stream]={"buffer":bytearray(),"started":False,"responded":False,"ended":False}
            elif kind == 0:
                state=streams[stream]; state["buffer"].extend(payload)
                if size: connection.sendall(frame(8,payload=size.to_bytes(4,"big"))+frame(8,stream=stream,payload=size.to_bytes(4,"big")))
                while len(state["buffer"]) >= 5:
                    length=int.from_bytes(state["buffer"][1:5],"big")
                    if len(state["buffer"]) < length+5: break
                    message=bytes(state["buffer"][5:5+length]); del state["buffer"][:5+length]
                    if message[0] != 10: raise AssertionError("missing gRPC bytes field")
                    length,offset=varint(message,1); data=message[offset:offset+length]
                    if not state["started"]:
                        if len(data) < 26 or data[0] != 0: raise AssertionError("invalid VLESS request")
                        state["started"]=True; data=data[26:]
                    if not data: continue
                    with self.lock: self.uploads.append((stream,data))
                    if state["ended"]: continue
                    if data in self.responses:
                        response=self.responses[data]
                        block=b"\x88" if response.get("http",200) == 200 else literal(":status",str(response["http"]))
                        if response.get("content_type") is not None: block+=literal("content-type",response["content_type"])
                        if response.get("initial_status") is not None: block+=literal("grpc-status",response["initial_status"])
                        body=response.get("body",b"")
                        connection.sendall(frame(1,5 if response.get("only") else 4,stream,block))
                        if not response.get("only"):
                            if body: connection.sendall(data_frames(stream,envelope(b"\x00\x00"+body)))
                            if response.get("data_end"): connection.sendall(frame(0,1,stream))
                            else:
                                final=b"" if response.get("status") is None else literal("grpc-status",response["status"])
                                connection.sendall(frame(1,5,stream,final))
                        state["responded"]=state["ended"]=True; continue
                    if data in (b"bad-order",b"bad-nul",b"bad-pseudo",b"bad-compression",b"bad-length",b"bad-trailers"):
                        retained=b"\x40\x0cx-vless-core\x08retained"
                        blocks={b"bad-order":retained+b"\x88",b"bad-nul":b"\x88\x40\x03x\x00y\x01v"+retained,
                                b"bad-pseudo":b"\x88\x44\x01/"+retained,b"bad-compression":b"\x88\xff\xff\xff\xff\xff\x10",
                                b"bad-length":GRPC_HEADERS+b"\x0f\x0d\x010"+retained,b"bad-trailers":GRPC_HEADERS}
                        connection.sendall(frame(1,4,stream,blocks[data]))
                        if data == b"bad-length": connection.sendall(data_frames(stream,envelope(b"\x00\x00vless-core")))
                        if data == b"bad-trailers": connection.sendall(data_frames(stream,envelope(b"\x00\x00"))+frame(1,5,stream,b"\x88"+retained))
                        state["responded"]=state["ended"]=True; continue
                    if data == b"extension": connection.sendall(frame(99,255,9999,b"vless-core extension"))
                    if data == b"reset": connection.sendall(frame(3,stream=stream,payload=(8).to_bytes(4,"big"))); continue
                    if data == b"status":
                        if not state["responded"]: connection.sendall(frame(1,4,stream,GRPC_HEADERS)); state["responded"]=True
                        connection.sendall(frame(1,5,stream,b"\x00\x0bgrpc-status\x017")); continue
                    if not state["responded"]:
                        connection.sendall(frame(1,4,stream,GRPC_HEADERS+b"\xbe" if data == b"indexed" else GRPC_HEADERS)); state["responded"]=True
                        data=b"\x00\x00"+data
                    connection.sendall(data_frames(stream,envelope(data)))
                    if data.endswith(b"server-fin"):
                        connection.sendall(frame(1,5,stream,b"\x00\x0bgrpc-status\x010")); state["ended"]=True
                    if data.endswith(b"goaway"): connection.sendall(frame(7,payload=stream.to_bytes(4,"big")+bytes(4)))
                if flags&1:
                    if state["buffer"]: raise AssertionError("truncated uplink gRPC message")
                    if not state["ended"]:
                        data=b"vless-core final reply"
                        if not state["responded"]:
                            connection.sendall(frame(1,4,stream,GRPC_HEADERS)); state["responded"]=True; data=b"\x00\x00"+data
                        connection.sendall(data_frames(stream,envelope(data))+frame(1,5,stream,b"\x00\x0bgrpc-status\x010")); state["ended"]=True
                    self.finished.set()
            elif kind == 6 and not flags&1:
                self.ping.set()
                if self.acknowledge: connection.sendall(frame(6,1,payload=payload))
            elif kind == 3: streams.pop(stream,None)

class GrpcTests(unittest.TestCase):
    def test_grpc_requires_content_type_and_terminal_status(self):
        cases=(("missing-type",None,"0",{}),("wrong-type","text/plain","0",{}),
               ("wrong-suffix","application/grpc-web","0",{}),("empty-suffix","application/grpc+","0",{}),
               ("missing-status","application/grpc",None,{}),("early-status","application/grpc",None,{"initial_status":"0"}),
               ("data-end","application/grpc",None,{"data_end":True}),
               ("invalid-status","application/grpc","no",{}),("unknown-status","application/grpc","2147483648",{}),
               ("only-success","application/grpc","0",{"only":True,"initial_status":"0"}),
               ("only-failure","application/grpc","7",{"only":True,"initial_status":"7"}))
        responses={name.encode():dict(content_type=kind,status=status,**options) for name,kind,status,options in cases}
        with GrpcPeer(responses=responses) as peer, cli(uri(peer.port,"grpc","none")) as core:
            with socks_connect(core.port,80) as sibling:
                exchange(sibling,b"vless-core sibling")
                for name,_,_,_ in cases:
                    with self.subTest(case=name), socks_connect(core.port,80) as rejected:
                        rejected.sendall(name.encode()); self.assertEqual(rejected.recv(1),b"")
                        if name != "only-success": self.assertIn("gRPC",core.log)
                    exchange(sibling,b"vless-core unchanged sibling")
            self.assertEqual(len(peer.connections),1)

    def test_grpc_error_drains_validated_data_and_maps_status(self):
        reply=bytes(range(251))*701
        cases=(("success","0",{}),("missing",None,{}),("denied","7",{}),("unknown","9999999999999999999999999",{}),
               ("data-end",None,{"data_end":True}))
        responses={name.encode():dict(content_type="application/grpc+proto",status=status,body=reply,**options) for name,status,options in cases}
        with GrpcPeer(responses=responses) as peer, cli(uri(peer.port,"grpc","none")) as core:
            with socks_connect(core.port,80) as sibling:
                exchange(sibling,b"vless-core initial sibling")
                for name,_,_ in cases:
                    with self.subTest(case=name), socks_connect(core.port,80) as tunnel:
                        tunnel.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,8192)
                        tunnel.sendall(name.encode()); time.sleep(0.05)
                        self.assertEqual(exact(tunnel,len(reply)),reply); self.assertEqual(tunnel.recv(1),b"")
                    exchange(sibling,b"vless-core retained sibling")
            self.assertEqual(len(peer.connections),1)
            self.assertIn("grpc-status=2",core.log)

    def test_malformed_http_response_keeps_sibling_and_hpack_table(self):
        with GrpcPeer() as peer, cli(uri(peer.port,"grpc","none")) as core:
            with socks_connect(core.port,80) as healthy:
                exchange(healthy,b"vless-core warmup")
                for action in (b"bad-order",b"bad-nul",b"bad-pseudo",b"bad-length",b"bad-trailers"):
                    with self.subTest(action=action), socks_connect(core.port,80) as rejected:
                        rejected.sendall(action); self.assertEqual(rejected.recv(1),b"")
                    with socks_connect(core.port,80) as indexed: exchange(indexed,b"indexed")
                    exchange(healthy,b"vless-core surviving stream")
                exchange(healthy,b"extension")
                self.assertEqual(len(peer.connections),1)

    def test_hpack_compression_error_closes_physical_connection(self):
        with GrpcPeer() as peer, cli(uri(peer.port,"grpc","none")) as core:
            with socks_connect(core.port,80) as healthy, socks_connect(core.port,80) as rejected:
                exchange(healthy,b"vless-core warmup")
                rejected.sendall(b"bad-compression"); self.assertEqual(rejected.recv(1),b"")
                self.assertEqual(healthy.recv(1),b"")
            with socks_connect(core.port,80) as recovered: exchange(recovered,b"vless-core recovered physical connection")
            self.assertEqual(len(peer.connections),2)

    def test_invalid_server_preface_and_settings_are_rejected(self):
        for settings in (False,b"\x00",struct.pack("!HI",2,1),struct.pack("!HI",4,0x80000000),struct.pack("!HI",5,1)):
            with self.subTest(settings=settings), GrpcPeer(settings=settings) as peer, cli(uri(peer.port,"grpc","none")) as core:
                with self.assertRaises((AssertionError,EOFError,ConnectionError)):
                    with socks_connect(core.port,80) as tunnel: exchange(tunnel,b"vless-core")
                self.assertIn("invalid h2 frame sequence",core.log)

    def test_client_fin_drains_reply_and_keeps_sibling(self):
        with GrpcPeer() as peer, cli(uri(peer.port,"grpc","none")) as core:
            with socks_connect(core.port,80) as sibling, socks_connect(core.port,80) as tunnel:
                exchange(tunnel,b"vless-core initial")
                payload=bytes(range(251))*521; tunnel.sendall(payload); tunnel.shutdown(socket.SHUT_WR)
                expected=payload+b"vless-core final reply"
                self.assertEqual(exact(tunnel,len(expected)),expected)
                self.assertEqual(tunnel.recv(1),b""); self.assertTrue(peer.finished.wait(1))
                exchange(sibling,b"vless-core surviving sibling")
            self.assertEqual(len(peer.connections),1)

    def test_server_fin_keeps_client_upload_open(self):
        with GrpcPeer() as peer, cli(uri(peer.port,"grpc","none")) as core:
            with socks_connect(core.port,80) as tunnel:
                exchange(tunnel,b"server-fin"); self.assertEqual(tunnel.recv(1),b"")
                tunnel.sendall(b"vless-core after server FIN"); tunnel.shutdown(socket.SHUT_WR)
                self.assertTrue(peer.finished.wait(1))
            self.assertIn(b"vless-core after server FIN",[data for _,data in peer.uploads])

    def test_xhttp_settings_do_not_change_grpc_transport(self):
        settings={"address":"127.0.0.2","port":1,"network":"xhttp","security":"none","xhttpSettings":{"path":"/vless-core"}}
        with GrpcPeer() as peer, cli(uri(peer.port,"grpc","none",downloadSettings=json.dumps(settings))) as core:
            with socks_connect(core.port,80) as tunnel: exchange(tunnel,b"vless-core ignored XHTTP settings")
            self.assertEqual(len(peer.connections),1)
            self.assertIn("query.downloadsettings is not applied",core.log)
    def test_pool_capacity_wait_deadline_and_recovery(self):
        with GrpcPeer(maximum=1) as peer, cli(uri(peer.port,"grpc","none"),extra=["--connect-timeout-ms","300"]) as core:
            clients=[]
            try:
                for _ in range(4): clients.append(socks_connect(core.port,80))
                self.assertEqual(len(peer.connections),4)
                started=time.monotonic()
                with self.assertRaises(AssertionError):
                    with socks_connect(core.port,80): pass
                self.assertGreater(time.monotonic()-started,0.2)
                self.assertLess(time.monotonic()-started,0.7)
                self.assertEqual(len(peer.connections),4)
                clients.pop().close()
                with socks_connect(core.port,80) as tunnel: exchange(tunnel,b"vless-core recovered pool slot")
                self.assertEqual(len(peer.connections),4)
            finally:
                for client in clients: client.close()

    def test_settings_metadata_and_stream_isolation(self):
        with GrpcPeer() as peer, cli(uri(peer.port,"grpc","none",initialWindowsSize=1024,userAgent="vless-core/grpc",authority="vless-core.test",serviceName="vless-core")) as core:
            with socks_connect(core.port,80) as healthy:
                exchange(healthy,b"vless-core healthy RPC")
                for action in (b"reset",b"status"):
                    with socks_connect(core.port,80) as rejected:
                        rejected.sendall(action); self.assertEqual(rejected.recv(1),b"")
                    exchange(healthy,b"vless-core sibling is still usable")
            self.assertEqual(len(peer.connections),1)
            self.assertEqual(peer.windows,[1024])
            for _,_,request in peer.requests:
                self.assertEqual(request["user-agent"],"vless-core/grpc")
                self.assertEqual(request[":authority"],"vless-core.test")
                self.assertEqual(request[":path"],"/vless-core/Tun")

    def test_goaway_drains_without_replaying_rpc(self):
        with GrpcPeer() as peer, cli(uri(peer.port,"grpc","none")) as core:
            with socks_connect(core.port,80) as existing:
                exchange(existing,b"vless-core existing")
                with socks_connect(core.port,80) as rotating: exchange(rotating,b"goaway")
                time.sleep(0.05)
                with socks_connect(core.port,80) as replacement: exchange(replacement,b"vless-core replacement")
                exchange(existing,b"vless-core existing after GOAWAY")
            self.assertEqual(len(peer.connections),2)
            self.assertEqual(len(peer.requests),3)

    def test_keepalive_ack_and_timeout(self):
        for acknowledge in (True,False):
            with self.subTest(acknowledge=acknowledge), GrpcPeer(acknowledge=acknowledge) as peer, cli(uri(peer.port,"grpc","none",idleTimeout=1,healthCheckTimeout=1)) as core:
                with socks_connect(core.port,80) as tunnel:
                    exchange(tunnel,b"vless-core keepalive")
                    self.assertTrue(peer.ping.wait(3))
                    if acknowledge: exchange(tunnel,b"vless-core after ACK")
                    else:
                        tunnel.settimeout(3); self.assertEqual(tunnel.recv(1),b"")
                        self.assertIn("keepalive acknowledgement deadline expired",core.log)

    def test_idle_keepalive_requires_permission(self):
        for permitted in (False,True):
            with self.subTest(permitted=permitted), GrpcPeer() as peer, cli(uri(peer.port,"grpc","none",idleTimeout=1,permitWithoutStream=int(permitted))) as core:
                with socks_connect(core.port,80) as tunnel: exchange(tunnel,b"vless-core idle pool")
                self.assertEqual(peer.ping.wait(1.4),permitted)
