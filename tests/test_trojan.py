import hashlib
import json
import socket
import subprocess
import threading
import time
import unittest
from pathlib import Path
from urllib.parse import quote
import fixtures as f

class TrojanTests(unittest.TestCase):
    def test_inspect_and_invalid_configuration_are_private(self):
        password='Public+Fixture:@%é\x00Tail'
        config=f'trojan://{quote(password,safe="")}@offline.invalid:443'
        result=subprocess.run([str(f.BUILD/'vless-core-test'),'--inspect-config','--uri-fd','0'],input=config,text=True,capture_output=True,timeout=3)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout,'CONFIG\t1\nPRIMARY\toffline.invalid\t443\nEND\n')
        self.assertNotIn(password,result.stdout+result.stderr)
        self.assertNotIn(hashlib.sha224(password.encode()).hexdigest(),result.stdout+result.stderr)
        for suffix in ('?flow=xtls-rprx-vision','?encryption=mlkem768x25519plus.native.0rtt.private','?security=wrong','?type=invalid','?fp=invalid','?security=none&security=tls'):
            result=subprocess.run([str(f.BUILD/'vless-core-test'),'--inspect-config','--uri-fd','0'],input=config+suffix,text=True,capture_output=True,timeout=3)
            self.assertNotEqual(result.returncode,0)
            self.assertNotIn('listening',result.stdout+result.stderr)
            self.assertNotIn('Public',result.stdout+result.stderr)
        for authority in ('@127.0.0.1:443','a%@127.0.0.1:443','a%0@127.0.0.1:443','a%GG@127.0.0.1:443','a@127.0.0.1','a@127.0.0.1:+443','a@[invalid]:443','a@host\\name:443','a@host:65536'):
            result=subprocess.run([str(f.BUILD/'vless-core-test'),'--inspect-config','--uri-fd','0'],input='trojan://'+authority,text=True,capture_output=True,timeout=3)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(result.stdout,'')

    def read_request(self,connection,password=f.TROJAN_PASSWORD):
        header=f.exact(connection,60)
        self.assertEqual(header[:56],hashlib.sha224(password.encode()).hexdigest().encode())
        self.assertEqual(header[56:59],b'\r\n\x01')
        kind=header[59]
        if kind == 3: address=f.exact(connection,f.exact(connection,1)[0])
        else: address=f.exact(connection,{1:4,4:16}[kind])
        tail=f.exact(connection,4)
        self.assertEqual(tail[2:],b'\r\n')
        return kind,address,int.from_bytes(tail[:2],'big')

    def test_server_first_and_silent_tunnel_have_no_response_header(self):
        for delay in (0,.35):
            def handler(connection):
                self.assertEqual(self.read_request(connection),(1,b'\x7f\x00\x00\x01',80))
                time.sleep(delay)
                connection.sendall(b'\x00\x00server-first')
                self.assertEqual(f.exact(connection,7),b'client!')
                connection.sendall(b'last')
                connection.shutdown(socket.SHUT_WR)
                self.assertEqual(f.exact(connection,4),b'tail')
            with self.subTest(delay=delay),f.Server(handler) as upstream,f.cli(f.uri(upstream.port,protocol='trojan'),extra=['--connect-timeout-ms','150']) as core:
                with f.socks_connect(core.port,80) as tunnel:
                    self.assertEqual(f.exact(tunnel,14),b'\x00\x00server-first')
                    tunnel.sendall(b'client!')
                    self.assertEqual(f.exact(tunnel,4),b'last')
                    self.assertEqual(tunnel.recv(1),b'')
                    tunnel.sendall(b'tail'); tunnel.shutdown(socket.SHUT_WR)
                self.assertNotIn('VLESS response',core.log)

    def test_addresses_and_exact_password_bytes(self):
        password='Public+Fixture:@%é\x00Tail'
        for target in ('127.0.0.1','::1','target.invalid'):
            def handler(connection):
                kind,address,port=self.read_request(connection,password)
                self.assertEqual(port,43210)
                self.assertEqual(kind,1 if target == '127.0.0.1' else 4 if target == '::1' else 3)
                connection.sendall(b'\x00\x00ok')
            with self.subTest(target=target),f.Server(handler) as upstream,f.cli(f.uri(upstream.port,protocol='trojan',password=password)) as core:
                with f.socks_connect(core.port,43210,target) as tunnel: self.assertEqual(f.exact(tunnel,4),b'\x00\x00ok')

    def test_tcp_reference_security_and_fingerprints(self):
        certificate,_=f.certificate()
        for security in ('none','tls','reality'):
            for fingerprint in ('chrome','edge','qq','firefox','random','randomized'):
                with self.subTest(security=security,fp=fingerprint),f.Server() as target,f.xray_server('tcp',security,protocol='trojan') as reference,f.cli(f.uri(reference.port,'tcp',security,protocol='trojan',fp=fingerprint),environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                    with f.socks_connect(core.port,target.port) as tunnel:
                        f.exchange(tunnel,b'\x00\x00trojan reference'+bytes(range(256))*20)
                        f.exchange(tunnel,b'last')

    def test_tcp_tls12_and_trust_modes(self):
        certificate,_=f.certificate()
        for mode in ('strict','insecure','tofu'):
            pin=f.PRIVATE/('trojan-'+mode+'.pins')
            environment={'VLESS_TLS_MODE':mode,'VLESS_XHTTP_PIN_FILE':str(pin)}
            if mode == 'strict': environment['VLESS_CA_BUNDLE']=str(certificate)
            with self.subTest(mode=mode),f.Server() as target,f.xray_server('tcp','tls',protocol='trojan',tls_settings={'minVersion':'1.2','maxVersion':'1.2'}) as reference,f.cli(f.uri(reference.port,'tcp','tls',protocol='trojan'),environment=environment) as core:
                for _ in range(2):
                    with f.socks_connect(core.port,target.port) as tunnel: f.exchange(tunnel,b'trojan tls12 trust')
            self.assertEqual(pin.exists(),mode == 'tofu')

    def test_wrong_password_and_fallback_do_not_invent_authentication_status(self):
        with f.Server() as target,f.xray_server('tcp','none',protocol='trojan') as reference,f.cli(f.uri(reference.port,protocol='trojan',password='wrong-public-fixture')) as core:
            with f.socks_connect(core.port,target.port) as tunnel:
                tunnel.sendall(b'wrong password')
                try: response=tunnel.recv(1)
                except ConnectionResetError: response=b''
                self.assertEqual(response,b'')
            self.assertNotIn('VLESS response',core.log)
            self.assertNotIn('wrong-public-fixture',core.log)
        fallback=b'HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n'
        def handler(connection):
            self.read_request(connection)
            connection.sendall(fallback)
        with f.Server(handler) as upstream,f.cli(f.uri(upstream.port,protocol='trojan')) as core:
            with f.socks_connect(core.port,80) as tunnel: self.assertEqual(f.exact(tunnel,len(fallback)),fallback)
            self.assertNotIn('password accepted',core.log.lower())

    def test_upload_backpressure_does_not_block_the_response(self):
        payload=b'u'*(4*1024*1024)
        def handler(connection):
            self.read_request(connection)
            connection.sendall(b'\x00\x00response')
            time.sleep(.15)
            self.assertEqual(f.exact(connection,len(payload)),payload)
            connection.sendall(b'complete')
        with f.Server(handler) as upstream,f.cli(f.uri(upstream.port,protocol='trojan'),extra=['--connect-timeout-ms','1000']) as core:
            with f.socks_connect(core.port,80) as tunnel:
                sender=threading.Thread(target=tunnel.sendall,args=(payload,)); sender.start()
                self.assertEqual(f.exact(tunnel,10),b'\x00\x00response')
                self.assertEqual(f.exact(tunnel,8),b'complete')
                sender.join(3); self.assertFalse(sender.is_alive())

    def test_websocket_reference_early_data_and_headers(self):
        certificate,_=f.certificate()
        for security in ('none','tls'):
            for early in (0,1,67,68,69,16384):
                with self.subTest(security=security,early=early),f.Server() as target,f.xray_server('ws',security,protocol='trojan') as reference,f.cli(f.uri(reference.port,'ws',security,protocol='trojan',ed=early,headers=json.dumps({'X-Trojan-Fixture':'custom'})),environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                    with f.socks_connect(core.port,target.port) as tunnel:
                        f.exchange(tunnel,b'\x00\x00trojan websocket'+bytes(range(256))*300)
                        f.exchange(tunnel,b'last')

    def test_websocket_server_first_early_boundaries_and_close(self):
        import base64
        from test_websocket import upgrade,client_frame,frame
        expected=hashlib.sha224(f.TROJAN_PASSWORD.encode()).hexdigest().encode()+b'\r\n\x01\x01\x7f\x00\x00\x01\x00\x50\r\n'
        for security in ('none','tls'):
            for early in (0,1,67,68,69,16384):
                closed=threading.Event()
                def handler(connection):
                    line,headers=upgrade(connection)
                    self.assertEqual(line,'GET /vless-core?custom=1 HTTP/1.1')
                    self.assertEqual(headers['host'],'trojan-host.test:8443')
                    self.assertEqual(headers['x-trojan-fixture'],'custom')
                    encoded=headers.get('sec-websocket-protocol')
                    if encoded:
                        self.assertNotIn('=',encoded)
                        request=base64.urlsafe_b64decode(encoded+'='*(-len(encoded)%4))
                    else:
                        opcode,request=client_frame(connection); self.assertEqual(opcode,2)
                    self.assertEqual(request,expected)
                    self.assertEqual(bool(encoded),early >= len(expected))
                    connection.sendall(frame(2,b'\x00\x00hello'))
                    self.assertEqual(client_frame(connection),(2,b'client'))
                    connection.sendall(frame(2,b'la',final=False))
                    opcode,payload=client_frame(connection); self.assertEqual(opcode,8)
                    connection.sendall(frame(0,b'st')+frame(8,payload)); closed.set()
                certificate,_=f.certificate()
                with self.subTest(security=security,early=early),f.Server(handler,tls=security == 'tls') as upstream,f.cli(f.uri(upstream.port,'ws',security,protocol='trojan',ed=early,path='/vless-core?ed=4096&custom=1',host='trojan-host.test:8443',headers=json.dumps({'X-Trojan-Fixture':'custom'})),environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                    with f.socks_connect(core.port,80) as tunnel:
                        self.assertEqual(f.exact(tunnel,7),b'\x00\x00hello')
                        tunnel.sendall(b'client'); self.assertEqual(f.exact(tunnel,2),b'la')
                        tunnel.shutdown(socket.SHUT_WR)
                        self.assertEqual(f.exact(tunnel,2),b'st'); self.assertEqual(tunnel.recv(1),b'')
                    self.assertTrue(closed.wait(1))

    def test_websocket_heartbeat_and_rejected_upgrade(self):
        from test_websocket import upgrade,client_frame,frame
        def handler(connection):
            upgrade(connection); opcode,request=client_frame(connection)
            self.assertEqual((opcode,len(request)),(2,68))
            connection.sendall(frame(2,b'\x00\x00hello'))
            opcode,payload=client_frame(connection)
            self.assertEqual(opcode,9); connection.sendall(frame(10,payload))
            connection.sendall(frame(2,b'tick'))
            opcode,payload=client_frame(connection); self.assertEqual(opcode,8)
            connection.sendall(frame(8,payload))
        certificate,_=f.certificate()
        with f.Server(handler,tls=True) as upstream,f.cli(f.uri(upstream.port,'ws','tls',protocol='trojan',heartbeatPeriod=1),environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
            with f.socks_connect(core.port,80) as tunnel:
                self.assertEqual(f.exact(tunnel,7),b'\x00\x00hello')
                self.assertEqual(f.exact(tunnel,4),b'tick'); tunnel.shutdown(socket.SHUT_WR)
                self.assertEqual(tunnel.recv(1),b'')
        def invalid(connection):
            upgrade(connection,lambda reply,headers,accept:reply.replace(accept,b'bad-accept'))
        with f.Server(invalid) as upstream,f.cli(f.uri(upstream.port,'ws','none',protocol='trojan')) as core:
            with self.assertRaises((AssertionError,EOFError,ConnectionError)):
                with f.socks_connect(core.port,80) as tunnel: tunnel.recv(1)
            self.assertIn('invalid WebSocket upgrade response',core.wait_log('invalid WebSocket upgrade response'))

    def test_grpc_reference_modes_pool_and_parallel_rpc(self):
        import concurrent.futures
        certificate,_=f.certificate()
        for security in ('none','tls','reality'):
            for mode in ('gun','multi'):
                with self.subTest(security=security,mode=mode),f.Server() as target,f.xray_server('grpc',security,mode=mode,protocol='trojan') as reference,f.CountingProxy(reference.port) as proxy,f.cli(f.uri(proxy.port,'grpc',security,protocol='trojan',mode=mode,initialWindowsSize=1024),environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                    def exchange(index):
                        with f.socks_connect(core.port,target.port) as tunnel:
                            f.exchange(tunnel,b'\x00\x00grpc'+bytes([index])+bytes(range(251))*1100)
                    for index in range(3): exchange(index)
                    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool: list(pool.map(exchange,range(4)))
                    self.assertEqual(len(proxy.connections),1)

    def test_grpc_reference_server_first(self):
        certificate,_=f.certificate()
        for security in ('none','tls','reality'):
            for mode in ('gun','multi'):
                def handler(connection):
                    connection.sendall(b'\x00\x00server-first')
                    self.assertEqual(f.exact(connection,7),b'client!')
                    connection.sendall(b'last'); connection.shutdown(socket.SHUT_WR)
                with self.subTest(security=security,mode=mode),f.Server(handler) as target,f.xray_server('grpc',security,mode=mode,protocol='trojan') as reference,f.cli(f.uri(reference.port,'grpc',security,protocol='trojan',mode=mode),environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                    with f.socks_connect(core.port,target.port) as tunnel:
                        self.assertEqual(f.exact(tunnel,14),b'\x00\x00server-first')
                        tunnel.sendall(b'client!')
                        self.assertEqual(f.exact(tunnel,4),b'last'); self.assertEqual(tunnel.recv(1),b'')

    def test_grpc_status_reset_and_goaway_keep_neighbors(self):
        from test_grpc import GrpcPeer
        responses={b'bad-status':{'content_type':'application/grpc','status':'7','body':b'\x00\x00last'},
                   b'complete-reset':{'content_type':'application/grpc','status':'0','body':b'\x00\x00complete','reset':0}}
        with GrpcPeer(protocol='trojan',responses=responses) as peer,f.cli(f.uri(peer.port,'grpc','none',protocol='trojan')) as core:
            with f.socks_connect(core.port,80) as neighbor:
                for command,reply in ((b'bad-status',b'\x00\x00last'),(b'complete-reset',b'\x00\x00complete')):
                    with f.socks_connect(core.port,80) as tunnel:
                        tunnel.sendall(command); self.assertEqual(f.exact(tunnel,len(reply)),reply)
                        self.assertEqual(tunnel.recv(1),b'')
                        if command == b'complete-reset':
                            try: tunnel.sendall(b'after-reset')
                            except ConnectionError: pass
                    f.exchange(neighbor,b'\x00\x00neighbor')
                with f.socks_connect(core.port,80) as reset:
                    reset.sendall(b'reset'); self.assertEqual(reset.recv(1),b'')
                f.exchange(neighbor,b'alive')
                self.assertEqual(len(peer.connections),1)
                f.exchange(neighbor,b'goaway')
                with f.socks_connect(core.port,80) as replacement: f.exchange(replacement,b'replacement')
                self.assertGreaterEqual(len(peer.connections),2)
            self.assertNotIn(b'after-reset',[data for _,data in peer.uploads])

    def test_grpc_server_fin_keeps_upload_and_client_fin_drains_reply(self):
        from test_grpc import GrpcPeer
        with GrpcPeer(protocol='trojan') as peer,f.cli(f.uri(peer.port,'grpc','none',protocol='trojan')) as core:
            with f.socks_connect(core.port,80) as sibling,f.socks_connect(core.port,80) as tunnel:
                f.exchange(tunnel,b'server-fin'); self.assertEqual(tunnel.recv(1),b'')
                tunnel.sendall(b'after-server-fin'); tunnel.shutdown(socket.SHUT_WR)
                self.assertTrue(peer.finished.wait(1))
                f.exchange(sibling,b'alive'); sibling.shutdown(socket.SHUT_WR)
                self.assertEqual(f.exact(sibling,len(b'vless-core final reply')),b'vless-core final reply')
                self.assertEqual(sibling.recv(1),b'')
            self.assertIn(b'after-server-fin',[data for _,data in peer.uploads])
    def test_initial_request_fence_preserves_duplex_and_deadline(self):
        import select
        import struct
        from test_grpc import frame,envelope,GRPC_HEADERS
        for transport,pooled in (('grpc',True),):
            for release in (True,False):
                replied=threading.Event(); recovered=threading.Event(); stopped=threading.Event(); sent=threading.Event()
                uploaded=bytearray(); reply=b'\x00\x00before-full-request'
                def handler(connection):
                    self.assertEqual(f.exact(connection,24),b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
                    connection.sendall(frame(4,payload=struct.pack('!HI',4,0)))
                    stream_id=0; primer_id=0; primer_data=bytearray(); primer_done=False
                    while not stopped.is_set():
                        if release and replied.is_set() and not recovered.is_set():
                            connection.sendall(frame(8,stream=stream_id,payload=(4096).to_bytes(4,'big')))
                            recovered.set()
                        if not (transport == 'xhttp' and connection.pending()) and not select.select([connection],[],[],.01)[0]: continue
                        header=f.exact(connection,9); size=int.from_bytes(header[:3],'big')
                        kind,flags=header[3:5]; stream=int.from_bytes(header[5:],'big')&0x7fffffff
                        data=f.exact(connection,size)
                        if kind == 4 and not flags&1: connection.sendall(frame(4,1))
                        if kind == 1:
                            if not primer_id: primer_id=stream
                            else: stream_id=stream
                            connection.sendall(frame(8,stream=stream,payload=(4096 if stream == primer_id else 32).to_bytes(4,'big')))
                        if kind == 0:
                            if stream == primer_id:
                                primer_data.extend(data)
                                if len(primer_data) >= (75 if transport == 'grpc' else 68) and not primer_done:
                                    response=frame(1,4,stream,GRPC_HEADERS if transport == 'grpc' else b'\x88')
                                    response+=frame(0,0 if transport == 'grpc' else 1,stream,envelope(b'warm') if transport == 'grpc' else b'warm')
                                    if transport == 'grpc':
                                        from test_grpc import literal
                                        response+=frame(1,5,stream,literal('grpc-status','0'))
                                    connection.sendall(response); primer_done=True
                                continue
                            uploaded.extend(data)
                            if not sent.is_set():
                                self.assertEqual(len(uploaded),32)
                                connection.sendall(frame(1,4,stream,GRPC_HEADERS if transport == 'grpc' else b'\x88')+frame(0,stream=stream,payload=envelope(reply) if transport == 'grpc' else reply))
                                sent.set()
                certificate,_=f.certificate()
                options={'mode':'stream-one'} if transport == 'xhttp' else {}
                if transport == 'xhttp' and pooled: options['extra']=json.dumps({'xmux':{'maxConnections':1}})
                with self.subTest(transport=transport,pooled=pooled,release=release),f.Server(handler,tls=transport == 'xhttp') as peer,f.cli(f.uri(peer.port,transport,'tls' if transport == 'xhttp' else 'none',protocol='trojan',**options),extra=['--connect-timeout-ms','800'],environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                    try:
                        with f.socks_connect(core.port,80) as warmup: self.assertEqual(f.exact(warmup,4),b'warm')
                        with f.socks_connect(core.port,80) as tunnel:
                            self.assertEqual(f.exact(tunnel,len(reply)),reply)
                            self.assertFalse(recovered.is_set()); replied.set()
                            if release:
                                self.assertTrue(recovered.wait(1))
                                until=time.monotonic()+1
                                minimum=75 if transport == 'grpc' else 68
                                while len(uploaded) < minimum and time.monotonic() < until: time.sleep(.001)
                                self.assertEqual(len(uploaded),minimum)
                                time.sleep(1)
                                tunnel.settimeout(.1)
                                with self.assertRaises(TimeoutError): tunnel.recv(1)
                            else:
                                self.assertEqual(tunnel.recv(1),b'')
                                self.assertIn('Trojan request deadline expired',core.wait_log('Trojan request deadline expired'))
                    finally: stopped.set()
