import base64
import concurrent.futures
import contextlib
import hashlib
import json
import os
import socket
import subprocess
import threading
import time
import unittest
import urllib.parse
import fixtures as f


class ShadowsocksTests(unittest.TestCase):
    def test_inspect_and_invalid_settings_are_private_and_offline(self):
        value='ss://aes-128-gcm:Private%2BPass%40Word@no-dns.invalid:443'
        command=[str(f.BUILD/'vless-core-test'),'--inspect-config','--uri-fd','0']
        result=subprocess.run(command,input=value,text=True,capture_output=True,timeout=3)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout,'CONFIG\t1\nPRIMARY\tno-dns.invalid\t443\nEND\n')
        self.assertNotIn('Private',result.stdout+result.stderr)
        for suffix in ('flow=xtls-rprx-vision','encryption=aes-128-gcm','plugin=obfs-local','security=bad','type=ws&host=bad%0D%0AInjected','security=tls&pcs=unsupported','security=tls&vcn=unsupported','security=tls&pinnedPeerCertificateSha256=unsupported'):
            for inspect in (False,True):
                args=command if inspect else [str(f.BUILD/'vless-core-test'),'--uri-fd','0','--server-ips','127.0.0.1']
                result=subprocess.run(args,input=value+'?'+suffix,text=True,capture_output=True,timeout=3)
                self.assertNotEqual(result.returncode,0)
                self.assertNotIn('Private',result.stdout+result.stderr)
                self.assertNotIn('Injected',result.stdout+result.stderr)
                self.assertNotIn('listening',result.stdout+result.stderr)

    def test_tcp_method_security_matrix(self):
        certificate,_=f.certificate(); data=b'\x00\x00Shadowsocks'+bytes(range(256))*1024
        def handler(connection):
            self.assertEqual(f.exact(connection,len(data)),data); connection.sendall(data)
            self.assertEqual(f.exact(connection,10),b'last bytes'); connection.sendall(b'last bytes')
        for method in f.SHADOWSOCKS_METHODS:
            password=f.shadowsocks_password(method)
            for security in ('none','tls','reality'):
                with self.subTest(method=method,security=security),f.Server(handler) as target,f.xray_server('tcp',security,protocol='shadowsocks',password=password,ss_method=method) as reference,f.cli(f.uri(reference.port,'tcp',security,protocol='shadowsocks',password=password,ss_method=method),environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                    with f.socks_connect(core.port,target.port) as tunnel:
                        f.exchange(tunnel,data); f.exchange(tunnel,b'last bytes')
                        tunnel.shutdown(socket.SHUT_WR); self.assertEqual(tunnel.recv(1),b'')
                    self.assertNotIn(password,core.log)
                    self.assertNotIn('VLESS response',core.log)

    def test_tcp_local_fin_reaches_outer_transport(self):
        for method in f.SHADOWSOCKS_METHODS:
            finished=threading.Event(); received=bytearray(); password=f.shadowsocks_password(method)
            def handler(connection):
                while True:
                    block=connection.recv(65536)
                    if not block: finished.set(); return
                    received.extend(block)
            with self.subTest(method=method),f.Server(handler) as server,f.cli(f.uri(server.port,protocol='shadowsocks',password=password,ss_method=method)) as core:
                with f.socks_connect(core.port,80) as tunnel:
                    tunnel.sendall(b'last application bytes'); tunnel.shutdown(socket.SHUT_WR)
                    self.assertTrue(finished.wait(2)); self.assertEqual(tunnel.recv(1),b'')
                self.assertGreater(len(received),32)
                self.assertNotIn('VLESS response',core.log)

    def test_tcp_reference_client_control_and_link_forms(self):
        for method in f.SHADOWSOCKS_METHODS[:4]:
            password=f.TROJAN_PASSWORD
            with self.subTest(method=method),f.Server() as target,f.xray_server('tcp','none',protocol='shadowsocks',password=password,ss_method=method) as reference:
                for legacy in (False,True):
                    text=f'{method}:{password}'+(f'@127.0.0.1:{reference.port}' if legacy else '')
                    value='ss://'+base64.urlsafe_b64encode(text.encode()).decode().rstrip('=')+('' if legacy else f'@127.0.0.1:{reference.port}')
                    with f.cli(value) as core:
                        with f.socks_connect(core.port,target.port) as tunnel: f.exchange(tunnel,b'link forms exact \x00\x00')
                with f.xray_client(reference.port,'tcp','none',protocol='shadowsocks',password=password,ss_method=method) as client:
                    with f.socks_connect(client.port,target.port) as tunnel: f.exchange(tunnel,b'unchanged Xray control')

    def test_tcp_sip023_multiuser_and_relay_chains(self):
        for method in ('2022-blake3-aes-128-gcm','2022-blake3-aes-256-gcm'):
            size=16 if method.endswith('128-gcm') else 32
            keys=[base64.b64encode(bytes(range(i,i+size))).decode() for i in range(3)]
            for count in (2,3):
                with self.subTest(method=method,count=count),contextlib.ExitStack() as stack:
                    target=stack.enter_context(f.Server())
                    leaf=stack.enter_context(f.xray_server('tcp','none',protocol='shadowsocks',ss_method=method,password=keys[count-2],ss_users=[{'password':keys[count-1]}]))
                    reference=leaf if count==2 else stack.enter_context(f.xray_server('tcp','none',protocol='shadowsocks',ss_method=method,password=keys[0],ss_users=[{'password':keys[1],'address':'127.0.0.1','port':leaf.port}]))
                    password=':'.join(keys[:count])
                    with f.cli(f.uri(reference.port,protocol='shadowsocks',ss_method=method,password=password)) as core:
                        for _ in range(2):
                            with f.socks_connect(core.port,target.port) as tunnel: f.exchange(tunnel,b'\x00\x00SIP023'+bytes(range(256))*512)
                    with f.xray_client(reference.port,'tcp','none',protocol='shadowsocks',ss_method=method,password=password) as client:
                        with f.socks_connect(client.port,target.port) as tunnel: f.exchange(tunnel,b'unchanged Xray SIP023 control')

    def test_tcp_destination_types_and_binary_password(self):
        for method in ('aes-128-gcm','2022-blake3-aes-128-gcm'):
            password='Exact+Pass:%@\x00Z' if not method.startswith('2022-') else f.shadowsocks_password(method)
            for address in ('127.0.0.1','localhost','::1'):
                with self.subTest(method=method,address=address),f.Server(address='::1' if address=='::1' else '127.0.0.1') as target,f.xray_server('tcp','none',protocol='shadowsocks',ss_method=method,password=password) as reference,f.cli(f.uri(reference.port,protocol='shadowsocks',ss_method=method,password=password)) as core:
                    with f.socks_connect(core.port,target.port,address) as tunnel: f.exchange(tunnel,b'\x00\x00address types'+bytes(range(256))*128)

    def test_tcp_server_first_and_delayed_application(self):
        for method in f.SHADOWSOCKS_METHODS:
            password=f.shadowsocks_password(method)
            def handler(connection):
                time.sleep(.35); connection.sendall(b'\x00\x00server-first')
                self.assertEqual(f.exact(connection,4),b'ping'); connection.sendall(b'pong')
            with self.subTest(method=method),f.Server(handler) as target,f.xray_server('tcp','none',protocol='shadowsocks',password=password,ss_method=method) as reference,f.cli(f.uri(reference.port,protocol='shadowsocks',password=password,ss_method=method),extra=['--connect-timeout-ms','200']) as core:
                with f.socks_connect(core.port,target.port) as tunnel:
                    self.assertEqual(f.exact(tunnel,14),b'\x00\x00server-first'); tunnel.sendall(b'ping'); self.assertEqual(f.exact(tunnel,4),b'pong')
            with f.Server() as target,f.xray_server('tcp','none',protocol='shadowsocks',password=password,ss_method=method) as reference,f.cli(f.uri(reference.port,protocol='shadowsocks',password=password,ss_method=method),extra=['--connect-timeout-ms','150']) as core:
                with f.socks_connect(core.port,target.port) as tunnel:
                    time.sleep(.35); f.exchange(tunnel,b'delayed first application')

    def test_tcp_backpressure_and_last_reply_after_fin(self):
        payload=bytes(range(251))*16384
        for method in ('aes-128-gcm','2022-blake3-aes-128-gcm'):
            password=f.shadowsocks_password(method)
            def handler(connection):
                connection.sendall(b'\x00\x00reply'); time.sleep(.15)
                digest=hashlib.sha256(f.exact(connection,len(payload))).digest()
                time.sleep(.1); connection.sendall(digest)
            with self.subTest(method=method),f.Server(handler) as target,f.xray_server('tcp','none',protocol='shadowsocks',password=password,ss_method=method) as reference,f.cli(f.uri(reference.port,protocol='shadowsocks',password=password,ss_method=method),extra=['--connect-timeout-ms','1000']) as core:
                with f.socks_connect(core.port,target.port) as tunnel:
                    def upload(): tunnel.sendall(payload); tunnel.shutdown(socket.SHUT_WR)
                    sender=threading.Thread(target=upload,daemon=True); sender.start()
                    self.assertEqual(f.exact(tunnel,7),b'\x00\x00reply')
                    self.assertEqual(f.exact(tunnel,32),hashlib.sha256(payload).digest()); self.assertEqual(tunnel.recv(1),b'')
                    sender.join(3); self.assertFalse(sender.is_alive())

    def test_tcp_fingerprints_tls_versions_and_trust_modes(self):
        certificate,_=f.certificate()
        for version in ('1.2','1.3'):
            for trust in ('strict','insecure','tofu'):
                pin=f.PRIVATE/f'shadowsocks-{version}-{trust}.pins'
                environment={'VLESS_TLS_MODE':trust,'VLESS_XHTTP_PIN_FILE':str(pin)}
                if trust=='strict': environment['VLESS_CA_BUNDLE']=str(certificate)
                with self.subTest(version=version,trust=trust),f.Server() as target,f.xray_server('tcp','tls',protocol='shadowsocks',tls_settings={'minVersion':version,'maxVersion':version}) as reference,f.cli(f.uri(reference.port,'tcp','tls',protocol='shadowsocks'),environment=environment) as core:
                    for _ in range(2):
                        with f.socks_connect(core.port,target.port) as tunnel: f.exchange(tunnel,b'Shadowsocks trust modes')
                self.assertEqual(pin.exists(),trust=='tofu')
        for fingerprint in ('chrome','edge','qq','firefox','random','randomized'):
            with self.subTest(fp=fingerprint),f.Server() as target,f.xray_server('tcp','tls',protocol='shadowsocks') as reference,f.cli(f.uri(reference.port,'tcp','tls',protocol='shadowsocks',fp=fingerprint),environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                with f.socks_connect(core.port,target.port) as tunnel: f.exchange(tunnel,b'Shadowsocks fingerprints')

    def test_tcp_wrong_key_does_not_invent_authentication_reason(self):
        for method in ('aes-128-gcm','2022-blake3-aes-128-gcm'):
            password=f.shadowsocks_password(method)
            wrong=base64.b64encode(bytes([254])*16).decode() if method.startswith('2022-') else 'different-password'
            with self.subTest(method=method),f.Server() as target,f.xray_server('tcp','none',protocol='shadowsocks',password=password,ss_method=method) as reference,f.cli(f.uri(reference.port,protocol='shadowsocks',password=wrong,ss_method=method),extra=['--connect-timeout-ms','250']) as core:
                with f.socks_connect(core.port,target.port) as tunnel:
                    tunnel.sendall(b'authentication attempt'); tunnel.settimeout(.7)
                    try: self.assertEqual(tunnel.recv(1),b'')
                    except TimeoutError: self.assertFalse(method.startswith('2022-'))
                self.assertFalse(target.connections)
                self.assertNotIn('VLESS response',core.log)
                self.assertNotIn('wrong password',core.log)
                self.assertNotIn(wrong,core.log)

    def test_configuration_fds_preserve_pins_and_hide_credentials(self):
        password='Ss-Private+Pass:@%'
        with f.Server() as target,f.xray_server('tcp','none',protocol='shadowsocks',password=password) as reference:
            config=f.uri(reference.port,protocol='shadowsocks',password=password).replace('127.0.0.1','no-dns.invalid',1)
            for option in ('--uri-fd','--connection-fd'):
                read,write=os.pipe(); os.write(write,(config+('\n127.0.0.1' if option=='--connection-fd' else '')).encode()); os.close(write)
                try:
                    extra=[option,str(read)]+(['--server-ips','127.0.0.1'] if option=='--uri-fd' else [])
                    with f.cli(None,extra=extra,pass_fds=(read,)) as core:
                        with f.socks_connect(core.port,target.port) as tunnel: f.exchange(tunnel,b'pinned SS channel')
                        self.assertNotIn(password,core.log)
                finally: os.close(read)


class ShadowsocksWebSocketTests(unittest.TestCase):
    def test_websocket_reality_rejected_before_listener(self):
        import subprocess
        value=f.uri(443,'ws','reality',protocol='shadowsocks')
        for inspect in (False,True):
            arguments=[str(f.BUILD/'vless-core-test'),'--uri-fd','0']
            if inspect: arguments.append('--inspect-config')
            result=subprocess.run(arguments,input=value,text=True,capture_output=True,timeout=3)
            self.assertNotEqual(result.returncode,0); self.assertNotIn('listening',result.stdout+result.stderr)

    def test_websocket_methods_security_and_early_data(self):
        import json
        certificate,_=f.certificate(); payload=b'\x00\x00Shadowsocks websocket'+bytes(range(256))*512
        for method in f.SHADOWSOCKS_METHODS:
            password=f.shadowsocks_password(method)
            for security in ('none','tls'):
                for early in (0,16384):
                    with self.subTest(method=method,security=security,early=early),f.Server() as target,f.xray_server('ws',security,protocol='shadowsocks',ss_method=method,password=password) as reference,f.cli(f.uri(reference.port,'ws',security,protocol='shadowsocks',ss_method=method,password=password,ed=early,headers=json.dumps({'X-SS-Fixture':'custom'})),environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                        with f.socks_connect(core.port,target.port) as tunnel:
                            f.exchange(tunnel,payload); f.exchange(tunnel,b'last websocket bytes')
                        self.assertNotIn(password,core.log)
                        self.assertNotIn('VLESS response',core.log)

    def test_websocket_first_flight_early_data_boundaries(self):
        import io
        import json
        from test_websocket import client_frame
        certificate,_=f.certificate()
        for method in ('aes-128-gcm','2022-blake3-aes-128-gcm'):
            password=f.shadowsocks_password(method)
            for outer_tls in (False,True):
                for early in (0,1,56,57,58,127,128,1024,16384):
                    with self.subTest(method=method,tls=outer_tls,early=early),f.Server() as target,f.xray_server('ws','none',protocol='shadowsocks',ss_method=method,password=password) as reference,f.CountingProxy(reference.port,tls=outer_tls) as proxy:
                        settings=dict(protocol='shadowsocks',ss_method=method,password=password,ed=early,headers=json.dumps({'X-SS-Fixture':'custom'}),host='ss-host.test:8443')
                        with f.cli(f.uri(proxy.port,'ws','tls' if outer_tls else 'none',**settings),environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                            with f.socks_connect(core.port,target.port) as tunnel:
                                f.exchange(tunnel,b'\x00\x00first block'); f.exchange(tunnel,b'not a repeated header')
                            raw=bytes(proxy.client_data[0]); headers,_,frames=raw.partition(b'\r\n\r\n')
                            fields=dict(line.split(b':',1) for line in headers.split(b'\r\n')[1:])
                            fields={key.lower():value.strip() for key,value in fields.items()}
                            encoded=fields.get(b'sec-websocket-protocol')
                            if encoded: first=base64.urlsafe_b64decode(encoded+b'='*(-len(encoded)%4))
                            else:
                                reader=type('Reader',(),{'recv':lambda self,size:self.source.read(size)})(); reader.source=io.BytesIO(frames)
                                opcode,first=client_frame(reader); self.assertEqual(opcode,2)
                            self.assertEqual(bool(encoded),early>=len(first))
                            self.assertEqual(fields[b'host'],b'ss-host.test:8443')
                            self.assertEqual(fields[b'x-ss-fixture'],b'custom')

    def test_websocket_server_first_close_and_heartbeat(self):
        certificate,_=f.certificate()
        for method in ('aes-128-gcm','2022-blake3-aes-128-gcm'):
            password=f.shadowsocks_password(method)
            for security in ('none','tls'):
                def handler(connection):
                    time.sleep(.1); connection.sendall(b'\x00\x00server-first')
                    self.assertEqual(f.exact(connection,4),b'ping'); connection.sendall(b'pong')
                with self.subTest(method=method,security=security),f.Server(handler) as target,f.xray_server('ws',security,protocol='shadowsocks',ss_method=method,password=password) as reference,f.cli(f.uri(reference.port,'ws',security,protocol='shadowsocks',ss_method=method,password=password,ed=16384,heartbeatPeriod=1),environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                    with f.socks_connect(core.port,target.port) as tunnel:
                        self.assertEqual(f.exact(tunnel,14),b'\x00\x00server-first'); time.sleep(1.05)
                        tunnel.sendall(b'ping'); self.assertEqual(f.exact(tunnel,4),b'pong')
                        self.assertEqual(tunnel.recv(1),b'')
        def invalid(connection):
            from test_websocket import upgrade
            upgrade(connection,lambda reply,headers,accept:reply.replace(accept,b'invalid'))
        with f.Server(invalid) as peer,f.cli(f.uri(peer.port,'ws','none',protocol='shadowsocks')) as core:
            with self.assertRaises((AssertionError,EOFError,ConnectionError)):
                with f.socks_connect(core.port,80) as tunnel: tunnel.recv(1)
            core.wait_log('invalid WebSocket upgrade response')


class ShadowsocksGRPCTests(unittest.TestCase):
    def test_grpc_methods_security_and_modes(self):
        certificate,_=f.certificate(); data=b'\x00\x00SS gRPC'+bytes(range(256))*512
        for method in f.SHADOWSOCKS_METHODS:
            password=f.shadowsocks_password(method)
            for security in ('none','tls','reality'):
                for mode in ('gun','multi'):
                    def handler(connection):
                        self.assertEqual(f.exact(connection,len(data)),data); connection.sendall(data)
                        self.assertEqual(f.exact(connection,4),b'last'); connection.sendall(b'last')
                    with self.subTest(method=method,security=security,mode=mode),f.Server(handler) as target,f.xray_server('grpc',security,mode=mode,protocol='shadowsocks',ss_method=method,password=password) as reference,f.cli(f.uri(reference.port,'grpc',security,protocol='shadowsocks',ss_method=method,password=password,mode=mode,initialWindowsSize=1024),environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                        with f.socks_connect(core.port,target.port) as tunnel:
                            f.exchange(tunnel,data); f.exchange(tunnel,b'last'); tunnel.shutdown(socket.SHUT_WR)
                            self.assertEqual(tunnel.recv(1),b'')
                        self.assertNotIn('VLESS response',core.log)

    def test_grpc_reuse_parallel_rpc_and_slow_sibling(self):
        certificate,_=f.certificate(); data=bytes(range(256))*1024
        for method in ('aes-128-gcm','2022-blake3-aes-128-gcm'):
            password=f.shadowsocks_password(method)
            for mode in ('gun','multi'):
                def handler(connection):
                    self.assertEqual(f.exact(connection,len(data)),data); connection.sendall(data)
                with self.subTest(method=method,mode=mode),f.Server(handler) as target,f.xray_server('grpc','tls',mode=mode,protocol='shadowsocks',ss_method=method,password=password) as reference,f.CountingProxy(reference.port) as proxy,f.cli(f.uri(proxy.port,'grpc','tls',protocol='shadowsocks',ss_method=method,password=password,mode=mode),environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                    with f.socks_connect(core.port,target.port) as tunnel: f.exchange(tunnel,data)
                    physical=len(proxy.connections)
                    slow=f.socks_connect(core.port,target.port); slow.sendall(data)
                    try:
                        def exchange(index):
                            with f.socks_connect(core.port,target.port) as tunnel:
                                f.exchange(tunnel,data); self.assertEqual(tunnel.recv(1),b'')
                        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as workers: list(workers.map(exchange,range(4)))
                        self.assertEqual(f.exact(slow,len(data)),data); self.assertEqual(slow.recv(1),b'')
                        self.assertEqual(len(proxy.connections),physical)
                    finally: slow.close()

    def test_grpc_server_first_and_backpressure(self):
        certificate,_=f.certificate(); payload=bytes(range(251))*16384
        for method in ('aes-128-gcm','2022-blake3-aes-128-gcm'):
            password=f.shadowsocks_password(method)
            for mode in ('gun','multi'):
                def handler(connection):
                    time.sleep(.15); connection.sendall(b'\x00\x00server-first')
                    digest=hashlib.sha256(f.exact(connection,len(payload))).digest(); connection.sendall(digest)
                with self.subTest(method=method,mode=mode),f.Server(handler) as target,f.xray_server('grpc','tls',mode=mode,protocol='shadowsocks',ss_method=method,password=password) as reference,f.cli(f.uri(reference.port,'grpc','tls',protocol='shadowsocks',ss_method=method,password=password,mode=mode),environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                    with f.socks_connect(core.port,target.port) as tunnel:
                        def upload(): tunnel.sendall(payload); tunnel.shutdown(socket.SHUT_WR)
                        sender=threading.Thread(target=upload,daemon=True); sender.start()
                        self.assertEqual(f.exact(tunnel,14),b'\x00\x00server-first')
                        self.assertEqual(f.exact(tunnel,32),hashlib.sha256(payload).digest()); self.assertEqual(tunnel.recv(1),b'')
                        sender.join(3); self.assertFalse(sender.is_alive())

    def test_grpc_reset_and_trailers_do_not_hide_transport_errors(self):
        from test_grpc import frame,envelope,GRPC_HEADERS,literal
        for trailers in (None,'7'):
            seen=[]
            def handler(connection):
                self.assertEqual(f.exact(connection,24),b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
                connection.sendall(frame(4))
                while True:
                    header=f.exact(connection,9); size=int.from_bytes(header[:3],'big'); kind,flags=header[3:5]; stream=int.from_bytes(header[5:],'big')&0x7fffffff
                    data=f.exact(connection,size)
                    if kind==4 and not flags&1: connection.sendall(frame(4,1))
                    if kind!=0 or not size: continue
                    seen.append(stream)
                    if trailers is None: connection.sendall(frame(3,stream=stream,payload=(8).to_bytes(4,'big')))
                    else: connection.sendall(frame(1,4,stream,GRPC_HEADERS)+frame(0,stream=stream,payload=envelope(b'\x00'))+frame(1,5,stream,literal('grpc-status',trailers)))
                    while connection.recv(65536): pass
                    return
            with self.subTest(trailers=trailers),f.Server(handler) as peer,f.cli(f.uri(peer.port,'grpc','none',protocol='shadowsocks')) as core:
                with f.socks_connect(core.port,80) as tunnel:
                    tunnel.sendall(b'payload')
                    try: response=tunnel.recv(1)
                    except ConnectionResetError: response=b''
                    self.assertEqual(response,b'')
                self.assertTrue(seen); self.assertNotIn('VLESS response',core.log)
                self.assertRegex(core.wait_log('reset' if trailers is None else 'grpc-status'),r'reset|grpc-status')


class ShadowsocksXHTTPTests(unittest.TestCase):
    def test_inspect_download_is_private_offline_and_has_no_pin_side_effect(self):
        import os
        import subprocess
        for method in ('aes-128-gcm','2022-blake3-aes-128-gcm'):
            password=f.shadowsocks_password(method); pin=f.PRIVATE/('ss-inspect-'+method)
            download=dict(address='download.invalid',port=8443,network='xhttp',security='tls',tlsSettings=dict(serverName='download.invalid'),xhttpSettings=dict(path='/download'))
            value=f.uri(443,'xhttp','tls',protocol='shadowsocks',ss_method=method,password=password,mode='stream-up',extra=json.dumps(dict(downloadSettings=download))).replace('@127.0.0.1:','@upload.invalid:')
            environment=dict(os.environ,VLESS_XHTTP_TLS_MODE='tofu',VLESS_XHTTP_PIN_FILE=str(pin))
            result=subprocess.run([str(f.BUILD/'vless-core-test'),'--inspect-config','--uri-fd','0'],input=value,text=True,capture_output=True,timeout=3,env=environment)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout,'CONFIG\t1\nPRIMARY\tupload.invalid\t443\nDOWNLOAD\tdownload.invalid\t8443\nEND\n')
            self.assertNotIn(password,result.stdout+result.stderr); self.assertFalse(pin.exists())

    def test_cancelled_clients_release_resources_and_keep_neighbors(self):
        from pathlib import Path
        import struct
        certificate,_=f.certificate()
        def handler(connection):
            connection.settimeout(2)
            try: connection.sendall(f.exact(connection,4))
            except (ConnectionError,EOFError,TimeoutError): pass
        for method in ('aes-128-gcm','2022-blake3-aes-128-gcm'):
            password=f.shadowsocks_password(method)
            for transport,mode in (('tcp',None),('ws',None),('grpc','multi'),('xhttp','stream-one'),('xhttp','packet-up')):
                settings=dict(protocol='shadowsocks',ss_method=method,password=password)
                if mode: settings['mode']=mode
                if transport=='xhttp': settings['extra']=json.dumps({'xmux':{'maxConnections':1}})
                with self.subTest(method=method,transport=transport,mode=mode),f.Server(handler) as target,f.xray_server(transport,'tls',mode=mode,protocol='shadowsocks',ss_method=method,password=password) as reference,f.cli(f.uri(reference.port,transport,'tls',**settings),environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                    descriptors=Path(f'/proc/{core.process.pid}/fd'); tasks=Path(f'/proc/{core.process.pid}/task')
                    with f.socks_connect(core.port,target.port) as tunnel:
                        f.exchange(tunnel,b'ping'); self.assertEqual(tunnel.recv(1),b'')
                    time.sleep(.2); baseline=(len(list(descriptors.iterdir())),len(list(tasks.iterdir())))
                    for _ in range(16):
                        tunnel=f.socks_connect(core.port,target.port)
                        tunnel.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0)); tunnel.sendall(b'ping'); tunnel.close()
                    with f.socks_connect(core.port,target.port) as tunnel:
                        f.exchange(tunnel,b'ping'); self.assertEqual(tunnel.recv(1),b'')
                    until=time.monotonic()+3
                    while True:
                        current=(len(list(descriptors.iterdir())),len(list(tasks.iterdir())))
                        if current[0]<=baseline[0] and current[1]<=baseline[1]: break
                        self.assertLess(time.monotonic(),until,f'cancelled SS clients retained resources: {baseline} -> {current}'); time.sleep(.01)

    def test_direct_and_block_keep_routing_without_upstream(self):
        payload=b'\x00\x00SS routing'+bytes(range(251))*128
        def handler(connection):
            received=bytearray()
            while True:
                data=connection.recv(65536)
                if not data: break
                received.extend(data)
            self.assertEqual(bytes(received),payload); connection.sendall(hashlib.sha256(received).digest())
        for method in ('aes-128-gcm','2022-blake3-aes-128-gcm'):
            password=f.shadowsocks_password(method)
            for transport in ('tcp','ws','grpc','xhttp'):
                value=f.uri(1,transport,'tls',protocol='shadowsocks',ss_method=method,password=password)
                with self.subTest(method=method,transport=transport),f.Server(handler) as target:
                    with f.cli(value,extra=['--routing','1;direct;0']) as core:
                        with f.socks_connect(core.port,target.port) as tunnel:
                            tunnel.sendall(payload); tunnel.shutdown(socket.SHUT_WR)
                            self.assertEqual(f.exact(tunnel,32),hashlib.sha256(payload).digest()); self.assertEqual(tunnel.recv(1),b'')
                    with f.cli(value,extra=['--routing','1;block;0']) as core:
                        with self.assertRaisesRegex(AssertionError,'SOCKS CONNECT failed'): f.socks_connect(core.port,target.port)

    def test_long_psk_normalization_matches_xray(self):
        import base64
        certificate,_=f.certificate()
        for method in f.SHADOWSOCKS_METHODS[4:]:
            size=16 if method.endswith('128-gcm') else 32
            for length in (size+1,64):
                password=base64.b64encode(bytes(range(length))).decode()
                for transport,mode in (('tcp',None),('ws',None),('grpc','multi'),('xhttp','packet-up')):
                    with self.subTest(method=method,length=length,transport=transport),f.Server() as target,f.xray_server(transport,'tls',mode=mode,protocol='shadowsocks',ss_method=method,password=password) as reference:
                        parameters=dict(protocol='shadowsocks',ss_method=method,password=password)
                        if mode: parameters['mode']=mode
                        with f.cli(f.uri(reference.port,transport,'tls',**parameters),environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                            with f.socks_connect(core.port,target.port) as tunnel: f.exchange(tunnel,b'\x00\x00normalized PSK'+bytes(range(256))*256)

    def test_sip023_chains_keep_identity_across_transports(self):
        import base64
        import contextlib
        certificate,_=f.certificate()
        for method in ('2022-blake3-aes-128-gcm','2022-blake3-aes-256-gcm'):
            size=16 if method.endswith('128-gcm') else 32
            keys=[base64.b64encode(bytes(range(i,i+size))).decode() for i in range(3)]
            for transport,mode in (('ws',None),('grpc','gun'),('grpc','multi'),('xhttp','stream-up'),('xhttp','packet-up')):
                for count in (2,3):
                    with self.subTest(method=method,transport=transport,mode=mode,count=count),contextlib.ExitStack() as stack:
                        target=stack.enter_context(f.Server())
                        if count==3:
                            leaf=stack.enter_context(f.xray_server('tcp','none',protocol='shadowsocks',ss_method=method,password=keys[1],ss_users=[{'password':keys[2]}]))
                            users=[{'password':keys[1],'address':'127.0.0.1','port':leaf.port}]
                        else: users=[{'password':keys[1]}]
                        reference=stack.enter_context(f.xray_server(transport,'tls',mode=mode,protocol='shadowsocks',ss_method=method,password=keys[0],ss_users=users))
                        parameters=dict(protocol='shadowsocks',ss_method=method,password=':'.join(keys[:count]))
                        if mode: parameters['mode']=mode
                        if transport=='xhttp': parameters['extra']=json.dumps({'xmux':{'maxConnections':1}})
                        core=stack.enter_context(f.cli(f.uri(reference.port,transport,'tls',**parameters),environment={'VLESS_CA_BUNDLE':str(certificate)}))
                        for _ in range(2):
                            with f.socks_connect(core.port,target.port) as tunnel: f.exchange(tunnel,b'\x00\x00SIP023 transport'+bytes(range(256))*512)

    def test_xhttp_methods_modes_security_and_private_connections(self):
        certificate,_=f.certificate(); data=b'\x00\x00SS XHTTP'+bytes(range(256))*512
        for method in f.SHADOWSOCKS_METHODS:
            password=f.shadowsocks_password(method)
            for security,alpn in (('none',None),('tls','h2'),('tls','http/1.1'),('reality',None)):
                for mode in ('stream-one','stream-up','packet-up'):
                    for pooled in (False,True):
                        options=dict(protocol='shadowsocks',ss_method=method,password=password,mode=mode,extra=json.dumps({'xmux':{'maxConnections':1}}) if pooled else '{}')
                        if alpn: options['alpn']=alpn
                        with self.subTest(method=method,security=security,alpn=alpn,mode=mode,pooled=pooled),f.Server() as target,f.xray_server('xhttp',security,mode=mode,protocol='shadowsocks',ss_method=method,password=password) as reference,f.CountingProxy(reference.port) as proxy,f.cli(f.uri(proxy.port,'xhttp',security,**options),environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                            for index in range(2):
                                with f.socks_connect(core.port,target.port) as tunnel:
                                    f.exchange(tunnel,data+bytes([index])); f.exchange(tunnel,b'last XHTTP bytes')
                            if not pooled: self.assertGreaterEqual(len(proxy.connections),2)
                            self.assertNotIn('VLESS response',core.log)

    def test_xhttp_server_first_last_bytes_and_reuse(self):
        certificate,_=f.certificate()
        for method in ('aes-128-gcm','2022-blake3-aes-128-gcm'):
            password=f.shadowsocks_password(method)
            for mode in ('stream-one','stream-up','packet-up'):
                for pooled in (False,True):
                    def handler(connection):
                        time.sleep(.1); connection.sendall(b'\x00\x00server-first')
                        self.assertEqual(f.exact(connection,7),b'client!'); time.sleep(.1); connection.sendall(b'last')
                    options=dict(protocol='shadowsocks',ss_method=method,password=password,mode=mode,extra=json.dumps({'xmux':{'maxConnections':1}}) if pooled else '{}')
                    with self.subTest(method=method,mode=mode,pooled=pooled),f.Server(handler) as target,f.xray_server('xhttp','tls',mode=mode,protocol='shadowsocks',ss_method=method,password=password) as reference,f.CountingProxy(reference.port) as proxy,f.cli(f.uri(proxy.port,'xhttp','tls',**options),environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                        for _ in range(2):
                            with f.socks_connect(core.port,target.port) as tunnel:
                                self.assertEqual(f.exact(tunnel,14),b'\x00\x00server-first'); tunnel.sendall(b'client!')
                                self.assertEqual(f.exact(tunnel,4),b'last'); self.assertEqual(tunnel.recv(1),b'')
                        if pooled: self.assertEqual(len(proxy.connections),1)

    def test_xhttp_independent_download_security_and_pins(self):
        certificate,_=f.certificate(); shared=dict(sessionIDPlacement='header',seqPlacement='header')
        for method in ('aes-128-gcm','2022-blake3-aes-128-gcm'):
            password=f.shadowsocks_password(method)
            for mode in ('stream-up','packet-up'):
                for upload_tls,download_tls in ((False,False),(True,False),(False,True)):
                    for pooled in (False,True):
                        with self.subTest(method=method,mode=mode,upload_tls=upload_tls,download_tls=download_tls,pooled=pooled),f.Server() as target,f.xray_server('xhttp','none',path='/',protocol='shadowsocks',ss_method=method,password=password,**shared) as reference,f.CountingProxy(reference.port,tls=upload_tls) as upload,f.CountingProxy(reference.port,address='127.0.0.2',tls=download_tls) as download:
                            settings=dict(address='download.invalid',port=download.port,network='xhttp',security='tls' if download_tls else 'none',xhttpSettings=dict(path='/download',**shared))
                            if download_tls: settings['tlsSettings']=dict(serverName='vless-core.test',alpn=['http/1.1'])
                            extra=dict(downloadSettings=settings,**shared)
                            if pooled: extra['xmux']=dict(maxConnections=1)
                            options=dict(protocol='shadowsocks',ss_method=method,password=password,mode=mode,path='/upload',extra=json.dumps(extra))
                            if upload_tls: options['alpn']='http/1.1'
                            config=f.uri(upload.port,'xhttp','tls' if upload_tls else 'none',**options).replace('@127.0.0.1:','@upload.invalid:')
                            with f.cli(config,extra=['--server-ips','127.0.0.1','--download-server-ips','127.0.0.2'],environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                                with f.socks_connect(core.port,target.port) as tunnel:
                                    f.exchange(tunnel,b'\x00\x00independent SS download'+bytes(range(251))*1100)
                                    f.exchange(tunnel,b'nonce state preserved between POSTs')
                                self.assertTrue(upload.connections); self.assertTrue(download.connections)

    def test_xhttp_reality_download_and_parallel_sessions(self):
        shared=dict(sessionIDPlacement='header',seqPlacement='header')
        for method in ('aes-128-gcm','2022-blake3-aes-128-gcm'):
            password=f.shadowsocks_password(method)
            for mode in ('stream-up','packet-up'):
                for pooled in (False,True):
                    with self.subTest(method=method,mode=mode,pooled=pooled),f.Server() as target,f.xray_server('xhttp','reality',path='/',protocol='shadowsocks',ss_method=method,password=password,**shared) as reference,f.CountingProxy(reference.port) as upload,f.CountingProxy(reference.port,address='127.0.0.2') as download:
                        settings=dict(address='download.invalid',port=download.port,network='xhttp',security='reality',realitySettings=dict(serverName='vless-core.test',publicKey=f.PUBLIC_KEY,shortId='01020304',fingerprint='firefox'),xhttpSettings=dict(path='/download',**shared))
                        extra=dict(downloadSettings=settings,**shared)
                        if pooled: extra['xmux']=dict(maxConnections=1)
                        config=f.uri(upload.port,'xhttp','reality',protocol='shadowsocks',ss_method=method,password=password,mode=mode,path='/upload',extra=json.dumps(extra)).replace('@127.0.0.1:','@upload.invalid:')
                        with f.cli(config,extra=['--server-ips','127.0.0.1','--download-server-ips','127.0.0.2']) as core:
                            def transfer(index):
                                with f.socks_connect(core.port,target.port) as tunnel: f.exchange(tunnel,b'\x00\x00separate SS REALITY download'+bytes([index])+bytes(range(251))*1100)
                            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as workers: list(workers.map(transfer,range(4)))
                            self.assertTrue(upload.connections); self.assertTrue(download.connections)

    def test_xhttp_head_packet_responses(self):
        certificate,_=f.certificate()
        for method in ('aes-128-gcm','2022-blake3-aes-128-gcm'):
            password=f.shadowsocks_password(method)
            for security,alpn in (('none',None),('tls','h2'),('tls','http/1.1')):
                for pooled in (False,True):
                    options=dict(protocol='shadowsocks',ss_method=method,password=password,mode='packet-up',uplinkHTTPMethod='HEAD',extra=json.dumps({'xmux':{'maxConnections':1}}) if pooled else '{}')
                    if alpn: options['alpn']=alpn
                    with self.subTest(method=method,security=security,alpn=alpn,pooled=pooled),f.Server() as target,f.xray_server('xhttp',security,mode='packet-up',protocol='shadowsocks',ss_method=method,password=password,uplinkHTTPMethod='HEAD') as reference,f.cli(f.uri(reference.port,'xhttp',security,**options),environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                        with f.socks_connect(core.port,target.port) as tunnel: f.exchange(tunnel,b'\x00\x00SS HEAD acknowledgement'+bytes(range(251))*1100)
