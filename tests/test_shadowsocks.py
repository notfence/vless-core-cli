import base64
import contextlib
import hashlib
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
