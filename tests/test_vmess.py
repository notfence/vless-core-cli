import base64
import hashlib
import json
import os
import socket
import subprocess
import threading
import time
import unittest
import fixtures as f


class VMessTests(unittest.TestCase):
    def test_tcp_body_security_matrix(self):
        certificate,_=f.certificate()
        data=b'\x00\x00VMess'+bytes(range(256))*1024
        for security in ('none','tls','reality'):
            for body in ('auto','aes-128-gcm','chacha20-poly1305','none','zero'):
                with self.subTest(security=security,body=body),f.Server() as target,f.xray_server('tcp',security,protocol='vmess') as reference,f.cli(f.uri(reference.port,'tcp',security,protocol='vmess',encryption=body),environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                    with f.socks_connect(core.port,target.port) as tunnel:
                        f.exchange(tunnel,data)
                        f.exchange(tunnel,b'last bytes')
                        tunnel.shutdown(socket.SHUT_WR)
                        self.assertEqual(tunnel.recv(1),b'')
                    self.assertNotIn('VLESS response',core.log)

    def test_tcp_base64_json_and_fingerprints(self):
        certificate,_=f.certificate()
        for fingerprint in ('chrome','edge','qq','firefox','random','randomized'):
            for security in ('tls','reality'):
                with self.subTest(fp=fingerprint,security=security),f.Server() as target,f.xray_server('tcp',security,protocol='vmess') as reference:
                    value=dict(v='2',add='127.0.0.1',port=str(reference.port),id=f.UUID,aid=0,scy='auto',net='tcp',tls=security,sni='vless-core.test',fp=fingerprint)
                    if security == 'reality': value.update(pbk=f.PUBLIC_KEY,sid='01020304')
                    uri='vmess://'+base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')
                    with f.cli(uri,environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                        with f.socks_connect(core.port,target.port) as tunnel: f.exchange(tunnel,b'base64 JSON\x00\x00')

    def test_tcp_tls12_and_trust_modes(self):
        certificate,_=f.certificate()
        for version in ('1.2','1.3'):
            for mode in ('strict','insecure','tofu'):
                pin=f.PRIVATE/f'vmess-{version}-{mode}.pins'
                environment={'VLESS_TLS_MODE':mode,'VLESS_XHTTP_PIN_FILE':str(pin)}
                if mode == 'strict': environment['VLESS_CA_BUNDLE']=str(certificate)
                with self.subTest(version=version,mode=mode),f.Server() as target,f.xray_server('tcp','tls',protocol='vmess',tls_settings={'minVersion':version,'maxVersion':version}) as reference,f.cli(f.uri(reference.port,'tcp','tls',protocol='vmess'),environment=environment) as core:
                    for _ in range(2):
                        with f.socks_connect(core.port,target.port) as tunnel: f.exchange(tunnel,b'VMess trust modes')
                self.assertEqual(pin.exists(),mode == 'tofu')

    def test_tcp_server_first_and_delayed_application(self):
        for body in ('aes-128-gcm','chacha20-poly1305','none','zero'):
            def handler(connection):
                time.sleep(.35)
                connection.sendall(b'\x00\x00server-first')
                self.assertEqual(f.exact(connection,4),b'ping')
                connection.sendall(b'pong')
            with self.subTest(body=body),f.Server(handler) as target,f.xray_server('tcp','none',protocol='vmess') as reference,f.cli(f.uri(reference.port,protocol='vmess',encryption=body),extra=['--connect-timeout-ms','200']) as core:
                with f.socks_connect(core.port,target.port) as tunnel:
                    self.assertEqual(f.exact(tunnel,14),b'\x00\x00server-first')
                    tunnel.sendall(b'ping'); self.assertEqual(f.exact(tunnel,4),b'pong')
            with f.Server() as target,f.xray_server('tcp','none',protocol='vmess') as reference,f.cli(f.uri(reference.port,protocol='vmess',encryption=body),extra=['--connect-timeout-ms','150']) as core:
                with f.socks_connect(core.port,target.port) as tunnel:
                    time.sleep(.35)
                    f.exchange(tunnel,b'delayed first application')

    def test_tcp_backpressure_and_last_reply_after_fin(self):
        payload=bytes(range(251))*16384
        def handler(connection):
            connection.sendall(b'\x00\x00reply')
            time.sleep(.15)
            digest=hashlib.sha256(f.exact(connection,len(payload))).digest()
            time.sleep(.1)
            connection.sendall(digest)
        with f.Server(handler) as target,f.xray_server('tcp','none',protocol='vmess') as reference,f.cli(f.uri(reference.port,protocol='vmess'),extra=['--connect-timeout-ms','1000']) as core:
            with f.socks_connect(core.port,target.port) as tunnel:
                def upload(): tunnel.sendall(payload); tunnel.shutdown(socket.SHUT_WR)
                sender=threading.Thread(target=upload,daemon=True); sender.start()
                self.assertEqual(f.exact(tunnel,7),b'\x00\x00reply')
                self.assertEqual(f.exact(tunnel,32),hashlib.sha256(payload).digest())
                self.assertEqual(tunnel.recv(1),b'')
                sender.join(3); self.assertFalse(sender.is_alive())

    def test_inspect_and_invalid_settings_have_no_network_effects(self):
        uuid='12345678-0000-0000-0000-000000000001'
        uri=f'vmess://{uuid}@offline.invalid:443?security=none'
        result=subprocess.run([str(f.BUILD/'vless-core-test'),'--inspect-config','--uri-fd','0'],input=uri,capture_output=True,text=True,timeout=3)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout,'CONFIG\t1\nPRIMARY\toffline.invalid\t443\nEND\n')
        self.assertNotIn(uuid,result.stderr+result.stdout)
        for suffix in ('aid=1','flow=xtls-rprx-vision','encryption=aes-128-cfb','encryption=auto&scy=none'):
            result=subprocess.run([str(f.BUILD/'vless-core-test'),'--uri',uri+'&'+suffix],capture_output=True,text=True,timeout=3)
            self.assertNotEqual(result.returncode,0)
            self.assertNotIn(uuid,result.stderr+result.stdout)
            self.assertNotIn('listening',result.stderr)

    def test_tcp_eof_and_wrong_uuid_do_not_invent_authentication_status(self):
        for length in (0,1,17,18,38):
            def handler(connection):
                connection.recv(1024)
                if length: connection.sendall(bytes(length))
            with self.subTest(response_bytes=length),f.Server(handler) as peer,f.cli(f.uri(peer.port,protocol='vmess')) as core:
                with f.socks_connect(core.port,80) as tunnel:
                    try: response=tunnel.recv(1)
                    except ConnectionResetError: response=b''
                    self.assertEqual(response,b'')
                core.wait_log('VMess')
                self.assertNotIn('VLESS response',core.log)
                self.assertNotIn('wrong UUID',core.log)

    def test_tcp_wrong_uuid_has_no_guessed_authentication_reason(self):
        with f.Server() as target,f.xray_server('tcp','none',protocol='vmess') as reference:
            uri=f.uri(reference.port,protocol='vmess').replace(f.UUID,'00000000-0000-0000-0000-000000000002')
            with f.cli(uri,extra=['--connect-timeout-ms','250']) as core:
                with f.socks_connect(core.port,target.port) as tunnel:
                    tunnel.sendall(b'wrong public fixture UUID')
                    try: response=tunnel.recv(1)
                    except ConnectionResetError: response=b''
                    self.assertEqual(response,b'')
                self.assertNotIn('VLESS response',core.log)
                self.assertNotIn('wrong UUID',core.log)

    def test_authid_wall_clock_skew_does_not_change_monotonic_deadline(self):
        with f.Server() as target,f.xray_server('tcp','none',protocol='vmess') as reference:
            config=f.uri(reference.port,protocol='vmess')
            for shift in ('past','future'):
                with self.subTest(shift=shift),f.cli(config,extra=['--connect-timeout-ms','250'],environment={'VC_TEST_VMESS_CLOCK':shift}) as core:
                    started=time.monotonic()
                    with f.socks_connect(core.port,target.port) as tunnel:
                        tunnel.sendall(b'wall clock fixture')
                        try: reply=tunnel.recv(1)
                        except ConnectionResetError: reply=b''
                        self.assertEqual(reply,b'')
                    self.assertLess(time.monotonic()-started,2)
                    self.assertNotIn('wrong UUID',core.log)
                    self.assertNotIn('wrong clock',core.log)
            with f.cli(config) as core:
                with f.socks_connect(core.port,target.port) as tunnel: f.exchange(tunnel,b'correct clock after rejected requests')

    def test_configuration_fds_preserve_ip_pins_and_hide_credentials(self):
        for option in ('--uri-fd','--connection-fd'):
            with self.subTest(option=option),f.Server() as target,f.xray_server('tcp','none',protocol='vmess') as reference:
                config=f.uri(reference.port,protocol='vmess').replace('@127.0.0.1:','@never-resolve.invalid:')
                reader,writer=os.pipe()
                try:
                    os.write(writer,(config+('\n127.0.0.1' if option == '--connection-fd' else '')).encode()); os.close(writer); writer=-1
                    arguments=[option,str(reader)]
                    if option == '--uri-fd': arguments+=['--server-ips','127.0.0.1']
                    with f.cli(None,extra=arguments,pass_fds=(reader,)) as core:
                        with f.socks_connect(core.port,target.port) as tunnel: f.exchange(tunnel,b'\x00\x00VMess through configuration FD')
                        from pathlib import Path
                        command=Path(f'/proc/{core.process.pid}/cmdline').read_bytes()
                        self.assertNotIn(f.UUID.encode(),command)
                        self.assertNotIn(f.UUID,core.log)
                        core.wait_log('success=1')
                finally:
                    os.close(reader)
                    if writer >= 0: os.close(writer)


    def test_websocket_base64_json_settings(self):
        certificate,_=f.certificate()
        for security in ('none','tls'):
            for early in (0,16384):
                with self.subTest(security=security,early=early),f.Server() as target,f.xray_server('ws',security,protocol='vmess') as reference:
                    value=dict(v='2',add='127.0.0.1',port=reference.port,id=f.UUID,aid='0',scy='aes-128-gcm',net='ws',tls=security,sni='vless-core.test',host='ws.test:8443',path=f'/vless-core?ed={early}',maxEarlyData=early,heartbeatPeriod=1,headers={'X-VMess-Fixture':'JSON'},insecure=False)
                    config='vmess://'+base64.b64encode(json.dumps(value).encode()).decode()
                    with f.cli(config,environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                        with f.socks_connect(core.port,target.port) as tunnel:
                            f.exchange(tunnel,b'\x00\x00JSON WS'+bytes(range(251))*300)
                            tunnel.shutdown(socket.SHUT_WR); self.assertEqual(tunnel.recv(1),b'')

    def test_websocket_modes_early_data_and_headers(self):
        certificate,_=f.certificate()
        payload=b'\x00\x00VMess websocket'+bytes(range(256))*1024
        for security in ('none','tls'):
            for body in ('auto','aes-128-gcm','chacha20-poly1305','none','zero'):
                for early in (0,1,128,16384):
                    with self.subTest(security=security,body=body,early=early),f.Server() as target,f.xray_server('ws',security,protocol='vmess') as reference,f.cli(f.uri(reference.port,'ws',security,protocol='vmess',encryption=body,ed=early,headers=json.dumps({'X-VMess-Fixture':'custom'})),environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                        with f.socks_connect(core.port,target.port) as tunnel:
                            f.exchange(tunnel,payload)
                            f.exchange(tunnel,b'last websocket bytes')

    def test_websocket_first_block_matches_early_data_limit(self):
        import io
        from test_websocket import client_frame
        certificate,_=f.certificate()
        for outer_tls in (False,True):
            for early in (0,1,116,127,128,129,132,133,16384):
                with self.subTest(tls=outer_tls,early=early),f.Server() as target,f.xray_server('ws','none',protocol='vmess') as reference,f.CountingProxy(reference.port,tls=outer_tls) as proxy:
                    options=dict(protocol='vmess',ed=early,encryption='aes-128-gcm',headers=json.dumps({'X-VMess-Fixture':'custom'}),host='vmess-host.test:8443')
                    with f.cli(f.uri(proxy.port,'ws','tls' if outer_tls else 'none',**options),environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                        with f.socks_connect(core.port,target.port) as tunnel:
                            f.exchange(tunnel,b'\x00\x00first block')
                            f.exchange(tunnel,b'not a repeated header')
                        raw=bytes(proxy.client_data[0]); headers,_,frames=raw.partition(b'\r\n\r\n')
                        values=dict(line.split(b':',1) for line in headers.split(b'\r\n')[1:])
                        values={key.lower():value.strip() for key,value in values.items()}
                        encoded=values.get(b'sec-websocket-protocol')
                        if encoded: first=base64.urlsafe_b64decode(encoded+b'='*(-len(encoded)%4))
                        else:
                            reader=type('Reader',(),{'recv':lambda self,size:self.source.read(size)})(); reader.source=io.BytesIO(frames)
                            opcode,first=client_frame(reader); self.assertEqual(opcode,2)
                        self.assertEqual(bool(encoded),early >= len(first))
                        self.assertEqual(values[b'host'],b'vmess-host.test:8443')
                        self.assertEqual(values[b'x-vmess-fixture'],b'custom')

    def test_websocket_server_first_fin_and_heartbeat(self):
        certificate,_=f.certificate()
        for security in ('none','tls'):
            for body in ('aes-128-gcm','chacha20-poly1305','none','zero'):
                def handler(connection):
                    time.sleep(.1)
                    connection.sendall(b'\x00\x00server-first')
                    self.assertEqual(f.exact(connection,4),b'ping')
                    connection.sendall(b'pong')
                with self.subTest(security=security,body=body),f.Server(handler) as target,f.xray_server('ws',security,protocol='vmess') as reference,f.cli(f.uri(reference.port,'ws',security,protocol='vmess',encryption=body,ed=16384,heartbeatPeriod=1),environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                    with f.socks_connect(core.port,target.port) as tunnel:
                        self.assertEqual(f.exact(tunnel,14),b'\x00\x00server-first')
                        time.sleep(1.05)
                        tunnel.sendall(b'ping'); self.assertEqual(f.exact(tunnel,4),b'pong')
                        tunnel.shutdown(socket.SHUT_WR); self.assertEqual(tunnel.recv(1),b'')
        def invalid(connection):
            from test_websocket import upgrade
            upgrade(connection,lambda reply,headers,accept:reply.replace(accept,b'invalid'))
        with f.Server(invalid) as peer,f.cli(f.uri(peer.port,'ws','none',protocol='vmess')) as core:
            with self.assertRaises((AssertionError,EOFError,ConnectionError)):
                with f.socks_connect(core.port,80) as tunnel: tunnel.recv(1)
            core.wait_log('invalid WebSocket upgrade response')

    def test_grpc_base64_json_and_xray_option_names(self):
        certificate,_=f.certificate()
        for security in ('none','tls','reality'):
            for mode in ('gun','multi'):
                with self.subTest(security=security,mode=mode),f.Server() as target,f.xray_server('grpc',security,mode=mode,protocol='vmess') as reference:
                    value=dict(v='2',add='127.0.0.1',port=str(reference.port),id=f.UUID,aid=0,scy='chacha20-poly1305',net='grpc',tls=security,path='vless-core',host='grpc.test',type=mode,multiMode=mode == 'multi',sni='vless-core.test',idle_timeout=0,health_check_timeout=0,permit_without_stream=False,initial_windows_size=1024,user_agent='VMess fixture')
                    if security == 'reality': value.update(pbk=f.PUBLIC_KEY,sid='01020304')
                    config='vmess://'+base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')
                    with f.cli(config,environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                        with f.socks_connect(core.port,target.port) as tunnel:
                            f.exchange(tunnel,b'\x00\x00JSON RPC'+bytes(range(251))*300)
                            tunnel.shutdown(socket.SHUT_WR); self.assertEqual(tunnel.recv(1),b'')

    def test_grpc_security_modes_and_body_algorithms(self):
        certificate,_=f.certificate()
        for security in ('none','tls','reality'):
            for mode in ('gun','multi'):
                for body in ('auto','aes-128-gcm','chacha20-poly1305','none','zero'):
                    with self.subTest(security=security,mode=mode,body=body),f.Server() as target,f.xray_server('grpc',security,mode=mode,protocol='vmess') as reference,f.cli(f.uri(reference.port,'grpc',security,protocol='vmess',encryption=body,mode=mode,initialWindowsSize=1024),environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                        for index in range(2):
                            with f.socks_connect(core.port,target.port) as tunnel:
                                f.exchange(tunnel,b'\x00\x00VMess gRPC'+bytes(range(256))*500+bytes([index]))
                                f.exchange(tunnel,b'last RPC bytes')

    def test_grpc_reuse_parallel_rpc_and_slow_sibling(self):
        import concurrent.futures
        certificate,_=f.certificate()
        payload=bytes(range(251))*600
        for mode in ('gun','multi'):
            with self.subTest(mode=mode),f.Server() as target,f.xray_server('grpc','tls',mode=mode,protocol='vmess') as reference,f.CountingProxy(reference.port) as proxy,f.cli(f.uri(proxy.port,'grpc','tls',protocol='vmess',mode=mode),environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                for _ in range(2):
                    with f.socks_connect(core.port,target.port) as tunnel: f.exchange(tunnel,b'warm VMess RPC')
                def exchange(index):
                    with f.socks_connect(core.port,target.port) as tunnel: f.exchange(tunnel,payload+bytes([index]))
                with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool: list(pool.map(exchange,range(16)))
                self.assertEqual(len(proxy.connections),1)
                def slow(connection):
                    while True: connection.sendall(b's'*65536)
                with f.Server(slow) as download:
                    blocked=f.socks_connect(core.port,download.port)
                    try:
                        time.sleep(.2)
                        for index in range(4): exchange(index)
                    finally: blocked.close()
                with f.socks_connect(core.port,target.port) as tunnel: f.exchange(tunnel,b'after cancelled RPC')

    def test_grpc_server_first_and_fin(self):
        certificate,_=f.certificate()
        for security in ('none','tls','reality'):
            for mode in ('gun','multi'):
                def handler(connection):
                    connection.sendall(b'\x00\x00server-first')
                    self.assertEqual(f.exact(connection,4),b'ping')
                    time.sleep(.1)
                    connection.sendall(b'pong')
                with self.subTest(security=security,mode=mode),f.Server(handler) as target,f.xray_server('grpc',security,mode=mode,protocol='vmess') as reference,f.cli(f.uri(reference.port,'grpc',security,protocol='vmess',mode=mode),environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                    with f.socks_connect(core.port,target.port) as tunnel:
                        self.assertEqual(f.exact(tunnel,14),b'\x00\x00server-first')
                        tunnel.sendall(b'ping'); tunnel.shutdown(socket.SHUT_WR)
                        self.assertEqual(f.exact(tunnel,4),b'pong')
                        self.assertEqual(tunnel.recv(1),b'')

    def test_grpc_fixture_waits_for_its_actual_listener(self):
        import contextlib
        from unittest import mock
        with f.Server(tls=True) as occupied,contextlib.ExitStack() as stack:
            candidate=f.port()
            with mock.patch.object(f,'port',side_effect=[occupied.port,candidate]):
                reference=stack.enter_context(f.xray_server('grpc','tls',protocol='vmess'))
            self.assertEqual(reference.port,candidate)

    def test_destination_addresses_across_transports(self):
        for transport in ('tcp','ws','grpc','xhttp'):
            for address in ('127.0.0.1','localhost','::1'):
                with self.subTest(transport=transport,address=address),f.Server(address='::1' if address == '::1' else '127.0.0.1') as target,f.xray_server(transport,'none',protocol='vmess') as reference,f.cli(f.uri(reference.port,transport,'none',protocol='vmess')) as core:
                    with f.socks_connect(core.port,target.port,address) as tunnel:
                        f.exchange(tunnel,b'\x00\x00destination address'+bytes(range(251))*40)
                        tunnel.shutdown(socket.SHUT_WR); self.assertEqual(tunnel.recv(1),b'')

    def test_xhttp_head_packet_responses(self):
        certificate,_=f.certificate()
        for security,alpn in (('none',None),('tls','h2'),('tls','http/1.1')):
            for pooled in (False,True):
                options=dict(protocol='vmess',mode='packet-up',uplinkHTTPMethod='HEAD',extra=json.dumps({'xmux':{'maxConnections':1}}) if pooled else '{}')
                if alpn: options['alpn']=alpn
                with self.subTest(security=security,alpn=alpn,pooled=pooled),f.Server() as target,f.xray_server('xhttp',security,mode='packet-up',protocol='vmess',uplinkHTTPMethod='HEAD') as reference,f.cli(f.uri(reference.port,'xhttp',security,**options),environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                    for _ in range(2):
                        with f.socks_connect(core.port,target.port) as tunnel:
                            for index in range(4): f.exchange(tunnel,(b'\x00\x00VMess HEAD response'+bytes([index]))*1000)

    def test_xhttp_reality_download_and_parallel_sessions(self):
        import concurrent.futures
        shared=dict(sessionIDPlacement='header',seqPlacement='header')
        for mode in ('stream-up','packet-up'):
            for pooled in (False,True):
                with self.subTest(mode=mode,pooled=pooled),f.Server() as target,f.xray_server('xhttp','reality',path='/',protocol='vmess',**shared) as reference,f.CountingProxy(reference.port) as upload,f.CountingProxy(reference.port,address='127.0.0.2') as download:
                    settings=dict(address='download.invalid',port=download.port,network='xhttp',security='reality',realitySettings=dict(serverName='vless-core.test',publicKey=f.PUBLIC_KEY,shortId='01020304',fingerprint='firefox'),xhttpSettings=dict(path='/download',**shared))
                    extra=dict(downloadSettings=settings,**shared)
                    if pooled: extra['xmux']=dict(maxConnections=1)
                    config=f.uri(upload.port,'xhttp','reality',protocol='vmess',mode=mode,path='/upload',extra=json.dumps(extra)).replace('@127.0.0.1:','@upload.invalid:')
                    with f.cli(config,extra=['--server-ips','127.0.0.1','--download-server-ips','127.0.0.2']) as core:
                        def transfer(index):
                            with f.socks_connect(core.port,target.port) as tunnel: f.exchange(tunnel,b'\x00\x00separate REALITY download'+bytes([index])+bytes(range(251))*1100)
                        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as workers: list(workers.map(transfer,range(4)))
                        self.assertGreater(len(upload.connections),0); self.assertGreater(len(download.connections),0)

    def test_xhttp_modes_security_body_algorithms_and_reuse(self):
        certificate,_=f.certificate()
        payload=b'\x00\x00VMess XHTTP'+bytes(range(251))*1100
        for security,alpn in (('none',None),('tls',None),('tls','http/1.1'),('reality',None)):
            for mode in ('stream-one','stream-up','packet-up'):
                for pooled in (False,True):
                    options=dict(protocol='vmess',mode=mode,extra=json.dumps({'xmux':{'maxConnections':1}}) if pooled else '{}')
                    if alpn: options['alpn']=alpn
                    with self.subTest(security=security,alpn=alpn,mode=mode,pooled=pooled),f.Server() as target,f.xray_server('xhttp',security,mode=mode,protocol='vmess') as reference,f.CountingProxy(reference.port) as proxy:
                        for body in ('auto','aes-128-gcm','chacha20-poly1305','none','zero'):
                            with f.cli(f.uri(proxy.port,'xhttp',security,encryption=body,**options),environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                                for index in range(2):
                                    with f.socks_connect(core.port,target.port) as tunnel:
                                        f.exchange(tunnel,payload+bytes([index]))
                                        f.exchange(tunnel,b'last XHTTP bytes')
                        if not pooled: self.assertGreaterEqual(len(proxy.connections),10)

    def test_xhttp_server_first_and_last_bytes(self):
        certificate,_=f.certificate()
        for mode in ('stream-one','stream-up','packet-up'):
            for pooled in (False,True):
                def handler(connection):
                    connection.sendall(b'\x00\x00server-first')
                    self.assertEqual(f.exact(connection,7),b'client!')
                    time.sleep(.1); connection.sendall(b'last')
                options=dict(protocol='vmess',mode=mode,extra=json.dumps({'xmux':{'maxConnections':1}}) if pooled else '{}')
                with self.subTest(mode=mode,pooled=pooled),f.Server(handler) as target,f.xray_server('xhttp','tls',mode=mode,protocol='vmess') as reference,f.cli(f.uri(reference.port,'xhttp','tls',**options),environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                    with f.socks_connect(core.port,target.port) as tunnel:
                        self.assertEqual(f.exact(tunnel,14),b'\x00\x00server-first')
                        tunnel.sendall(b'client!'); tunnel.shutdown(socket.SHUT_WR)
                        self.assertEqual(f.exact(tunnel,4),b'last')
                        self.assertEqual(tunnel.recv(1),b'')

    def test_xhttp_independent_download_settings_pins_and_json(self):
        certificate,_=f.certificate(); shared=dict(sessionIDPlacement='header',seqPlacement='header')
        for mode in ('stream-up','packet-up'):
            for upload_tls,download_tls in ((False,False),(True,False),(False,True)):
                for pooled in (False,True):
                    with self.subTest(mode=mode,upload_tls=upload_tls,download_tls=download_tls,pooled=pooled),f.Server() as target,f.xray_server('xhttp','none',path='/',protocol='vmess',**shared) as reference,f.CountingProxy(reference.port,tls=upload_tls) as upload,f.CountingProxy(reference.port,address='127.0.0.2',tls=download_tls) as download:
                        settings=dict(address='download.invalid',port=download.port,network='xhttp',security='tls' if download_tls else 'none',xhttpSettings=dict(path='/download',**shared))
                        if download_tls: settings['tlsSettings']=dict(serverName='vless-core.test',alpn=['http/1.1'])
                        extra=dict(downloadSettings=settings,**shared)
                        if pooled: extra['xmux']=dict(maxConnections=1)
                        for encoded in (False,True):
                            if encoded:
                                value=dict(add='upload.invalid',port=upload.port,id=f.UUID,net='xhttp',tls='tls' if upload_tls else '',scy='auto',sni='vless-core.test',mode=mode,path='/upload',extra=extra)
                                if upload_tls: value['alpn']='http/1.1'
                                config='vmess://'+base64.b64encode(json.dumps(value).encode()).decode()
                            else:
                                options=dict(protocol='vmess',mode=mode,path='/upload',extra=json.dumps(extra))
                                if upload_tls: options['alpn']='http/1.1'
                                config=f.uri(upload.port,'xhttp','tls' if upload_tls else 'none',**options).replace('@127.0.0.1:','@upload.invalid:')
                            with f.cli(config,extra=['--server-ips','127.0.0.1','--download-server-ips','127.0.0.2'],environment={'VLESS_CA_BUNDLE':str(certificate)}) as core:
                                for index in range(2):
                                    with f.socks_connect(core.port,target.port) as tunnel: f.exchange(tunnel,b'\x00\x00independent VMess'+bytes(range(251))*300+bytes([index]))
                        self.assertGreater(len(upload.connections),0); self.assertGreater(len(download.connections),0)
                        self.assertIn(b'get /download/',b'\r\n'.join(bytes(data).lower() for data in download.client_data))

if __name__ == '__main__': unittest.main()
