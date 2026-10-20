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


if __name__ == '__main__': unittest.main()
