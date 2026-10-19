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
