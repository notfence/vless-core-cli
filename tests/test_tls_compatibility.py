import os
import ssl
import subprocess
import unittest
from concurrent.futures import ThreadPoolExecutor

from fixtures import BUILD, OPENSSL, PRIVATE, KEY, PUBLIC_KEY, Process, Server, CountingProxy, certificate, cli, exact, exchange, port, socks_connect, uri, xray_server

FINGERPRINTS=("chrome","edge","qq","firefox","random","randomized")

def hello_layout(data):
    if len(data)<9 or data[:3] not in (b"\x16\x03\x01",b"\x16\x03\x03"):
        raise AssertionError("missing TLS ClientHello record")
    size=int.from_bytes(data[3:5],"big")
    message=data[5:5+size]
    if len(message)!=size or message[0]!=1 or int.from_bytes(message[1:4],"big")!=size-4 or len(message)<42:
        raise AssertionError("invalid ClientHello framing")
    offset=39+message[38]
    count=int.from_bytes(message[offset:offset+2],"big"); offset+=2
    if count%2 or count>len(message)-offset:
        raise AssertionError("invalid ClientHello cipher list")
    def normalized(value):
        return 0x0a0a if value&0x0f0f == 0x0a0a and value>>8 == value&255 else value
    ciphers=tuple(normalized(int.from_bytes(message[index:index+2],"big")) for index in range(offset,offset+count,2))
    offset+=count
    if offset>=len(message): raise AssertionError("missing compression list")
    offset+=1+message[offset]
    if offset+2>len(message) or int.from_bytes(message[offset:offset+2],"big")!=len(message)-offset-2:
        raise AssertionError("invalid ClientHello extension list")
    offset+=2; extensions=[]
    while offset<len(message):
        if offset+4>len(message): raise AssertionError("truncated ClientHello extension")
        kind=int.from_bytes(message[offset:offset+2],"big")
        count=int.from_bytes(message[offset+2:offset+4],"big"); offset+=4
        if count>len(message)-offset: raise AssertionError("truncated ClientHello extension value")
        extensions.append(normalized(kind)); offset+=count
    return ciphers,tuple(extensions)

class TlsCompatibilityTests(unittest.TestCase):
    def test_tls13_certificate_curves_with_each_profile(self):
        for curve in ("secp384r1","secp521r1"):
            cert,key=PRIVATE/f"tls-{curve}.pem",PRIVATE/f"tls-{curve}-key.pem"
            generated=subprocess.run([str(OPENSSL),"req","-config","/dev/null","-new","-x509","-newkey","ec","-pkeyopt",f"ec_paramgen_curve:{curve}","-nodes","-days","2","-subj","/CN=vless-core.test","-addext","subjectAltName=DNS:vless-core.test","-keyout",str(key),"-out",str(cert)],capture_output=True,text=True,timeout=15)
            self.assertEqual(generated.returncode,0,generated.stderr)
            listen=port()
            with Process([str(OPENSSL),"s_server","-accept",f"127.0.0.1:{listen}","-cert",str(cert),"-key",str(key),"-tls1_3","-www"],"tls-curve",{"OPENSSL_CONF":"/dev/null"},ready="ACCEPT") as server:
                for fingerprint in FINGERPRINTS:
                    with self.subTest(curve=curve,fingerprint=fingerprint):
                        result=subprocess.run([str(BUILD/"test_tls_state"),"--http",uri(listen,"tcp","tls",fp=fingerprint)],env=dict(os.environ,VLESS_CA_BUNDLE=str(cert)),capture_output=True,text=True,timeout=10)
                        self.assertEqual(result.returncode,0,result.stdout+result.stderr+server.log)

    def test_tls12_parallel_transfers_and_recovery(self):
        cert,_=certificate(); payload=bytes(range(251))*523
        def finite_response(connection):
            connection.sendall(exact(connection,len(payload)))
            connection.shutdown(1)
        for transport in ("tcp","ws","grpc","xhttp"):
            with self.subTest(transport=transport), Server(finite_response) as target, xray_server(transport,"tls",tls_settings={"minVersion":"1.2","maxVersion":"1.2"}) as reference:
                with cli(uri(reference.port,transport,"tls",fp="firefox"),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                    def transfer(index):
                        with socks_connect(core.port,target.port) as tunnel: exchange(tunnel,payload)
                    try:
                        for iteration in range(5):
                            with ThreadPoolExecutor(max_workers=16) as clients: list(clients.map(transfer,range(16)))
                    except BaseException as error: raise AssertionError(f"{transport}: {error}\n{core.log}\n{reference.log}") from error
                    with socks_connect(core.port,target.port) as tunnel: exchange(tunnel,payload)
                    self.assertIsNone(core.process.poll(),core.log)

    def test_tls12_encryption_vision_and_finish(self):
        cert,_=certificate(); context=ssl.create_default_context(cafile=str(cert)); payload=bytes(range(251))*1045
        def finish(connection):
            while True:
                data=connection.recv(65536)
                if not data: break
                connection.sendall(data)
            raw=connection.unwrap(); raw.shutdown(1); raw.close()
        for transport in ("tcp","ws","grpc","xhttp"):
            with self.subTest(transport=transport), Server(finish,tls=True) as target:
                with xray_server(transport,"tls",flow="xtls-rprx-vision",decryption=f"mlkem768x25519plus.native.60s.{KEY}",tls_settings={"minVersion":"1.2","maxVersion":"1.2"}) as reference:
                    parameters={"flow":"xtls-rprx-vision","encryption":f"mlkem768x25519plus.native.0rtt.{PUBLIC_KEY}"}
                    with cli(uri(reference.port,transport,"tls",fp="firefox",**parameters),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                        try:
                            for index in range(2):
                                with socks_connect(core.port,target.port) as connection, context.wrap_socket(connection,server_hostname="vless-core.test") as tunnel:
                                    exchange(tunnel,payload)
                                    raw=tunnel.unwrap(); raw.shutdown(1)
                                    with raw: self.assertEqual(raw.recv(1),b"")
                        except BaseException as error: raise AssertionError(f"{transport}: {error}\n{core.log}\n{reference.log}") from error

    def test_tls_signature_certificates_and_client_auth(self):
        for algorithm in ("ed25519","rsa-pss"):
            cert,key=PRIVATE/f"tls-{algorithm}.pem",PRIVATE/f"tls-{algorithm}-key.pem"
            command=[str(OPENSSL),"req","-config","/dev/null","-new","-x509","-newkey",algorithm,"-nodes","-days","2","-subj","/CN=vless-core.test","-addext","subjectAltName=DNS:vless-core.test","-keyout",str(key),"-out",str(cert)]
            if algorithm == "rsa-pss": command += ["-pkeyopt","rsa_keygen_bits:2048"]
            generated=subprocess.run(command,capture_output=True,text=True,timeout=15)
            self.assertEqual(generated.returncode,0,generated.stderr)
            for version in ("1_2","1_3"):
                for authentication in (None,"optional","required"):
                    with self.subTest(algorithm=algorithm,version=version,authentication=authentication):
                        listen=port()
                        command=[str(OPENSSL),"s_server","-accept",f"127.0.0.1:{listen}","-cert",str(cert),"-key",str(key),f"-tls{version}","-www"]
                        if authentication: command += ["-Verify" if authentication == "required" else "-verify","1"]
                        with Process(command,"tls-signature",{"OPENSSL_CONF":"/dev/null"},ready="ACCEPT") as server:
                            result=subprocess.run([str(BUILD/"test_tls_state"),"--http",uri(listen,"tcp","tls",fp="firefox")],env=dict(os.environ,VLESS_CA_BUNDLE=str(cert)),capture_output=True,text=True,timeout=10)
                            if authentication == "required": self.assertNotEqual(result.returncode,0,result.stdout+result.stderr+server.log)
                            else: self.assertEqual(result.returncode,0,result.stdout+result.stderr+server.log)

    def profile_layout(self, fingerprint):
        captured=[]
        def handle(connection):
            header=exact(connection,5)
            captured.append(header+exact(connection,int.from_bytes(header[3:5],"big")))
        with Server(handle) as server:
            result=subprocess.run([str(BUILD/"test_tls_state"),uri(server.port,"tcp","tls",fp=fingerprint)],capture_output=True,text=True,timeout=5)
            self.assertEqual(result.returncode,1,result.stdout+result.stderr)
        self.assertTrue(captured,"no profile ClientHello captured")
        return hello_layout(captured[0])

    def test_ordinary_tls_uses_selected_fingerprint(self):
        cert,_=certificate()
        for fingerprint in FINGERPRINTS:
            expected=self.profile_layout(fingerprint)
            for transport in ("ws","xhttp","grpc"):
                with self.subTest(fingerprint=fingerprint,transport=transport), Server() as target, xray_server(transport,"tls") as reference, CountingProxy(reference.port) as wire:
                    with cli(uri(wire.port,transport,"tls",fp=fingerprint),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                        with socks_connect(core.port,target.port) as tunnel: exchange(tunnel,b"vless-core fingerprint")
                        self.assertTrue(wire.client_data)
                        actual=hello_layout(bytes(wire.client_data[0]))
                        self.assertEqual(actual[0],expected[0],core.log)
                        expected_extensions=tuple(value for value in expected[1] if not (transport == "ws" and value == 0x4469))
                        if fingerprint == "qq": self.assertEqual(0x4469 in actual[1],transport != "ws",core.log)
                        if fingerprint in ("random","randomized"):
                            self.assertCountEqual(actual[1],expected_extensions,core.log)
                        else:
                            self.assertEqual(actual[1],expected_extensions,core.log)

    def test_tls12_xray_transports(self):
        cert,_=certificate()
        payload=bytes(range(251))*1045
        for transport in ("tcp","ws","grpc","xhttp"):
            for fingerprint in FINGERPRINTS:
                with self.subTest(transport=transport,fingerprint=fingerprint), Server() as target, xray_server(transport,"tls",tls_settings={"minVersion":"1.2","maxVersion":"1.2"}) as reference, CountingProxy(reference.port) as wire:
                    with cli(uri(wire.port,transport,"tls",fp=fingerprint),environment={"VLESS_CA_BUNDLE":str(cert)}) as core:
                        with socks_connect(core.port,target.port) as tunnel: exchange(tunnel,payload)
                        layout=hello_layout(bytes(wire.client_data[0]))
                        self.assertTrue(any(cipher not in (0x0a0a,0x1301,0x1302,0x1303) for cipher in layout[0]),core.log)
                        self.assertIsNone(core.process.poll(),core.log)

    def test_manual_tls12_cipher_families(self):
        cert,key=certificate()
        ec_ciphers=("ECDHE-ECDSA-CHACHA20-POLY1305","ECDHE-ECDSA-AES128-GCM-SHA256","ECDHE-ECDSA-AES256-GCM-SHA384",
                 "ECDHE-ECDSA-AES128-SHA256","ECDHE-ECDSA-AES256-SHA384","ECDHE-ECDSA-AES128-SHA","ECDHE-ECDSA-AES256-SHA")
        rsa_cert,rsa_key=PRIVATE/"tls12-rsa.pem",PRIVATE/"tls12-rsa-key.pem"
        generated=subprocess.run([str(OPENSSL),"req","-config","/dev/null","-new","-x509","-newkey","rsa:2048","-nodes","-days","2","-subj","/CN=vless-core.test","-addext","subjectAltName=DNS:vless-core.test","-keyout",str(rsa_key),"-out",str(rsa_cert)],capture_output=True,text=True,timeout=15)
        self.assertEqual(generated.returncode,0,generated.stderr)
        rsa_ciphers=("ECDHE-RSA-CHACHA20-POLY1305","ECDHE-RSA-AES128-GCM-SHA256","ECDHE-RSA-AES256-GCM-SHA384",
                     "ECDHE-RSA-AES128-SHA256","ECDHE-RSA-AES256-SHA384","ECDHE-RSA-AES128-SHA","ECDHE-RSA-AES256-SHA",
                     "DHE-RSA-CHACHA20-POLY1305","DHE-RSA-AES128-GCM-SHA256","DHE-RSA-AES256-GCM-SHA384",
                     "DHE-RSA-AES128-SHA256","DHE-RSA-AES256-SHA256","DHE-RSA-AES128-SHA","DHE-RSA-AES256-SHA",
                     "AES128-GCM-SHA256","AES256-GCM-SHA384","AES128-SHA256","AES256-SHA256","AES128-SHA","AES256-SHA")
        for cert,key,ciphers in ((cert,key,ec_ciphers),(rsa_cert,rsa_key,rsa_ciphers)):
            for cipher in ciphers:
                for mac_then_encrypt in (False,True) if "GCM" not in cipher and "CHACHA" not in cipher else (False,):
                    with self.subTest(cipher=cipher,mac_then_encrypt=mac_then_encrypt):
                        listen=port()
                        command=[str(OPENSSL),"s_server","-accept",f"127.0.0.1:{listen}","-cert",str(cert),"-key",str(key),"-tls1_2","-cipher",cipher,"-www"]
                        if mac_then_encrypt: command.append("-no_etm")
                        with Process(command,"tls12-cipher",{"OPENSSL_CONF":"/dev/null"},ready="ACCEPT") as server:
                            result=subprocess.run([str(BUILD/"test_tls_state"),"--http",uri(listen,"tcp","tls",fp="firefox")],env=dict(os.environ,VLESS_CA_BUNDLE=str(cert)),capture_output=True,text=True,timeout=10)
                            self.assertEqual(result.returncode,0,result.stdout+result.stderr+server.log)
