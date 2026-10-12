import socket
import os
import ssl
import unittest
from fixtures import Server, certificate, cli, exact, exchange, socks_connect

class Upstream(Server):
    def __init__(self, auth=False, reject=False, reply_type=1, method_response=None, auth_response=None, connect_response=None):
        self.auth, self.reject, self.targets, self.credentials, self.reply_type = auth, reject, [], [], reply_type
        self.method_response, self.auth_response, self.connect_response = method_response, auth_response, connect_response
        super().__init__(self.handle)

    def handle(self, connection):
        version, count = exact(connection,2)
        if version != 5:
            raise AssertionError("upstream version")
        methods = exact(connection,count)
        method = 2 if self.auth else 0
        if method not in methods:
            raise AssertionError("upstream method not offered")
        if self.method_response is not None:
            connection.sendall(self.method_response)
            return
        for byte in bytes([5,method]):
            connection.sendall(bytes([byte]))
        if self.auth:
            version, length = exact(connection,2)
            user = exact(connection,length)
            password = exact(connection,exact(connection,1)[0])
            self.credentials.append((user,password))
            if self.auth_response is not None:
                connection.sendall(self.auth_response)
                return
            connection.sendall(bytes([1,1 if self.reject else 0]))
            if self.reject:
                return
        header = exact(connection,4)
        if header[:3] != b"\x05\x01\x00":
            raise AssertionError(header.hex())
        if header[3] == 1:
            target = socket.inet_ntop(socket.AF_INET,exact(connection,4))
        elif header[3] == 4:
            target = socket.inet_ntop(socket.AF_INET6,exact(connection,16))
        else:
            target = exact(connection,exact(connection,1)[0]).decode()
        target_port = int.from_bytes(exact(connection,2),"big")
        self.targets.append((target,target_port))
        if self.connect_response is not None:
            connection.sendall(self.connect_response)
            return
        tail = {1:b"\x7f\x00\x00\x01",4:socket.inet_pton(socket.AF_INET6,"::1"),3:b"\x0fvless-core.test"}[self.reply_type]
        for byte in b"\x05\x00\x00"+bytes([self.reply_type])+tail+b"\x00\x00":
            connection.sendall(bytes([byte]))
        if target_port == 443:
            cert,key = certificate(); context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert,key)
            with context.wrap_socket(connection,server_side=True) as secure:
                self.echo(secure)
        else:
            self.echo(connection)

class SocksTests(unittest.TestCase):
    def test_ignored_uri_fields_warn_without_values(self):
        with Upstream() as upstream, cli(f"socks5://127.0.0.1:{upstream.port}?security=none&type=xhttp&extra=secret-private-parameter&fp=not-applied&allowInsecure=true") as core:
            with socks_connect(core.port,8080) as tunnel: exchange(tunnel,b"vless-core unchanged SOCKS transport")
            for field in ("transport","extra","fp","allowinsecure"): self.assertIn(f"query.{field} is not applied to SOCKS5",core.log)
            self.assertNotIn("secret-private-parameter",core.log)
            self.assertNotIn("not-applied",core.log)

    def wire_reply(self, core, request):
        with socket.create_connection(("127.0.0.1",core.port),timeout=3) as connection:
            connection.sendall(b"\x05\x01\x00"); self.assertEqual(exact(connection,2),b"\x05\x00")
            connection.sendall(request)
            return exact(connection,10)[1]

    def test_invalid_local_requests_and_reply_codes(self):
        address=b"\x7f\x00\x00\x01\x1f\x90"
        cases=((b"\x05\x02\x00\x01"+address,7),(b"\x05\x03\x00\x01"+address,7),
               (b"\x05\x01\x00\xff",8),(b"\x05\x01\x01\x01"+address,1),
               (b"\x04\x01\x00\x01"+address,1),(b"\x05\x01\x00\x01"+address[:-2]+bytes(2),1),
               (b"\x05\x01\x00\x03\x03a\x00b\x1f\x90",1),(b"\x05\x01\x00\x03\x03a\nb\x1f\x90",1))
        with Upstream() as upstream, cli(f"socks5://127.0.0.1:{upstream.port}") as core:
            for request,expected in cases:
                with self.subTest(request=request): self.assertEqual(self.wire_reply(core,request),expected)
            self.assertEqual(upstream.targets,[])

    def test_upstream_reply_reason_is_preserved(self):
        request=b"\x05\x01\x00\x01\x7f\x00\x00\x01\x1f\x90"
        for code in range(1,9):
            response=bytes([5,code,0,1])+b"\x7f\x00\x00\x01\x00\x00"
            with self.subTest(code=code), Upstream(connect_response=response) as upstream, cli(f"socks5://127.0.0.1:{upstream.port}") as core:
                self.assertEqual(self.wire_reply(core,request),code)

    def test_malformed_upstream_addresses_are_general_failure(self):
        request=b"\x05\x01\x00\x01\x7f\x00\x00\x01\x1f\x90"
        responses=(b"\x05\x00\x01\x01\x7f\x00\x00\x01\x00\x00",b"\x05\x09\x00\x01\x7f\x00\x00\x01\x00\x00",
                   b"\x05\x00\x00\x03\x00\x00\x00",b"\x05\x00\x00\x03\x03a\x00b\x00\x00",b"\x05\x00\x00\x03\x03a\nb\x00\x00")
        for response in responses:
            with self.subTest(response=response), Upstream(connect_response=response) as upstream, cli(f"socks5://127.0.0.1:{upstream.port}") as core:
                self.assertEqual(self.wire_reply(core,request),1)

    def test_authentication_denial_is_forbidden(self):
        request=b"\x05\x01\x00\x01\x7f\x00\x00\x01\x1f\x90"
        with Upstream(auth=True,reject=True) as upstream, cli(f"socks5://vless-core:secret@127.0.0.1:{upstream.port}") as core:
            self.assertEqual(self.wire_reply(core,request),2)
            self.assertNotIn("secret",core.log)

    def assert_rejected(self, upstream, expected, credentials=""):
        with cli(f"socks5://{credentials}127.0.0.1:{upstream.port}") as core:
            with self.assertRaises(AssertionError):
                socks_connect(core.port,8080)
            self.assertIn(expected,core.log)
            self.assertIsNone(core.process.poll(),core.log)
            if credentials:
                self.assertNotIn(credentials,core.log)
                self.assertNotIn("secret",core.log)

    def test_invalid_method_responses(self):
        responses = ((b"", "method negotiation read failed"), (b"\x05", "method negotiation read failed"), (b"\x04\x00", "method negotiation read failed"), (b"\x05\xff", "rejected authentication methods"), (b"\x05\x01", "unsupported auth method"), (b"\x05\x02", "unsupported auth method"))
        for response, expected in responses:
            with self.subTest(response=response.hex()), Upstream(method_response=response) as upstream:
                self.assert_rejected(upstream,expected)

    def test_invalid_authentication_responses(self):
        for response in (b"",b"\x01",b"\x02\x00",b"\x01\x01"):
            with self.subTest(response=response.hex()), Upstream(auth=True,auth_response=response) as upstream:
                self.assert_rejected(upstream,"username/password auth failed","vless-core:secret@")

    def test_rejected_connect_codes(self):
        for code in range(1,9):
            response = bytes([5,code,0,1])+b"\x7f\x00\x00\x01\x00\x00"
            with self.subTest(code=code), Upstream(connect_response=response) as upstream:
                self.assert_rejected(upstream,f"CONNECT rejected target with code 0x{code:02x}")

    def test_invalid_and_truncated_connect_responses(self):
        replies = (b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00",b"\x05\x00\x00\x04"+socket.inet_pton(socket.AF_INET6,"::1")+b"\x00\x00",b"\x05\x00\x00\x03\x0fvless-core.test\x00\x00")
        for reply in replies:
            for cut in range(len(reply)):
                with self.subTest(address_type=reply[3],cut=cut), Upstream(connect_response=reply[:cut]) as upstream:
                    expected = "CONNECT response read failed" if cut < 4 else "CONNECT bind address read failed"
                    self.assert_rejected(upstream,expected)
        for response, expected in ((b"\x04\x00\x00\x01\x7f\x00\x00\x01\x00\x00","CONNECT response read failed"),(b"\x05\x00\x00\xff","CONNECT bind address read failed")):
            with self.subTest(response=response.hex()), Upstream(connect_response=response) as upstream:
                self.assert_rejected(upstream,expected)

    def test_maximum_credentials(self):
        for length in (1,255):
            user, password = "u"*length, "p"*length
            with self.subTest(length=length), Upstream(auth=True) as upstream, cli(f"socks5://{user}:{password}@127.0.0.1:{upstream.port}") as core:
                with socks_connect(core.port,8080) as tunnel:
                    exchange(tunnel,b"vless-core credentials")
                self.assertEqual(upstream.credentials,[(user.encode(),password.encode())])
                self.assertNotIn(f"{user}:{password}@",core.log)

    def test_recovery_after_upstream_failure(self):
        for stage in ("method","auth","connect"):
            arguments = {"auth":True,"method_response":b"\x05\xff"} if stage == "method" else {"auth":True,stage+"_response":b"\x01\x01" if stage == "auth" else b"\x05\x05\x00\x01\x7f\x00\x00\x01\x00\x00"}
            with self.subTest(stage=stage), Upstream(**arguments) as upstream, cli(f"socks5://vless-core:secret@127.0.0.1:{upstream.port}") as core:
                with self.assertRaises(AssertionError):
                    socks_connect(core.port,8080)
                setattr(upstream,stage+"_response",None)
                with socks_connect(core.port,8080) as tunnel:
                    exchange(tunnel,b"vless-core recovered")
                self.assertIsNone(core.process.poll(),core.log)

    def test_ipv6_upstream(self):
        with Upstream() as protocol:
            with Server(protocol.handle,address="::1") as upstream, cli(f"socks5://[::1]:{upstream.port}") as core:
                with socks_connect(core.port,8080) as tunnel:
                    exchange(tunnel,b"vless-core IPv6 SOCKS server")
                self.assertEqual(protocol.targets,[("127.0.0.1",8080)])

    def test_addresses_auth_and_fragmented_responses(self):
        for auth in (False,True):
            with Upstream(auth) as upstream:
                credentials = "vless-core:p%40ss@" if auth else ""
                with cli(f"socks5://{credentials}127.0.0.1:{upstream.port}") as core:
                    for target in ("127.0.0.1","::1","vless-core.test"):
                        with self.subTest(auth=auth,target=target):
                            with socks_connect(core.port,8080,target) as connection:
                                exchange(connection,bytes(range(251))*1024)
                    self.assertEqual(upstream.targets,[(target,8080) for target in ("127.0.0.1","::1","vless-core.test")])
                    if auth:
                        self.assertEqual(upstream.credentials,[(b"vless-core",b"p@ss")]*3)
                        self.assertNotIn("p@ss",core.log)

    def test_pre_resolved_addresses_no_dns(self):
        with Upstream() as upstream:
            with cli(f"socks5://no-dns.invalid:{upstream.port}",["--server-ips","127.0.0.2,127.0.0.1"]) as core:
                with socks_connect(core.port,8080,"vless-core.test") as connection:
                    exchange(connection,b"vless-core pre-resolved")
                self.assertIn(("vless-core.test",8080),upstream.targets)

    def test_pre_resolved_ipv6_addresses_no_dns(self):
        with Upstream() as protocol, Server(protocol.handle,address="::1") as upstream:
            with cli(f"socks5://no-dns.invalid:{upstream.port}",["--server-ips","127.0.0.2,::1"]) as core:
                with socks_connect(core.port,8080) as connection:
                    exchange(connection,b"vless-core pre-resolved IPv6")
            read_fd, write_fd=os.pipe()
            try:
                os.write(write_fd,f"socks5://no-dns.invalid:{upstream.port}\n::1,127.0.0.2".encode()); os.close(write_fd); write_fd=-1
                with cli(None,["--connection-fd",str(read_fd)],pass_fds=(read_fd,)) as core:
                    with socks_connect(core.port,8080) as connection:
                        exchange(connection,b"vless-core connection descriptor IPv6")
            finally:
                os.close(read_fd)
                if write_fd >= 0: os.close(write_fd)

    def test_rejected_authentication(self):
        with Upstream(auth=True,reject=True) as upstream:
            with cli(f"socks5://vless-core:wrong@127.0.0.1:{upstream.port}") as core:
                with self.assertRaises(AssertionError):
                    socks_connect(core.port,8080)
                self.assertIn("auth failed",core.log.lower())

    def test_upstream_bind_address_formats(self):
        for reply_type in (1,3,4):
            with self.subTest(reply_type=reply_type), Upstream(reply_type=reply_type) as upstream, cli(f"socks5://127.0.0.1:{upstream.port}") as core:
                with socks_connect(core.port,8080) as tunnel:
                    exchange(tunnel,b"vless-core bind address")

    def test_transparent_tls_sni(self):
        cert,_ = certificate()
        with Upstream() as upstream, cli(f"socks5://127.0.0.1:{upstream.port}") as core:
            with socks_connect(core.port,443) as connection:
                context = ssl.create_default_context(cafile=str(cert))
                with context.wrap_socket(connection,server_hostname="vless-core.test") as secure:
                    exchange(secure,b"vless-core transparent TLS")
            self.assertEqual(upstream.targets,[("vless-core.test",443)])
