import os
import socket
import subprocess
import unittest
from unittest import mock
import fixtures
from fixtures import BUILD, Server, cli, exact, exchange, socks_connect, uri

class CliTests(unittest.TestCase):
    def test_socks_method_negotiation(self):
        with Server() as target, cli("socks5://127.0.0.1:1",["--routing","1;direct;0"]) as core:
            for methods in (b"\x02",b"\x01\x02",b"\xff",b"\x00",b"\x02\x00",b"\x00\x02",bytes([2])*254+b"\x00"):
                with self.subTest(methods=methods.hex()), socket.create_connection(("127.0.0.1",core.port),timeout=3) as connection:
                    connection.sendall(b"\x05"+bytes([len(methods)])+methods)
                    accepted = b"\x00" in methods
                    self.assertEqual(exact(connection,2),b"\x05\x00" if accepted else b"\x05\xff")
                    if accepted:
                        connection.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01"+target.port.to_bytes(2,"big"))
                        self.assertEqual(exact(connection,10),b"\x05\x00\x00\x01"+bytes(6))
                        exchange(connection,b"vless-core method negotiation")
                    else:
                        self.assertEqual(connection.recv(1),b"")
            self.assertIsNone(core.process.poll(),core.log)

    def test_listener_collision_recovery(self):
        original = fixtures.port
        with Server() as occupied:
            selected = []
            def choose():
                value = occupied.port if not selected else original()
                selected.append(value)
                return value
            with mock.patch("fixtures.port",side_effect=choose), cli("socks5://127.0.0.1:1") as core:
                self.assertNotEqual(core.port,occupied.port)
                self.assertGreaterEqual(len(selected),2)
                self.assertIsNone(core.process.poll(),core.log)
        for message, count in (("invalid configuration",1),("bind: address already in use",3)):
            with self.subTest(message=message), mock.patch("fixtures.Process",side_effect=AssertionError(message)) as failed:
                with self.assertRaisesRegex(AssertionError,message):
                    with cli("socks5://127.0.0.1:1"):
                        self.fail("unexpected listener success")
                self.assertEqual(failed.call_count,count)

    def invoke(self, args, pass_fds=()):
        return subprocess.run([str(BUILD/"vless-core-test"),*args],capture_output=True,text=True,pass_fds=pass_fds,timeout=5)

    def test_help_version_patch(self):
        for option, expected in (("--help","--connection-fd"),("--version","vless-core 1.1.5"),("--openssl-patch-status","unpatched")):
            with self.subTest(option=option):
                result = self.invoke([option]); self.assertEqual(result.returncode,0); self.assertIn(expected,result.stdout+result.stderr)

    def test_invalid_arguments_and_sources(self):
        for args in ([],["--uri","socks5://127.0.0.1","--listen-port","65536"],["--uri-fd","-1","--listen-port","12345"],["--uri","socks5://127.0.0.1","--uri","socks5://127.0.0.2","--listen-port","12345"],["--uri","socks5://127.0.0.1","--listen-port","12345","--route-control-port","1","--route-control-socket","/tmp/vless-core"],["--uri","socks5://127.0.0.1","--listen-port","12345","--route-control-socket","relative"],["--uri","socks5://127.0.0.1","--listen-port","12345","--xray-version","256.0.0"]):
            with self.subTest(args=args):
                self.assertNotEqual(self.invoke(args).returncode,0)

    def test_invalid_base64_keys(self):
        for key in ("!"*43,"A"*42+"!","A"*43+"=!","A"*43+"=A","A"*42+"%20","A"*42+"%2B","A"*42+"%2F","A"*42+"%C2%A0"):
            for parameter, expected in (("security=reality&pbk=","pbk is required"),("encryption=mlkem768x25519plus.native.1rtt.","invalid VLESS encryption relay key")):
                with self.subTest(key=key,parameter=parameter):
                    result = self.invoke(["--uri",uri(443).split("?",1)[0]+"?"+parameter+key,"--listen-port","12345"])
                    self.assertNotEqual(result.returncode,0)
                    self.assertIn(expected,result.stdout+result.stderr)
                    self.assertNotIn("listening on",result.stdout+result.stderr)

    def test_fd_inputs_and_connection_overrides(self):
        for option, data in (("--uri-fd",b"socks5://127.0.0.1:1080#vless-core"),("--connection-fd",b"socks5://no-dns.invalid:1080#vless-core\n127.0.0.1")):
            read, write = os.pipe()
            try:
                os.write(write,data); os.close(write); write = -1
                with cli(None,[option,str(read)],pass_fds=(read,)) as process:
                    self.assertIn("listening on",process.log)
                    self.assertNotIn(data.split(b"\n")[0].decode(),process.log)
            finally:
                os.close(read)
                if write >= 0:
                    os.close(write)
        for data in (b"",b"a\x00b",b"a\nb\nc",b"a\r\nb",b"a"*4609):
            read,write = os.pipe()
            try:
                os.write(write,data); os.close(write); write = -1
                self.assertNotEqual(self.invoke(["--connection-fd",str(read),"--listen-port","12345"],(read,)).returncode,0)
            finally:
                os.close(read)
                if write >= 0:
                    os.close(write)

    def test_routing_direct_block_and_sniff(self):
        with Server() as target:
            for policy, success in (("1;direct;0",True),("1;block;0",False),(f"1;block;0;direct,port,{target.port}",True),("1;block;1",True)):
                with self.subTest(policy=policy):
                    with cli("socks5://127.0.0.1:1",["--routing",policy]) as process:
                        if success:
                            with socks_connect(process.port,target.port) as connection:
                                exchange(connection,b"vless-core direct")
                        else:
                            with self.assertRaises(AssertionError):
                                socks_connect(process.port,target.port)
            with cli("socks5://127.0.0.1:1",["--routing","1;block;0;direct,domain,vless-core.test"]) as process:
                with socks_connect(process.port,target.port) as connection:
                    exchange(connection,b"GET / HTTP/1.1\r\nHost: vless-core.test\r\n\r\n")
                self.assertIn("sniffed",process.log)

    def test_local_listener_and_client_recovery(self):
        with cli("socks5://127.0.0.1:1") as process:
            for _ in range(5):
                with socket.create_connection(("127.0.0.1",process.port),timeout=5) as connection:
                    connection.sendall(b"\x04\x01\x00")
                    self.assertEqual(exact(connection,10)[:2],b"\x05\x01")
            self.assertIsNone(process.process.poll(),process.log)

    def test_network_sandbox(self):
        for host, expected in (("192.0.2.1","network/non-loopback-connect"),("no-network.invalid","network/external-dns")):
            with self.subTest(host=host):
                with cli(f"socks5://{host}:9") as process:
                    with self.assertRaises(AssertionError):
                        socks_connect(process.port,8080)
                    self.assertIn(expected,process.log)

    def test_vless_response_failures(self):
        for response in (b"\x01\x00",b"\x00\x04a"):
            def handler(connection):
                exact(connection,26)
                connection.sendall(response)
            with self.subTest(response=response.hex()), Server(handler) as upstream, cli(uri(upstream.port)) as core:
                with socks_connect(core.port,8080) as tunnel:
                    with self.assertRaises((EOFError,ConnectionError)):
                        exchange(tunnel,b"vless-core")
                self.assertIn("VLESS response read failed",core.log)

    def test_tls_connection_refused(self):
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1",0))
            target_port = reserved.getsockname()[1]
            for transport in ("tcp","ws","xhttp","grpc"):
                with self.subTest(transport=transport), cli(uri(target_port,transport,"tls")) as core:
                    with self.assertRaises(AssertionError):
                        socks_connect(core.port,8080)
                    self.assertIn("tcp connect failed",core.log)
                    self.assertIsNone(core.process.poll(),core.log)

    def test_ipv6_direct_and_vless_server(self):
        with Server(address="::1") as target, cli("socks5://127.0.0.1:1",["--routing","1;direct;0"]) as core:
            with socks_connect(core.port,target.port,"::1") as tunnel:
                exchange(tunnel,b"vless-core IPv6 direct")
        def vless_peer(connection):
            exact(connection,26)
            connection.sendall(b"\x00\x00")
            Server.echo(connection)
        with Server(vless_peer,address="::1") as upstream, cli(uri(upstream.port).replace("@127.0.0.1:","@[::1]:")) as core:
            with socks_connect(core.port,8080) as tunnel:
                exchange(tunnel,b"vless-core IPv6 server")
