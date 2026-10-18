import contextlib
import os
import json
import socket
import struct
import threading
import subprocess
import time
import unittest
from unittest import mock
import fixtures
from fixtures import BUILD, Server, cli, exact, exchange, socks_connect, uri

class CliTests(unittest.TestCase):
    def test_invalid_endpoint_never_starts_listener(self):
        configs=("vless://00000000-0000-0000-0000-000000000001@vless-core.test\r\nX-Audit: injected:443?type=ws&security=none",
            uri(443,"ws","none",host="vless-core.test:+80"),
            uri(443,"xhttp","none",downloadSettings=json.dumps({"address":"bad\\host","port":443,"network":"xhttp"})))
        for config in configs:
            for inspect in (False,True):
                with self.subTest(inspect=inspect,index=configs.index(config)):
                    command=[str(BUILD/"vless-core-test"),"--uri-fd","0","--server-ips","127.0.0.1"]
                    if inspect: command.append("--inspect-config")
                    result=subprocess.run(command,input=config,text=True,capture_output=True,timeout=3)
                    self.assertNotEqual(result.returncode,0)
                    self.assertNotIn("listening",result.stdout+result.stderr)
                    self.assertNotIn("X-Audit",result.stdout+result.stderr)

    def test_inspection_is_private_and_offline(self):
        configurations=(("socks5://user:private-vless-core@no-dns.invalid:1080#vless-core", "PRIMARY\tno-dns.invalid\t1080\n"),
            (uri(443,"xhttp","none",downloadSettings=json.dumps({"address":"download.invalid","port":8443,"network":"xhttp"})), "PRIMARY\t127.0.0.1\t443\nDOWNLOAD\tdownload.invalid\t8443\n"))
        for config,endpoints in configurations:
            with self.subTest(config=config.split("?",1)[0].split("@")[-1]):
                result=subprocess.run([str(BUILD/"vless-core-test"),"--inspect-config","--uri-fd","0"],input=config,text=True,capture_output=True,timeout=3)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(result.stdout,"CONFIG\t1\n"+endpoints+"END\n")
                self.assertNotIn("private-vless-core",result.stdout+result.stderr)
                self.assertNotIn("listening",result.stdout+result.stderr)
        result=subprocess.run([str(BUILD/"vless-core-test"),"--inspect-config","--uri-fd","0"],input="vless-core-invalid-secret",text=True,capture_output=True,timeout=3)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(result.stdout,"")
        self.assertNotIn("vless-core-invalid-secret",result.stderr)

    def test_tls_failures_are_not_tcp_refusals(self):
        def alert(connection):
            connection.recv(65536)
            connection.sendall(b"\x15\x03\x03\x00\x02\x02\x28")
        for transport,pins in ((transport,pins) for transport in ("tcp","ws","xhttp","grpc") for pins in ([],["--server-ips","127.0.0.1,127.0.0.2"])):
            with self.subTest(transport=transport,pinned=bool(pins)), Server(alert) as upstream, cli(uri(upstream.port,transport,"tls",allowInsecure="1"),pins) as core:
                with socket.create_connection(("127.0.0.1",core.port),timeout=4) as tunnel:
                    tunnel.sendall(b"\x05\x01\x00"); self.assertEqual(exact(tunnel,2),b"\x05\x00")
                    tunnel.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50")
                    self.assertEqual(exact(tunnel,10)[1],1)
                self.wait_for_probe(core,"transport")
                self.assertRegex(core.wait_log(r"upstream connect failed: .* id=1 stage=transport category=tls system=\d+",regex=True),r"upstream connect failed: .* id=1 stage=transport category=tls system=\d+")

    def test_vless_response_failure_reasons_and_identity(self):
        cases=((b"","no response received"),(b"\x00","truncated header"),(b"\x00\x03x","truncated addons"))
        for response,reason in cases:
            def handler(connection):
                exact(connection,26); connection.sendall(response)
            with self.subTest(reason=reason), Server(handler) as upstream, cli(uri(upstream.port)) as core:
                with socks_connect(core.port,80) as tunnel: self.assertEqual(tunnel.recv(1),b"")
                self.wait_for_probe(core,"protocol")
                self.assertIn(f"VLESS response read failed: {reason} id=1 stage=protocol category=eof system=0",core.wait_log(f"VLESS response read failed: {reason} id=1 stage=protocol category=eof system=0"))

    def test_transport_reset_is_not_a_clean_truncated_response(self):
        def handler(connection):
            exact(connection,26)
            connection.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack("ii",1,0))
        with Server(handler) as upstream, cli(uri(upstream.port)) as core:
            with socks_connect(core.port,80) as tunnel: self.assertEqual(tunnel.recv(1),b"")
            self.wait_for_probe(core,"transport")
            self.assertRegex(core.wait_log(r"VLESS response read failed: transport failure before the complete header id=1 stage=transport category=system system=\d+",regex=True),r"VLESS response read failed: transport failure before the complete header id=1 stage=transport category=system system=\d+")
            self.assertNotIn("truncated header",core.log)

    def test_absolute_incoming_socks_budget(self):
        def upstream(connection):
            exact(connection,26); connection.sendall(b"\x00\x00")
            while True:
                data=connection.recv(4096)
                if not data: return
                connection.sendall(data)
        with Server(upstream) as target, cli(uri(target.port,"tcp","none")) as core:
            with socket.create_connection(("127.0.0.1",core.port),timeout=4) as connection:
                started=time.monotonic(); connection.sendall(b"\x05")
                time.sleep(4); connection.sendall(b"\x01")
                time.sleep(4); connection.sendall(b"\x00")
                self.assertEqual(exact(connection,2),b"\x05\x00")
                self.assertEqual(exact(connection,10),b"\x05\x01\x00\x01"+bytes(6))
                self.assertEqual(connection.recv(1),b"")
                self.assertGreater(time.monotonic()-started,9)
                self.assertLess(time.monotonic()-started,12)
                self.assertFalse(target.connections)
            with socks_connect(core.port,80) as connection: exchange(connection,b"vless-core recovered negotiation slot")

    def test_vless_response_header_uses_remaining_connection_budget(self):
        for initial in ("payload", "server", "fin", "addons"):
            def handler(connection):
                exact(connection,26)
                if initial in ("payload","addons"):
                    self.assertEqual(exact(connection,1),b"A")
                if initial == "fin":
                    self.assertEqual(connection.recv(1),b"")
                connection.sendall(b"\x00\x20" if initial == "addons" else b"\x00")
                if initial == "addons":
                    for _ in range(32):
                        time.sleep(0.03); connection.sendall(b"\x00")
                else:
                    time.sleep(0.8)
            with self.subTest(initial=initial), Server(handler) as target, cli(uri(target.port,"tcp","none"),["--connect-timeout-ms","200"]) as core:
                with socks_connect(core.port,80) as tunnel:
                    tunnel.settimeout(0.65); started=time.monotonic()
                    if initial in ("payload","addons"): tunnel.sendall(b"A")
                    if initial == "fin": tunnel.shutdown(socket.SHUT_WR)
                    self.assertEqual(tunnel.recv(1),b"")
                    self.assertLess(time.monotonic()-started,0.6)
                self.wait_for_probe(core,"protocol")
                self.assertIn("VLESS response deadline expired",core.wait_log("VLESS response deadline expired"))

    def test_vless_initial_local_idle_pauses_remaining_budget(self):
        def handler(connection):
            exact(connection,26); self.assertEqual(exact(connection,1),b"A")
            connection.sendall(b"\x00\x00A")
        with Server(handler) as target, cli(uri(target.port,"tcp","none"),["--connect-timeout-ms","200"]) as core:
            with socks_connect(core.port,80) as tunnel:
                time.sleep(0.45); tunnel.sendall(b"A"); self.assertEqual(exact(tunnel,1),b"A")

    def test_initial_upload_backpressure_does_not_hide_vless_response(self):
        release=threading.Event(); completed=threading.Event(); errors=[]
        payload=b"vless-core duplex before response\x00"*(256*1024)
        def handler(connection):
            exact(connection,26)
            time.sleep(0.25); connection.sendall(b"\x00\x00READY")
            if not release.wait(3): return
            request=bytearray()
            while True:
                block=connection.recv(65536)
                if not block: break
                request.extend(block)
            self.assertEqual(bytes(request),payload)
            connection.sendall(b"DONE"); completed.set()
        with Server(handler) as target, cli(uri(target.port),["--connect-timeout-ms","1000"]) as core:
            with socks_connect(core.port,80) as tunnel:
                tunnel.settimeout(5)
                def upload():
                    try: tunnel.sendall(payload); tunnel.shutdown(socket.SHUT_WR)
                    except OSError as error: errors.append(error)
                sender=threading.Thread(target=upload,daemon=True); sender.start()
                try:
                    self.assertEqual(exact(tunnel,5),b"READY")
                    release.set(); self.assertEqual(exact(tunnel,4),b"DONE")
                    self.assertEqual(tunnel.recv(1),b"")
                    self.assertTrue(completed.wait(1))
                finally:
                    release.set()
                    with contextlib.suppress(OSError): tunnel.shutdown(socket.SHUT_RDWR)
                    sender.join(5)
                self.assertFalse(sender.is_alive()); self.assertFalse(errors,errors)

    def test_complete_vless_header_disables_connection_budget_without_payload(self):
        def handler(connection):
            exact(connection,26); self.assertEqual(exact(connection,1),b"A")
            connection.sendall(b"\x00\x00"); time.sleep(0.45); connection.sendall(b"A")
        with Server(handler) as target, cli(uri(target.port,"tcp","none"),["--connect-timeout-ms","200"]) as core:
            with socks_connect(core.port,80) as tunnel:
                tunnel.sendall(b"A"); self.assertEqual(exact(tunnel,1),b"A")

    def test_complete_vless_header_ends_paused_budget(self):
        ready=threading.Event()
        def handler(connection):
            exact(connection,26); connection.sendall(b"\x00\x00"); ready.set()
            self.assertEqual(exact(connection,1),b"A"); time.sleep(0.3); connection.sendall(b"A")
        with Server(handler) as target, cli(uri(target.port,"tcp","none"),["--connect-timeout-ms","200"]) as core:
            with socks_connect(core.port,80) as tunnel:
                self.assertTrue(ready.wait(1)); time.sleep(0.3)
                tunnel.sendall(b"A"); self.assertEqual(exact(tunnel,1),b"A")

    def test_vless_half_close_preserves_response(self):
        payload=bytes(range(251))*521
        def handler(connection):
            exact(connection,26); request=bytearray()
            while True:
                block=connection.recv(65536)
                if not block: break
                request.extend(block)
            self.assertEqual(bytes(request),payload)
            connection.sendall(b"\x00\x00"+payload[::-1])
        with Server(handler) as target, cli(uri(target.port,"tcp","none")) as core:
            with socks_connect(core.port,80) as tunnel:
                tunnel.sendall(payload); tunnel.shutdown(socket.SHUT_WR)
                self.assertEqual(exact(tunnel,len(payload)),payload[::-1])
                self.assertEqual(tunnel.recv(1),b"")

    def test_vless_remote_fin_preserves_upload(self):
        payload=bytes(range(251))*521; completed=threading.Event()
        def handler(connection):
            exact(connection,26); self.assertEqual(exact(connection,5),b"start")
            connection.sendall(b"\x00\x00"+payload); connection.shutdown(socket.SHUT_WR)
            request=bytearray()
            while True:
                block=connection.recv(65536)
                if not block: break
                request.extend(block)
            self.assertEqual(bytes(request),payload[::-1]); completed.set()
        with Server(handler) as target, cli(uri(target.port,"tcp","none")) as core:
            with socks_connect(core.port,80) as tunnel:
                tunnel.sendall(b"start"); self.assertEqual(exact(tunnel,len(payload)),payload)
                self.assertEqual(tunnel.recv(1),b""); tunnel.sendall(payload[::-1]); tunnel.shutdown(socket.SHUT_WR)
                self.assertTrue(completed.wait(2))

    def test_fragmented_vless_response_does_not_block_upload(self):
        first=threading.Event()
        def handler(connection):
            exact(connection,26); connection.sendall(b"\x00")
            self.assertEqual(exact(connection,1),b"A"); first.set()
            self.assertEqual(exact(connection,1),b"B"); connection.sendall(b"\x00AB")
        with Server(handler) as target, cli(uri(target.port,"tcp","none")) as core:
            with socks_connect(core.port,80) as tunnel:
                tunnel.settimeout(2); tunnel.sendall(b"A"); self.assertTrue(first.wait(1))
                time.sleep(0.05); tunnel.sendall(b"B"); self.assertEqual(exact(tunnel,2),b"AB")

    def test_unknown_uri_fields_are_reported_without_values(self):
        with cli(uri(1,"tcp","none",unknown="vless-core-private-value",host="vless-core-unused-host")) as core:
            self.assertIn("unknown field query.unknown",core.wait_log("unknown field query.unknown"))
            self.assertIn("field query.host",core.wait_log("field query.host"))
            self.assertNotIn("vless-core-private-value",core.log)
            self.assertNotIn("vless-core-unused-host",core.log)

    def test_xhttp_option_warnings_do_not_expose_values(self):
        extra={"noSSEHeader":True,"scMaxBufferedPosts":30,"scStreamUpServerSecs":"20-80","serverMaxHeaderBytes":16384,"unknown":{"private":"vless-core-secret-value"}}
        with cli(uri(1,"xhttp","none",extra=json.dumps(extra))) as core:
            for name in ("noSSEHeader","scMaxBufferedPosts","scStreamUpServerSecs","serverMaxHeaderBytes"):
                self.assertIn(f"server-only field extra.{name}",core.wait_log(f"server-only field extra.{name}"))
                self.assertNotIn(f"unknown field extra.{name}",core.log)
            self.assertIn("unknown field extra.unknown",core.wait_log("unknown field extra.unknown"))
            self.assertNotIn("vless-core-secret-value",core.log)

    def test_absolute_socks_handshake_budget(self):
        def slow(connection):
            exact(connection, 3)
            for byte in b"\x05\x00":
                connection.sendall(bytes([byte])); time.sleep(0.05)
            exact(connection, 10)
            for byte in b"\x05\x00\x00\x01" + bytes(6):
                connection.sendall(bytes([byte])); time.sleep(0.05)
        with Server(slow) as upstream, cli(f"socks5://127.0.0.1:{upstream.port}", ["--connect-timeout-ms", "150"]) as core:
            started = time.monotonic()
            with self.assertRaises(AssertionError):
                with socks_connect(core.port, 8080): pass
            self.assertLess(time.monotonic() - started, 0.5)
            self.wait_for_probe(core, "protocol")

    def test_invalid_connection_budget(self):
        for value in ("0", "-1", "300001", "1ms", "", "999999999999999999999"):
            with self.subTest(value=value):
                result=self.invoke(["--uri","socks5://127.0.0.1:1","--listen-port","12345","--connect-timeout-ms",value])
                self.assertNotEqual(result.returncode,0)
                self.assertIn("invalid connection timeout",result.stderr)
        self.assertNotEqual(self.invoke(["--connect-timeout-ms"]).returncode,0)

    def test_idle_direct_connection_has_no_establishment_timeout(self):
        with Server() as target, cli("socks5://127.0.0.1:1",["--routing","1;direct;0","--connect-timeout-ms","100"]) as core:
            with socks_connect(core.port,target.port) as tunnel:
                time.sleep(0.2)
                exchange(tunnel,b"vless-core idle connection remains usable")

    def test_direct_half_close_preserves_response(self):
        payload = b"vless-core half close" * 4096
        def respond(connection):
            request = bytearray()
            while True:
                block = connection.recv(65536)
                if not block: break
                request.extend(block)
            self.assertEqual(bytes(request), payload)
            connection.sendall(payload[::-1])
        with Server(respond) as target, cli("socks5://127.0.0.1:1", ["--routing", "1;direct;0"]) as core:
            with socks_connect(core.port, target.port) as tunnel:
                tunnel.sendall(payload)
                tunnel.shutdown(socket.SHUT_WR)
                self.assertEqual(exact(tunnel, len(payload)), payload[::-1])
                self.assertEqual(tunnel.recv(1), b"")

    def test_direct_upstream_half_close_preserves_upload(self):
        payload = b"vless-core reverse half close" * 4096
        completed = threading.Event()
        def respond(connection):
            connection.sendall(payload)
            connection.shutdown(socket.SHUT_WR)
            request = bytearray()
            while True:
                block=connection.recv(65536)
                if not block: break
                request.extend(block)
            self.assertEqual(bytes(request),payload[::-1]); completed.set()
        with Server(respond) as target, cli("socks5://127.0.0.1:1",["--routing","1;direct;0"]) as core:
            with socks_connect(core.port,target.port) as tunnel:
                self.assertEqual(exact(tunnel,len(payload)),payload)
                self.assertEqual(tunnel.recv(1),b"")
                tunnel.sendall(payload[::-1]); tunnel.shutdown(socket.SHUT_WR)
                self.assertTrue(completed.wait(2))

    def test_socks_upstream_half_close_preserves_response(self):
        payload=b"vless-core socks half close" * 4096
        def respond(connection):
            exact(connection,3); connection.sendall(b"\x05\x00")
            exact(connection,10); connection.sendall(b"\x05\x00\x00\x01"+bytes(6))
            request=bytearray()
            while True:
                block=connection.recv(65536)
                if not block: break
                request.extend(block)
            self.assertEqual(bytes(request),payload); connection.sendall(payload[::-1])
        with Server(respond) as upstream, cli(f"socks5://127.0.0.1:{upstream.port}") as core:
            with socks_connect(core.port,8080) as tunnel:
                tunnel.sendall(payload); tunnel.shutdown(socket.SHUT_WR)
                self.assertEqual(exact(tunnel,len(payload)),payload[::-1]); self.assertEqual(tunnel.recv(1),b"")

    def test_direct_duplex_with_backpressure(self):
        payload=bytes(range(251))*4096
        def transfer(connection):
            connection.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,4096)
            errors=[]
            def send():
                try: connection.sendall(payload[::-1])
                except BaseException as error: errors.append(error)
            sender=threading.Thread(target=send,daemon=True); sender.start()
            self.assertEqual(exact(connection,len(payload)),payload)
            sender.join(timeout=5); self.assertFalse(sender.is_alive()); self.assertFalse(errors,errors)
        with Server(transfer) as target, cli("socks5://127.0.0.1:1",["--routing","1;direct;0"]) as core:
            with socks_connect(core.port,target.port) as tunnel:
                tunnel.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,4096)
                errors=[]
                def send():
                    try: tunnel.sendall(payload)
                    except BaseException as error: errors.append(error)
                sender=threading.Thread(target=send,daemon=True); sender.start()
                self.assertEqual(exact(tunnel,len(payload)),payload[::-1])
                sender.join(timeout=5); self.assertFalse(sender.is_alive()); self.assertFalse(errors,errors)

    def wait_for_probe(self, core, stage):
        deadline = time.monotonic()+2
        while f"success=0 stage={stage} " not in core.log and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertIn(f"success=0 stage={stage} ",core.wait_log(f"success=0 stage={stage} "))
        self.assertIsNone(core.process.poll(),core.log)

    def test_connection_failure_stage_reports(self):
        for config, stage in (("socks5://no-dns.invalid:1080","dns"),(uri(fixtures.port()),"tcp")):
            with self.subTest(stage=stage), cli(config) as core:
                with self.assertRaises(AssertionError):
                    socks_connect(core.port,8080)
                self.wait_for_probe(core,stage)
        def alert(connection):
            connection.sendall(b"\x15\x03\x03\x00\x02\x02\x28")
        with Server(alert) as upstream, cli(uri(upstream.port,security="tls")) as core:
            with self.assertRaises(AssertionError):
                socks_connect(core.port,8080)
            self.wait_for_probe(core,"transport")
        for stage in ("protocol","carry"):
            def reject(connection):
                exact(connection,26)
                if stage == "carry": connection.sendall(b"\x00\x00")
                self.assertEqual(exact(connection,len(b"vless-core probe")),b"vless-core probe")
            with self.subTest(stage=stage), Server(reject) as upstream, cli(uri(upstream.port)) as core:
                with socks_connect(core.port,8080) as tunnel:
                    tunnel.sendall(b"vless-core probe")
                    self.assertEqual(tunnel.recv(64),b"")
                self.wait_for_probe(core,stage)

    def test_aborted_clients_keep_existing_and_new_connections_alive(self):
        greeting = b"\x05\x01\x00"
        request = b"\x05\x01\x00\x01\x7f\x00\x00\x01\x1f\x90"
        with Server() as target, cli("socks5://127.0.0.1:1",["--routing","1;direct;0"]) as core:
            with socks_connect(core.port,target.port) as active:
                for data in (b"",greeting[:1],greeting,greeting+request[:4],greeting+request):
                    with self.subTest(data=data.hex()):
                        for _ in range(4):
                            with socket.create_connection(("127.0.0.1",core.port),timeout=3) as aborted:
                                aborted.sendall(data)
                                aborted.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack("ii",1,0))
                            time.sleep(0.02)
                            self.assertIsNone(core.process.poll(),core.log)
                        exchange(active,b"vless-core existing connection survives")
                        with socks_connect(core.port,target.port) as recovered:
                            exchange(recovered,b"vless-core new connection survives")

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
        for option, expected in (("--help","--connection-fd"),("--version","vless-core 2.0.0 ("),("--openssl-patch-status","unpatched")):
            with self.subTest(option=option):
                result = self.invoke([option]); self.assertEqual(result.returncode,0); self.assertIn(expected,result.stdout+result.stderr)

    def test_xray_version_strict_argv_env_and_precedence(self):
        invalid=("", "+1.2.3", "1.+2.3", "1.2.+3", "-0.2.3", "1.-0.3", "1.2.-0", " 1.2.3", "1. 2.3", "1.2.3 ",
                 "1.2", "1..3", "1.2.", "1.2.3.4", "1.2.3junk", "256.0.0", "0.256.0", "0.0.256",
                 "4294967296.6.27", "26.4294967296.27", "26.6.4294967296", "18446744073709551616.6.27",
                 "26.6.18446744073709551616", "vless-core-private-version-value")
        for source in ("argv","env"):
            for version in invalid:
                with self.subTest(source=source,version=version):
                    environment=dict(os.environ,XRAY_VER=version if source == "env" else "26.6.27")
                    arguments=[str(BUILD/"vless-core-test"),"--uri-fd","0","--listen-port",str(fixtures.port())]
                    if source == "argv": arguments.extend(["--xray-version",version])
                    with subprocess.Popen(arguments,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=environment) as process:
                        stalled=False
                        try: process.wait(timeout=0.7)
                        except subprocess.TimeoutExpired: stalled=True; process.kill()
                        stdout,stderr=process.communicate(timeout=2)
                        self.assertFalse(stalled,"invalid Xray version reached configuration input")
                        self.assertNotEqual(process.returncode,0)
                        self.assertIn("Xray version",stderr)
                        self.assertNotIn("listening",stdout+stderr)
                        self.assertNotIn("vless-core-private-version-value",stdout+stderr)
        for version in ("0.0.0","255.255.255","026.006.027"):
            with self.subTest(source="env",version=version), cli("socks5://127.0.0.1:1080#vless-core",environment={"XRAY_VER":version}) as core:
                self.assertIsNone(core.process.poll(),core.log)
            with self.subTest(source="argv-priority",version=version), cli("socks5://127.0.0.1:1080#vless-core",extra=["--xray-version",version],
                       environment={"XRAY_VER":"vless-core-private-version-value"}) as core:
                self.assertIsNone(core.process.poll(),core.log)

    def test_invalid_arguments_and_sources(self):
        for args in ([],["--uri","socks5://127.0.0.1","--listen-port","65536"],["--uri-fd","-1","--listen-port","12345"],["--uri","socks5://127.0.0.1","--uri","socks5://127.0.0.2","--listen-port","12345"],["--uri","socks5://127.0.0.1","--listen-port","12345","--route-control-port","1","--route-control-socket","/tmp/vless-core"],["--uri","socks5://127.0.0.1","--listen-port","12345","--route-control-socket","relative"],["--uri","socks5://127.0.0.1","--listen-port","12345","--xray-version","256.0.0"]):
            with self.subTest(args=args):
                self.assertNotEqual(self.invoke(args).returncode,0)

    def test_strict_startup_argument_grammar(self):
        secret="vless-core-private-startup-value"
        config=f"socks5://user:{secret}@127.0.0.1:1080#vless-core"
        listen=str(fixtures.port())
        cases=[]
        for value in (listen+"junk","+"+listen," "+listen,"-"+listen,str((1<<32)+int(listen)),"18446744073709551616"):
            cases.append((["--uri",config,"--listen-port",value],"--listen-port"))
        for option,value in (("--route-control-port","0"),("--connect-timeout-ms","30000"),("--uri-fd","0"),("--connection-fd","0")):
            for invalid in ("+"+value," "+value,"0junk","18446744073709551616"):
                prefix=["--listen-port",listen] if option.endswith("-fd") else ["--uri",config,"--listen-port",listen]
                cases.append(([*prefix,option,invalid],option))
        for option,value in (("--listen-port",listen),("--route-control-port","0"),("--connect-timeout-ms","30000"),("--routing","1;direct;0"),("--route-control-socket","/tmp/vless-core"),("--xray-version","26.6.27")):
            base=["--uri",config,"--listen-port",listen]
            cases.append(([*base,option,value,option,value],option))
            cases.append(([*base,option],option))
        cases += [(["--uri",config,"--listen-port",listen,"--unknown-startup-option"],"unknown"),
                  (["--uri",config,"--listen-port",listen,secret],"unknown")]
        for args,field in cases:
            with self.subTest(field=field,args=args):
                with subprocess.Popen([str(BUILD/"vless-core-test"),*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) as process:
                    stalled=False
                    try: stdout,stderr=process.communicate(timeout=0.7)
                    except subprocess.TimeoutExpired:
                        stalled=True; process.kill(); stdout,stderr=process.communicate(timeout=2)
                    self.assertFalse(stalled,"invalid arguments did not exit before starting work")
                    self.assertNotEqual(process.returncode,0)
                    self.assertNotIn("listening on",stdout+stderr)
                    self.assertIn(field,stdout+stderr)
                    self.assertNotIn(secret,stdout+stderr)

    def test_argument_validation_precedes_configuration_fd_read(self):
        with subprocess.Popen([str(BUILD/"vless-core-test"),"--uri-fd","0","--listen-port",str(fixtures.port()),"--unknown-startup-option"],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) as process:
            stalled=False
            try: process.wait(timeout=0.7)
            except subprocess.TimeoutExpired: stalled=True; process.kill(); process.wait(timeout=2)
            stdout=process.stdout.read(); stderr=process.stderr.read()
            self.assertFalse(stalled,"configuration was read before argument validation")
            self.assertNotEqual(process.returncode,0)
            self.assertIn("unknown",stderr)
            self.assertNotIn("listening on",stdout+stderr)

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
                    self.assertIn("listening on",process.wait_log("listening on"))
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
                self.assertIn("sniffed",process.wait_log("sniffed"))

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
                    self.assertIn(expected,process.wait_log(expected))

    def test_vless_response_failures(self):
        for response in (b"\x01\x00",b"\x00\x04a"):
            def handler(connection):
                exact(connection,26)
                connection.sendall(response)
            with self.subTest(response=response.hex()), Server(handler) as upstream, cli(uri(upstream.port)) as core:
                with socks_connect(core.port,8080) as tunnel:
                    with self.assertRaises((EOFError,ConnectionError)):
                        exchange(tunnel,b"vless-core")
                self.assertIn("VLESS response read failed",core.wait_log("VLESS response read failed"))

    def test_tls_connection_refused(self):
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1",0))
            target_port = reserved.getsockname()[1]
            for transport in ("tcp","ws","xhttp","grpc"):
                with self.subTest(transport=transport), cli(uri(target_port,transport,"tls")) as core:
                    with socket.create_connection(("127.0.0.1",core.port),timeout=4) as tunnel:
                        tunnel.sendall(b"\x05\x01\x00"); self.assertEqual(exact(tunnel,2),b"\x05\x00")
                        tunnel.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x1f\x90")
                        self.assertEqual(exact(tunnel,10)[1],5)
                    self.assertIn("tcp connect failed",core.wait_log("tcp connect failed"))
                    self.wait_for_probe(core,"tcp")
                    self.assertRegex(core.wait_log(r"upstream connect failed: .* id=1 stage=tcp category=system system=\d+",regex=True),r"upstream connect failed: .* id=1 stage=tcp category=system system=\d+")
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
