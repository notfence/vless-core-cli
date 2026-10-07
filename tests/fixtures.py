import base64
import contextlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import threading
import time
import urllib.parse

BUILD = Path(os.environ.get("TEST_BUILD_DIR", Path(__file__).resolve().parents[1] / "build/host-tests"))
OPENSSL = Path(os.environ.get("TEST_OPENSSL_PREFIX", Path.home() / ".local/openssl-3.5")) / "bin/openssl"
XRAY = Path(os.environ.get("TEST_XRAY_BIN", Path(__file__).resolve().parents[2] / "tools/xray-v26.6.27-linux-64/xray"))
PRIVATE = Path(os.environ["TEST_PRIVATE_ROOT"])
UUID = "00000000-0000-0000-0000-000000000001"
KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHl8"
PUBLIC_KEY = "j0DFrbaPJWJK5bIU6nZ6bslNgp09e14a0bpvPiE4KF8"

def exact(connection, length):
    data = bytearray()
    while len(data) < length:
        try:
            block = connection.recv(length - len(data))
        except TimeoutError as error:
            raise TimeoutError(f"expected {length} bytes, received {len(data)} before timeout") from error
        if not block:
            raise EOFError(f"expected {length} bytes, received {len(data)}")
        data.extend(block)
    return bytes(data)

def port():
    with socket.socket() as connection:
        connection.bind(("127.0.0.1", 0))
        return connection.getsockname()[1]

def uri(server_port, transport="tcp", security="none", **parameters):
    query = dict(type=transport, security=security, sni="vless-core.test", path="/vless-core", serviceName="vless-core")
    query.update(parameters)
    if security == "reality":
        query.update(pbk=PUBLIC_KEY, sid="01020304")
    return f"vless://{UUID}@127.0.0.1:{server_port}?{urllib.parse.urlencode(query)}#vless-core"

def certificate():
    cert, key = PRIVATE / "certificate.pem", PRIVATE / "key.pem"
    if not cert.exists():
        result = subprocess.run([str(OPENSSL), "req", "-config", "/dev/null", "-new", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "2", "-subj", "/CN=vless-core.test", "-addext", "subjectAltName=DNS:vless-core.test,IP:127.0.0.1", "-keyout", str(key), "-out", str(cert)], capture_output=True, text=True, timeout=15)
        if result.returncode:
            raise AssertionError(result.stderr)
    return cert, key

class Process:
    def __init__(self, command, label, environment=None, ready=None, pass_fds=()):
        self.coverage = Path(command[0]).name == "vless-core-test" and "--coverage" in os.environ.get("TEST_HOST_FLAGS", "")
        self.path = BUILD / f"{label}-{time.monotonic_ns()}.log"
        self.file = self.path.open("wb")
        env = dict(os.environ)
        for name in ("VLESS_TLS_MODE", "VLESS_XHTTP_TLS_MODE", "VLESS_XHTTP_PIN_FILE", "VLESS_CA_BUNDLE", "XRAY_VER", "SSL_CERT_FILE", "SSL_CERT_DIR", "OPENSSL_CONF", "OPENSSL_MODULES"):
            env.pop(name, None)
        env.update(environment or {})
        self.process = subprocess.Popen(command, stdout=self.file, stderr=subprocess.STDOUT, env=env, pass_fds=pass_fds, start_new_session=True)
        try:
            if ready:
                deadline = time.monotonic() + 5
                while ready not in self.log:
                    if self.process.poll() is not None or time.monotonic() >= deadline:
                        raise AssertionError(f"process not ready: {command[0]}\n{self.log}\nlog: {self.path}")
                    time.sleep(0.01)
        except BaseException:
            self.close()
            raise

    @property
    def log(self):
        return self.path.read_text(errors="replace")

    def close(self):
        stopped = False
        if self.process.poll() is None:
            stopped = True
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        self.file.close()
        if stopped and self.coverage and "PASS coverage/cli-flush" not in self.log:
            raise AssertionError(f"CLI coverage was not flushed: {self.path}\n{self.log}")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

def start_listener(command, label, ready, environment=None, pass_fds=()):
    for attempt in range(3):
        listen_port = port()
        try:
            process = Process(command(listen_port),label,environment,ready,pass_fds)
        except AssertionError as error:
            detail = str(error).lower()
            if attempt < 2 and "bind" in detail and "address already in use" in detail:
                continue
            raise
        process.port = listen_port
        return process

class Server:
    def __init__(self, handler=None, tls=False, address="127.0.0.1"):
        self.listener = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((address, 0))
        self.listener.listen(128)
        self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.handler = handler or self.echo
        self.stop = threading.Event()
        self.connections, self.workers, self.errors = [], [], []
        self.lock = threading.Lock()
        self.context = None
        if tls:
            cert, key = certificate()
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.context.minimum_version = ssl.TLSVersion.TLSv1_3
            self.context.maximum_version = ssl.TLSVersion.TLSv1_3
            self.context.load_cert_chain(cert, key)
            self.context.set_alpn_protocols(["h2", "http/1.1"])
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    @staticmethod
    def echo(connection):
        while True:
            data = connection.recv(65536)
            if not data:
                return
            connection.sendall(data)

    def accept(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            connection.settimeout(20)
            with self.lock:
                self.connections.append(connection)
            worker = threading.Thread(target=self.serve, args=(connection,), daemon=True)
            self.workers.append(worker)
            worker.start()

    def serve(self, connection):
        try:
            if self.context:
                connection = self.context.wrap_socket(connection, server_side=True)
                with self.lock:
                    self.connections.append(connection)
            self.handler(connection)
        except (EOFError, ConnectionError, ssl.SSLError):
            pass
        except OSError:
            if not self.stop.is_set():
                self.errors.append("unexpected server socket error")
        except BaseException as error:
            self.errors.append(repr(error))
        finally:
            connection.close()

    def close(self):
        self.stop.set()
        self.listener.close()
        self.thread.join(timeout=2)
        with self.lock:
            for connection in self.connections:
                with contextlib.suppress(OSError):
                    connection.shutdown(socket.SHUT_RDWR)
                connection.close()
        for worker in self.workers:
            worker.join(timeout=2)
            if worker.is_alive():
                self.errors.append("server worker did not stop")
        if self.errors:
            raise AssertionError(self.errors)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

@contextlib.contextmanager
def cli(config, extra=(), environment=None, pass_fds=()):
    def command(listen_port):
        args = [str(BUILD / "vless-core-test"), "--listen-port", str(listen_port)]
        if config is not None:
            args.extend(["--uri", config])
        return [*args,*extra]
    with start_listener(command,"cli","listening on",environment,pass_fds) as process:
        yield process

def socks_connect(listen_port, target_port, target="127.0.0.1"):
    connection = socket.create_connection(("127.0.0.1", listen_port), timeout=15)
    try:
        connection.sendall(b"\x05\x01\x00")
        if exact(connection, 2) != b"\x05\x00":
            raise AssertionError("SOCKS method response")
        try:
            address = b"\x01" + socket.inet_pton(socket.AF_INET, target)
        except OSError:
            try:
                address = b"\x04" + socket.inet_pton(socket.AF_INET6, target)
            except OSError:
                address = b"\x03" + bytes([len(target)]) + target.encode()
        connection.sendall(b"\x05\x01\x00" + address + target_port.to_bytes(2, "big"))
        header = exact(connection, 4)
        if header[:2] != b"\x05\x00":
            raise AssertionError(f"SOCKS CONNECT failed: {header.hex()}")
        size = {1:4,4:16}.get(header[3])
        if size is None:
            size = exact(connection, 1)[0]
        exact(connection, size+2)
        return connection
    except BaseException:
        connection.close()
        raise

@contextlib.contextmanager
def xray_tls_target(groups=None):
    cert, key = certificate()
    settings = {"minVersion":"1.3", "maxVersion":"1.3", "alpn":["h2", "http/1.1"], "certificates":[{"certificateFile":str(cert), "keyFile":str(key)}]}
    if groups:
        settings["curvePreferences"] = groups
    config = {"log":{"loglevel":"info"}, "inbounds":[{"listen":"127.0.0.1", "port":0, "protocol":"vless", "settings":{"clients":[{"id":UUID}], "decryption":"none"}, "streamSettings":{"network":"raw", "security":"tls", "tlsSettings":settings}}], "outbounds":[{"protocol":"blackhole"}]}
    def command(listen_port):
        config["inbounds"][0]["port"] = listen_port
        path = PRIVATE / f"reality-target-{listen_port}.json"
        path.write_text(json.dumps(config))
        return [str(XRAY), "run", "-c", str(path)]
    with start_listener(command, "reality-target", "started") as process:
        yield process

@contextlib.contextmanager
def xray_server(transport, security, mode=None, flow="", decryption="none", tls_certificate=None, reality_target_groups=None, **transport_parameters):
    cert, key = certificate()
    cert = tls_certificate or cert
    with contextlib.ExitStack() as stack:
        stream = {"network": "raw" if transport == "tcp" else transport, "security": security}
        if transport == "ws":
            stream["wsSettings"] = {"path":"/vless-core"}
        elif transport == "xhttp":
            stream["xhttpSettings"] = {"path":"/vless-core", "mode":mode or "auto", **transport_parameters}
        elif transport == "grpc":
            stream["grpcSettings"] = {"serviceName":"vless-core", "multiMode":mode == "multi"}
        if security == "tls":
            stream["tlsSettings"] = {"alpn":["h2", "http/1.1"], "certificates":[{"certificateFile":str(cert),"keyFile":str(key)}]}
        elif security == "reality":
            mask = stack.enter_context(xray_tls_target(reality_target_groups))
            stream["realitySettings"] = {"target":f"127.0.0.1:{mask.port}", "serverNames":["vless-core.test"], "privateKey":KEY, "shortIds":["01020304"], "maxTimeDiff":60000}
        config = {"log":{"loglevel":"info"}, "inbounds":[{"listen":"127.0.0.1", "port":0, "protocol":"vless", "settings":{"clients":[{"id":UUID,"flow":flow}],"decryption":decryption}, "streamSettings":stream}], "outbounds":[{"protocol":"freedom","settings":{"domainStrategy":"AsIs"},"tag":"local"},{"protocol":"blackhole","tag":"deny"}], "routing":{"rules":[{"type":"field","ip":["127.0.0.0/8","::1/128"],"outboundTag":"local"},{"type":"field","network":"tcp,udp","outboundTag":"deny"}]}}
        config["outbounds"][0]["settings"]["finalRules"] = [{"action":"allow","ip":["127.0.0.0/8","::1/128"]}]
        def command(listen_port):
            config["inbounds"][0]["port"] = listen_port
            path = PRIVATE/f"xray-{listen_port}.json"
            path.write_text(json.dumps(config))
            return [str(XRAY),"run","-c",str(path)]
        process = stack.enter_context(start_listener(command,"xray","started"))
        yield process

@contextlib.contextmanager
def xray_client(server_port, transport="tcp", security="reality", mode=None, flow="", encryption="none", extra=None, fingerprint="firefox"):
    cert, _ = certificate()
    stream = {"network":"raw" if transport == "tcp" else transport, "security":security}
    if security == "reality":
        stream["realitySettings"] = {"serverName":"vless-core.test", "fingerprint":fingerprint, "publicKey":PUBLIC_KEY, "shortId":"01020304"}
    elif security == "tls":
        stream["tlsSettings"] = {"serverName":"vless-core.test", "fingerprint":fingerprint, "certificates":[{"certificateFile":str(cert), "usage":"verify"}]}
    if transport == "xhttp":
        stream["xhttpSettings"] = {"path":"/vless-core", "mode":mode or "auto", **(extra or {})}
    config = {"log":{"loglevel":"info"}, "inbounds":[{"listen":"127.0.0.1", "port":0, "protocol":"socks", "settings":{"auth":"noauth", "udp":False}}], "outbounds":[{"protocol":"vless", "settings":{"vnext":[{"address":"127.0.0.1", "port":server_port, "users":[{"id":UUID, "encryption":encryption, "flow":flow}]}]}, "streamSettings":stream}]}
    def command(listen_port):
        config["inbounds"][0]["port"] = listen_port
        path = PRIVATE / f"reference-client-{listen_port}.json"
        path.write_text(json.dumps(config))
        return [str(XRAY), "run", "-c", str(path)]
    with start_listener(command, "reference-client", "started") as process:
        yield process

def exchange(connection, data):
    received = bytearray()
    size = 8192 if isinstance(connection,ssl.SSLSocket) else len(data)
    for offset in range(0,len(data),size):
        block = data[offset:offset+size]
        connection.sendall(block)
        received.extend(exact(connection,len(block)))
    if received != data:
        raise AssertionError("payload corruption")
