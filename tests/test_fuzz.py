import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

BUILD = Path(os.environ.get("TEST_BUILD_DIR", Path(__file__).resolve().parents[1] / "build/host-tests"))

def frame(kind, flags, stream, payload):
    return len(payload).to_bytes(3,"big")+bytes([kind,flags])+stream.to_bytes(4,"big")+payload

def seeds():
    prefix = b"vless://00000000-0000-0000-0000-000000000001@127.0.0.1:443?encryption=none&"
    hello = b"\x03\x03"+bytes(32)+b"\x00\x13\x01\x00\x00\x28\x00\x33\x00\x24\x00\x1d\x00\x20"+bytes(range(32))
    return {
        "uri":[prefix+b"security=none&type=tcp#vless-core",prefix+b"security=tls&type=ws&host=vless-core.test&path=%2Fvless-core",
               prefix+b"security=tls&type=grpc&serviceName=vless-core",prefix+b"security=tls&type=xhttp&mode=stream-one&path=%2Fvless-core&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D",
               b"socks5://vless-core:password@127.0.0.1:1080#vless-core",b"socks5://[::1]:1080#vless-core",b"AA==",b"%00%ff%2f"],
        "hpack":[b"\x88",bytes.fromhex("48826402"),bytes.fromhex("4883680cff"),bytes.fromhex("488410000000"),
                 b"\x00\x07:status\x03200",b"\x00\x0bgrpc-status\x010",b"\xff"*8],
        "h2":[frame(1,4,1,b"\x88"),frame(1,0,1,b"\x48")+frame(9,4,1,bytes.fromhex("826402")),
              frame(4,1,0,b""),frame(8,0,0,b"\x00\x00\x00\x01"),frame(3,0,1,bytes(4)),
              frame(0,1,1,b"\x00\x00\x00\x00\x0c\x0a\x0avless-core")],
        "grpc":[b"\x00\x00\x00\x00\x0c\x0a\x0avless-core",b"\x0a\x0avless-core",b"\x00"*5,b"\xff"*12],
        "http":[b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nvless-core",
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na\r\nvless-core\r\n0\r\n\r\n",
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: vless-core\r\n\r\n"],
        "xhttp":[b"a\r\nvless-core\r\n0\r\n\r\n",b"a;vless-core=value\r\nvless-core\r\n0\r\nTrailer: value\r\n\r\n",b"ffffffffffffffff\r\n",b"0\r\n\r\n"],
        "ws":[b"\x82\x0avless-core",b"\x02\x05vless\x80\x05-core",b"\x89\x00",b"\x88\x00",b"\x82\x7e\x00\x0avless-core",b"\x82\x7f"+bytes(7)+b"\x0avless-core"],
        "vision":[bytes(16)+bytes([command,0,10,0,0])+b"vless-core" for command in (0,1,2)],
        "tls":[b"\x02"+len(hello).to_bytes(3,"big")+hello,b"\x16\x03\x03\x00\x0avless-core",b"\x0b\x00\x00\x05\x00\x00\x00\x01\x00"],
    }

class FuzzTests(unittest.TestCase):
    def test_production_parsers_with_sanitized_mutations(self):
        runs = int(os.environ.get("TEST_FUZZ_RUNS","10000"))
        self.assertGreaterEqual(runs,1000)
        binary = BUILD/"fuzz-parsers"
        self.assertTrue(binary.is_file(),f"missing mandatory fuzzer: {binary}")
        for parser, samples in seeds().items():
            with self.subTest(parser=parser), tempfile.TemporaryDirectory(prefix=f"fuzz-{parser}-",dir=os.environ["TEST_PRIVATE_ROOT"]) as directory:
                corpus = Path(directory)
                for index, sample in enumerate(samples):
                    (corpus/str(index)).write_bytes(sample)
                log = BUILD/f"fuzz-{parser}-{time.monotonic_ns()}.log"
                command = [str(binary),str(corpus),f"-runs={runs}","-seed=13371337","-max_len=4096","-timeout=3",
                           "-rss_limit_mb=1024",f"-artifact_prefix={BUILD}/fuzz-{parser}-"]
                environment = dict(os.environ,VC_FUZZ_PARSER=parser,ASAN_OPTIONS="detect_leaks=1",UBSAN_OPTIONS="halt_on_error=1")
                with log.open("wb") as output:
                    result = subprocess.run(command,env=environment,stdout=output,stderr=subprocess.STDOUT,timeout=180)
                self.assertEqual(result.returncode,0,f"{parser}: {log.read_text()[-4000:]}\nlog: {log}")
                self.assertIn(f"Done {runs} runs",log.read_text())

if __name__ == "__main__":
    BUILD.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="fuzz-private-",dir=BUILD) as directory:
        os.environ["TEST_PRIVATE_ROOT"] = directory
        unittest.main(verbosity=2)
