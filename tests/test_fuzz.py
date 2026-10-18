import os
import json
import re
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from urllib.parse import quote

BUILD = Path(os.environ.get("TEST_BUILD_DIR", Path(__file__).resolve().parents[1] / "build/host-tests"))

def frame(kind, flags, stream, payload):
    return len(payload).to_bytes(3,"big")+bytes([kind,flags])+stream.to_bytes(4,"big")+payload

def seeds():
    prefix = b"vless://00000000-0000-0000-0000-000000000001@127.0.0.1:443?encryption=none&"
    hello = b"\x03\x03"+bytes(32)+b"\x00\x13\x01\x00\x00\x28\x00\x33\x00\x24\x00\x1d\x00\x20"+bytes(range(32))
    vision_client=b"\x03\x03"+bytes(32)+b"\x00\x00\x02\x13\x03\x01\x00\x00\x07\x00\x2b\x00\x03\x02\x03\x04"
    vision_client=b"\x01"+len(vision_client).to_bytes(3,"big")+vision_client
    vision_client=b"\x16\x03\x03"+len(vision_client).to_bytes(2,"big")+vision_client
    vision_records=[vision_client,b"\x17\x03\x03\x00\x20"+bytes(32)]
    for cipher in (0x1301,0x1302,0x1303,0x1304,0x1305,0xc02f):
        body=b"\x03\x03"+bytes(32)+b"\x00"+cipher.to_bytes(2,"big")+b"\x00\x00\x06\x00\x2b\x00\x02\x03\x04"
        body=b"\x02"+len(body).to_bytes(3,"big")+body
        record=b"\x16\x03\x03"+len(body).to_bytes(2,"big")+body
        vision_records.extend((record,vision_client+record,record+b"\x17\x03\x03\x00\x20"+bytes(32)))
    download={"address":"127.0.0.2","port":8443,"network":"xhttp","security":"tls",
              "tlsSettings":{"serverName":"vless-core.test","alpn":["h2","http/1.1"]},
              "xhttpSettings":{"path":"/vless-core","extra":{"headers":{"Cookie":"vless-core=1"},"noGRPCHeader":True}}}
    extras=[{"mode":"packet-up","uplinkDataPlacement":placement,"uplinkDataKey":"vless-core","uplinkChunkSize":"64-128",
             "scMaxEachPostBytes":"1024-4096","scMinPostsIntervalMs":"10-30","headers":{"X-Vless-Core":"a\\b\"c","Cookie":"vless-core=1"},
             "sessionIDPlacement":"header","sessionIDKey":"x-session","seqPlacement":"query","seqKey":"seq",
             "sessionIDTable":"Base62","sessionIDLength":"16-32","xPaddingMethod":"tokenish",
             "xPaddingObfsMode":True,"xPaddingPlacement":"cookie","xPaddingKey":"padding"}
            for placement in ("body","header","cookie")]
    extras.append({"mode":"stream-up","downloadSettings":download,
                   "xmux":{"maxConnections":"1-3","maxConcurrency":"0","cMaxReuseTimes":"3-5",
                           "hMaxRequestTimes":"10-20","hMaxReusableSecs":"1-3","hKeepAlivePeriod":-1}})
    extras.append({"noSSEHeader":False,"scMaxBufferedPosts":30,"scStreamUpServerSecs":"20-80","serverMaxHeaderBytes":8192})
    extras.extend(({"sessionIDTable":"AAAAAAAA","sessionIDLength":16}, {"sessionIDTable":"AAAB","sessionIDLength":"1-31"}))
    extras.extend(({"xmux":{"maxConcurrency":"","maxConnections":3,"cMaxReuseTimes":0,"hMaxRequestTimes":"600-900","hMaxReusableSecs":"1800-3000","hKeepAlivePeriod":0}},
                   {"xmux":{"maxConcurrency":"","maxConnections":"","cMaxReuseTimes":"","hMaxRequestTimes":"","hMaxReusableSecs":""}},
                   {"xmux":{"maxConcurrency":" ","maxConnections":3}}, {"xmux":{"hKeepAlivePeriod":""}}))
    uri_extras=[]
    for extra in extras:
        encoded=json.dumps(extra,separators=(",",":"))
        uri_extras.extend((encoded.encode(),prefix+b"security=none&type=xhttp&extra="+quote(encoded,safe="").encode()+b"#vless-core"))
    uri_extras.extend((json.dumps(download,separators=(",",":")).encode(),
                       b'{"downloadSettings":{"address":"127.0.0.2","port":8080,"network":"xhttp","xhttpSettings":{"host":"vless-core.test","path":"/download","xPaddingBytes":"512-512","extra":{"xPaddingBytes":"128-128","sessionIDPlacement":"header","sessionIDKey":"X-vless-core-session"}}}}',
                       b'{"downloadSettings":{"address":"127.0.0.2","port":8080,"network":"splithttp","splithttpSettings":{"xPaddingBytes":"512-512","extra":{}}}}',
                       b'{"headers":{"X-Vless-Core":"a","x-vless-core":"b"}}',
                       b'{"sessionKey":"a","sessionIDKey":"b"}',
                       b'{"headers":{"Cookie":"x_data_0=old"},"uplinkDataPlacement":"cookie"}',
                       b'{"xmux":{"maxConnections":1,"maxConcurrency":1}}',
                       b'{"mode":"packet-up","uplinkDataPlacement":"cookie","sessionIDPlacement":"cookie","sessionIDKey":"x_data_0"}'))
    return {
        "arguments":[b"--version",b"-v",b"--version\x00--version",
                     b"--uri\x00socks5://127.0.0.1:1080#vless-core\x00--listen-port\x001080",
                     b"--connection-fd\x000\x00--listen-port\x0065535\x00--route-control-port\x000",
                     b"--uri-fd\x002147483648",b"--connect-timeout-ms\x00-1",b"--listen-port\x0065536",
                     b"--listen-port\x001080\x00--listen-port\x001081",b"--uri\x00--help\x00--uri\x00vless-core",
                     b"--uri\x00socks5://127.0.0.1:1080#vless-core\x00--xray-version\x00255.255.255",
                     b"--uri-fd\x000\x00--xray-version\x004294967296.6.27",
                     b"--uri-fd\x000\x00--xray-version\x001.2.18446744073709551616",
                     b"--uri-fd\x000\x00--xray-version\x001.+2.3"],
        "uri":[prefix+b"security=none&type=tcp#vless-core",prefix+b"security=tls&type=ws&host=vless-core.test&path=%2Fvless-core",
               prefix+b"security=tls&type=grpc&serviceName=vless-core",prefix+b"security=tls&type=xhttp&mode=stream-one&path=%2Fvless-core&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D",
               b"socks5://vless-core:password@127.0.0.1:1080#vless-core",b"socks5://[::1]:1080#vless-core",b"AA==",b"%00%ff%2f",b"Zh==",b"Zm9=",b"AAAA=",
               prefix+b"type=ws&path=%2Fvless%20core%3Fx%3D%252F",prefix+b"type=xhttp&path=%2Fbad%2500",*uri_extras,
               b"1;block;0;direct,cidr,192.0.2.1/4294967296",b"1;block;0;direct,cidr,2001:db8::1/18446744073709551616",
               b"1;block;0;direct,cidr,0.0.0.0/0",b"1;block;0;direct,cidr,::/0",b"1;block;0;direct,cidr,192.0.2.1/+0",
               b"socks5://127.0.0.1:1080?security=tls",b"socks5://127.0.0.1:1080?type=xhttp&extra=not-json"],
        "hpack":[b"\x88",bytes.fromhex("48826402"),bytes.fromhex("4883680cff"),bytes.fromhex("488410000000"),
                 b"\x00\x07:status\x03200",b"\x00\x0bgrpc-status\x010",b"\xff"*8,
                 bytes.fromhex("828684410f7777772e6578616d706c652e636f6d"),
                 bytes.fromhex("828684be58086e6f2d6361636865"),bytes.fromhex("828684be5886a8eb10649cbf")],
        "h2":[frame(4,0,0,b"")+frame(1,4,1,b"\x88"),frame(4,0,0,b"")+frame(1,0,1,b"\x48")+frame(9,4,1,bytes.fromhex("826402")),
              frame(4,0,0,bytes.fromhex("000100000000000300000002000400000400000500008000000600010000")),
              frame(0x89,0,0,b"\x00\x01x\x00\x01y"),frame(0xff,7,0,b"vless-core"),
              frame(4,0,0,b"")+frame(0x89,0,0,b"\x00\x01x\x00\x01y")+frame(0xff,0,0,b""),
              frame(4,0,0,bytes.fromhex("000480000000")),frame(0x89,0,0,b"\x00\x09x\x00\x01y"),
              frame(4,1,0,b""),frame(8,0,0,b"\x00\x00\x00\x01"),frame(3,0,1,bytes(4)),
              frame(0,1,1,b"\x00\x00\x00\x00\x0c\x0a\x0avless-core")],
        "pool":[frame(4,0,0,b"")+frame(1,4,1,b"\x88\x00\x0ccontent-type\x10application/grpc")+frame(0,24,1,b"vless-core")+frame(0,1,1,b""),
                frame(4,0,0,b"")+frame(1,4,3,b"\x88\x00\x0ccontent-type\x10application/grpc")+frame(3,0,1,bytes(4))+frame(0,2,3,b"vless-core"),
                frame(7,0,0,b"\x00\x00\x00\x01"+bytes(4)),frame(4,0,0,b"\x00\x04\x00\x00\x04\x00"),
                frame(4,0,0,b"")+frame(1,4,1,b"\x88\x00\x0ccontent-type\x10application/grpc")+frame(1,5,1,b"\x00\x0bgrpc-status\x010"),
                frame(4,0,0,b"")+frame(1,4,1,b"\x88\x40\x03x\x00y\x01v\x40\x01x\x01n")+frame(1,4,3,b"\x88\xbe"),
                frame(4,0,0,b"")+frame(2,0,1,bytes(4))+frame(1,4,3,b"\x88"),
                frame(4,0,0,b"")+frame(2,0,1,b"\x00\x00\x00\x01\x00")+frame(1,4,3,b"\x88"),
                frame(4,0,0,b"")+frame(1,32,1,b"\x00\x00\x00\x01\x00\x88\x40")+frame(9,4,1,b"\x01x\x01v")+frame(1,4,3,b"\x88\xbe")],
        "grpc":[b"\x00\x00\x00\x00\x0c\x0a\x0avless-core",b"\x0a\x0avless-core",b"\x00"*5,b"\xff"*12,
                b"\x00\x00\x00\x00\x08\x0a\x03abc\x0a\x01x",b"\x00\x01\x00\x00\x00\x0a\xfb\xff\xff\x07x",
                b"\x00\x00\x00\x00\x07\x0a\x03abc\x0a\x00",b"\x00\x00\x00\x00\x09\x13\x0a\x01x\x14\x0a\x02ok"],
        "http":[b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nvless-core",
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na\r\nvless-core\r\n0\r\n\r\n",
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: vless-core\r\n\r\n"],
        "xhttp":[b"a\r\nvless-core\r\n0\r\n\r\n",b"a;vless-core=value\r\nvless-core\r\n0\r\nTrailer: value\r\n\r\n",b"ffffffffffffffff\r\n",b"0\r\n\r\n"],
        "ws":[b"\x82\x0avless-core",b"\x02\x05vless\x80\x05-core",b"\x89\x00",b"\x88\x00",b"\x82\x7e\x00\x0avless-core",b"\x82\x7f"+bytes(7)+b"\x0avless-core",
              b"\x01\x02\xf0\x9f\x89\x00\x80\x02\x98\x80",b"\xc2\x00",b"\x80\x00",b"\x82\x80"+bytes(4),b"\x88\x03\x03\xe8\xff"],
        "vision":[*[bytes(16)+bytes([command,0,10,0,0])+b"vless-core" for command in (0,1,2)],
                  b"\x00\x00vless-core",b"\x00\x0avless-coretail",b"\x00\xff",b"\x01\x00",b"short tail",*vision_records],
        "tls":[b"\x02"+len(hello).to_bytes(3,"big")+hello,b"\x02\x00\x00\x26\x03\x03"+bytes(32)+b"\x00\xcc\xa9\x00",
               b"\x16\x03\x03\x00\x0avless-core",b"\x0b\x00\x00\x05\x00\x00\x00\x01\x00",
               b"",b"\x18\x00\x00\x01\x00",b"\x18\x00\x00\x01\x01",b"\x18\x00\x00\x01\x02",
               b"\x18\x00\x00\x01\x01\x00",b"\x18\x00\x00\x01\x00"*2,
               b"\x04\x00\x00\x0e\x00\x00\x00\x3c\x00\x00\x00\x00\x00\x00\x01x\x00\x00\x18\x00\x00\x01\x01",
               b"\x18\x00\x00\x01\x01\x04\x00\x00\x0e\x00\x00\x00\x3c\x00\x00\x00\x00\x00\x00\x01x\x00\x00"],
        "encryption":[b"\x02vless-core",b"\x03vless-core",b"\x06vless-core",b"\x07vless-core",b"\x0bvless-core",b"\x12vless-core",b"\x16vless-core",bytes(21)],
    }

class FuzzTests(unittest.TestCase):
    def test_production_parsers_with_sanitized_mutations(self):
        runs = int(os.environ.get("TEST_FUZZ_RUNS","10000"))
        self.assertGreaterEqual(runs,1000)
        binary = BUILD/"fuzz-parsers"
        self.assertTrue(binary.is_file(),f"missing mandatory fuzzer: {binary}")
        for parser, samples in seeds().items():
            with self.subTest(parser=parser), tempfile.TemporaryDirectory(prefix=f"fuzz-{parser}-",dir=os.environ["TEST_PRIVATE_ROOT"]) as directory:
                binary=BUILD/("fuzz-encryption" if parser == "encryption" else "fuzz-http2-pool" if parser == "pool" else "fuzz-parsers")
                self.assertTrue(binary.is_file(),f"missing mandatory fuzzer: {binary}")
                corpus = Path(directory)
                for index, sample in enumerate(samples):
                    (corpus/str(index)).write_bytes(sample)
                log = BUILD/f"fuzz-{parser}-{time.monotonic_ns()}.log"
                command = [str(binary),str(corpus),f"-runs={runs}","-seed=13371337","-max_len=4096","-timeout=3",
                           "-rss_limit_mb=1024",f"-artifact_prefix={BUILD}/fuzz-{parser}-"]
                environment = dict(os.environ,VC_FUZZ_PARSER=parser,ASAN_OPTIONS="detect_leaks=1",UBSAN_OPTIONS="halt_on_error=1",DEBUGINFOD_URLS="")
                with log.open("wb") as output:
                    result = subprocess.run(command,env=environment,stdout=output,stderr=subprocess.STDOUT,timeout=180)
                self.assertEqual(result.returncode,0,f"{parser}: {log.read_text()[-4000:]}\nlog: {log}")
                completed=re.findall(r"^Done ([0-9]+) runs in [0-9]+ second\(s\)$",log.read_text(),re.MULTILINE)
                self.assertEqual(len(completed),1,"missing or ambiguous fuzz completion")
                self.assertGreaterEqual(int(completed[0]),runs,"fuzzer stopped before the requested number of runs")

if __name__ == "__main__":
    BUILD.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="fuzz-private-",dir=BUILD) as directory:
        os.environ["TEST_PRIVATE_ROOT"] = directory
        unittest.main(verbosity=2)
