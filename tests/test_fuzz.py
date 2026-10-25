import os
import base64
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
    vmess_uris=[]
    vmess_settings=[
        dict(net='ws',tls='tls',host='vless-core.test',path='/vless-core?ed=16384',headers={'X-Fixture':'present'},heartbeatPeriod=1),
        dict(net='grpc',tls='none',path='vless-core',host='grpc.test',type='multi',multiMode=True,permit_without_stream=False,initial_windows_size=1024),
        dict(net='grpc',tls='tls',type='gun',multiMode=42),
        dict(net='xhttp',tls='tls',mode='stream-up',extra=dict(xmux=dict(maxConcurrency='',maxConnections=3),downloadSettings=download)),
        dict(net='xhttp',tls='none',mode='packet-up',xmux=dict(maxConnections=1),noGRPCHeader=True,xPaddingBytes=0),
        dict(net='xhttp',tls='tls',extra=dict(downloadSettings=download),downloadSettings=download),
        dict(net='tcp',scy='none',vcn='unsupported'),
    ]
    for options in vmess_settings:
        value=dict(v='2',add='127.0.0.1',port=443,id='00000000-0000-0000-0000-000000000001',aid=0,scy='auto')
        value.update(options)
        encoded=json.dumps(value,separators=(',',':')).encode()
        vmess_uris.extend((b'vmess://'+base64.b64encode(encoded),b'vmess://'+base64.urlsafe_b64encode(encoded).rstrip(b'=')))
    vmess_uris.extend(b'vmess://00000000-0000-0000-0000-000000000001@127.0.0.1:443?'+query for query in (
        b'type=ws&security=tls&ed=16384',b'type=grpc&mode=multi&initialWindowsSize=1024',
        b'type=xhttp&mode=stream-up&extra='+quote(json.dumps({'downloadSettings':download}),safe='').encode()))
    vmess_frames=[bytes([flag])+bytes.fromhex(wire) for flag in (0,64,128) for wire in (
        'dc0e6902de0ac0cc128a15fa7a2dbce8e547098c1d2776a32aa0d6c303e36cb4f4ee2321d750',
        'dc0e6902de0ac0cc128a15fa7a2dbce8e547088c1d2775f2ef7f4f2a3c35c7739e35725a28f6',
        'dc01d6432a2b799bd7c4ca22575a36af9c91098c7e2039a172b928ce39c5223a9048fcda32fde30ab3778dd14b',
        '8e739d3ecdca9a91f13b0d502be14505dfbe2dd4de1d95f19597ba58acd8ab0183000102030405060708090a0b0c0d0e0f10')]
    vmess_frames.append(b'\x02\xbc\x91'+b'v'*16384)
    ss_uris=[]; ss_frames=[]
    ss_methods=('aes-128-gcm','aes-256-gcm','chacha20-poly1305','xchacha20-poly1305','2022-blake3-aes-128-gcm','2022-blake3-aes-256-gcm','2022-blake3-chacha20-poly1305')
    for index,method in enumerate(ss_methods):
        password=base64.b64encode(bytes(range(16 if index==4 else 32))).decode() if index>=4 else 'Exact+Pass:%@\x00Z'
        raw=(method+':'+password).encode()
        settings=('type=tcp','type=ws&security=tls&ed=16384','type=grpc&mode=multi','type=xhttp&mode=stream-up&extra='+quote(json.dumps({'downloadSettings':download,'xmux':{'maxConnections':1}}),safe=''))
        for query in settings: ss_uris.append(('ss://'+method+':'+quote(password,safe='')+'@127.0.0.1:443?'+query).encode())
        ss_uris.extend((b'ss://'+base64.urlsafe_b64encode(raw).rstrip(b'=')+b'@127.0.0.1:443',b'ss://'+base64.b64encode(raw+b'@127.0.0.1:443')))
    ss_uris.extend((b'ss://aes-128-gcm:%GG@127.0.0.1:1',b'ss://aes-128-gcm:fixture@host:18446744073709551616',b'ss://aes-128-gcm:fixture@127.0.0.1:1?plugin=obfs-local',b'ss://aes-128-gcm:fixture@127.0.0.1:1?type=ws&host=bad%0D%0AInjected',b'ss://e3+_',b'ss://Zh==@host:1',b'ss://Zm9=@host:1'))
    for method in (ss_methods[4],ss_methods[5]):
        key=base64.b64encode(bytes(range(16 if method==ss_methods[4] else 32))).decode()
        ss_uris.append(('ss://'+method+':'+quote(key+':'+key,safe='')+'@127.0.0.1:443?type=grpc').encode())
    for index,body,response in (
        (0,"266d2a80c7fd99dcfb3249967bd3313c87b484aba1bfca2a4f531230507f8c9a29cc6c1f2965dcd86e2c965e8072c5","404142434445464748494a4b4c4d4e4f266d2a80c7fd99dcfb3249967bd3313c87b484aba1bfca2a4f531230507f8c9a29cc6c1f2965dcd86e2c965e8072c5dfa53b96279ffa3143f473a0462602c5ebd29348ea83ef8091b9a031b6d9de1045955e660ab6bb5e90e265e429d9"),
        (1,"97d9cda78b3058c4c80942593103c6be1ccfc0cabf16cf4b6c14c50609fdf2937d81f0cad506b0354484d5cba15bdd","404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f97d9cda78b3058c4c80942593103c6be1ccfc0cabf16cf4b6c14c50609fdf2937d81f0cad506b0354484d5cba15bdd47a6f6ce1e154b43753f109974a8ec8d15f130647b33547bb95c2d23e6baa70ceb1b35a223a27867315c0394ce70"),
        (2,"dd1c85d79776394c72ca12d3c51cf04e1621df730e6229883f03a4d5773705f4d14be91717c769bd40f0f5f96df703","404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5fdd1c85d79776394c72ca12d3c51cf04e1621df730e6229883f03a4d5773705f4d14be91717c769bd40f0f5f96df7036daf866ee3d2612e3ea8c1b54352433cde51278f818b3613ee7c381f4909f3870a065210c2cf3dd3c179df20b4cf"),
        (3,"20f2657210cfa465f93243672e22e04a1f817fb71e20f3f537840429124fbb18d804e65c599219403b6561e411e294","404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f20f2657210cfa465f93243672e22e04a1f817fb71e20f3f537840429124fbb18d804e65c599219403b6561e411e2946e7ae35f7efc725b8642b55d8909796c7642ab1ced2cee5024c72827d7edf4818d788ffa7fc60e18f83edfdd80e5"),
        (4,"b3c1d115a289a7778ae5b585c21db9cbb8028d89307aff609adc567cf3332abade20c0087287def15fff9333c83a90","404142434445464748494a4b4c4d4e4fb2ccc846e965a2bc8775985da611ffac72d16ed35d9ee9508c17579870b357873c7c2d34fefcc1cae5b62d8d89307aff609adc567cf3332abade20c0087287def15fff9333c83a90a9baa63c07f795de3e3d985ed03519bacaef44ec5794369f1629e838ba7144e5beeb0b0239618cabcb2b217775be"),
        (5,"6979367a806c4e71f5748fb987d37a087973ee3f9a95589ef11e29b1b4b65cd441ae72513e3fac4257631de3b76795","404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f6874e6d351c385cfdec5657e74cdd8d6e213ca4c516d9791abe084c67b686072adf59e1ba989c7d388a03b55da9dfcc993414b06bea8bee33b128dee3f9a95589ef11e29b1b4b65cd441ae72513e3fac4257631de3b76795a76c2aaa26b57fb3828fa64012b40823a74903e5332a1f3edfb09d378774b75f7dd01d162838281094c8165e2b03"),
        (6,"d9bb8965a13fff0a1358e72ebdf5ba789efabec84bf80917d441239339744abb0ace2a45e9ab49067441e83d293f8d","404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5fd8b69a4c76f623b46df89be78ef143d0ce97372ce44fdcedd8b829ca033b1b58b6769b8a7aabf76667ef716640327662ec5d470d461740c24e50f6bec84bf80917d441239339744abb0ace2a45e9ab49067441e83d293f8d98e8b3a9891e8c69f8ac91b93387aa1582d5aaaf75e3a70dfbfb03a1e6d3408558f744443dbb6912f69c76ca14ca"),
    ):
        for flag,wire in ((index|64,body),(index,response),(index|192,body),(index|224,body)):
            value=bytes([flag])+bytes.fromhex(wire); ss_frames.extend((value,value[:-1],value[:-1]+bytes([value[-1]^1])))
    ss_frames.extend((b'\x44'+bytes(16)+bytes(65535),b'\x86'+bytes(64),b'\xc0'+bytes(64),b'\xe0'+bytes(64)))

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
        "uri":[*ss_uris,*vmess_uris,b"vmess://00000000-0000-0000-0000-000000000001@127.0.0.1:443?encryption=auto",
               b"vmess://00000000-0000-0000-0000-000000000001@[::1]:65535?scy=zero&aid=0",
               b"vmess://"+base64.b64encode(b'{"v":"2","add":"127.0.0.1","port":443,"id":"00000000-0000-0000-0000-000000000001","aid":"0","scy":"auto","net":"tcp","tls":""}'),
               b"vmess://e31=",b"vmess://e3+_",b"vmess://e30===",
               b"trojan://public-fixture@127.0.0.1:443",b"trojan://A+B%00%3A%40%25@[::1]:65535?security=none",
               b"trojan://user:pass@127.0.0.1:443?type=ws&ed=69",b"trojan://fixture@127.0.0.1:443?type=grpc&mode=multi",
               b"trojan://fixture@127.0.0.1:443?type=xhttp&mode=packet-up&extra=%7B%22xmux%22%3A%7B%22maxConnections%22%3A1%7D%7D",
               b"trojan://fixture@127.0.0.1:443?flow=xtls-rprx-vision",b"trojan://fixture@127.0.0.1:443?encryption=invalid",
               b"trojan://@127.0.0.1:443",b"trojan://%GG@127.0.0.1:443",b"trojan://fixture@host:18446744073709551616",
               prefix+b"security=none&type=tcp#vless-core",prefix+b"security=tls&type=ws&host=vless-core.test&path=%2Fvless-core",
               prefix+b"security=tls&type=grpc&serviceName=vless-core",prefix+b"security=tls&type=xhttp&mode=stream-one&path=%2Fvless-core&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D",
               b"socks5://vless-core:password@127.0.0.1:1080#vless-core",b"socks5://[::1]:1080#vless-core",b"AA==",b"%00%ff%2f",b"Zh==",b"Zm9=",b"AAAA=",
               prefix+b"type=ws&path=%2Fvless%20core%3Fx%3D%252F",prefix+b"type=xhttp&path=%2Fbad%2500",*uri_extras,
               b"1;block;0;direct,cidr,192.0.2.1/4294967296",b"1;block;0;direct,cidr,2001:db8::1/18446744073709551616",
               b"1;block;0;direct,cidr,0.0.0.0/0",b"1;block;0;direct,cidr,::/0",b"1;block;0;direct,cidr,192.0.2.1/+0",
               b"socks5://127.0.0.1:1080?security=tls",b"socks5://127.0.0.1:1080?type=xhttp&extra=not-json",
               b"vless://00000000-0000-0000-0000-000000000001@vless-core.test\r\nX-Audit: injected:443?type=ws",
               b"vless://00000000-0000-0000-0000-000000000001@[not-ip]:443?type=tcp",
               b"socks5://[::1]:18446744073709551616",b"socks5://vless-core.test:+1080",
               prefix+b"type=ws&host=%5B%3A%3A1%5D%3A65535",prefix+b"type=ws&host=bad%20host",
               prefix+b"type=ws&host=%5B%3A%3A1%5Dextra",
               prefix+b"type=httpupgrade&security=none&ed=4294967295",
               prefix+b"type=httpupgrade&security=tls&path=%2Ffixture%3Fed%3D1%26keep%3Da%252Fb",
               prefix+b"type=httpupgrade&security=none&path=%2Fwith%20space%3Fz%3D2%26ed%3D0%26a%3D1%23fragment",
               prefix+b"type=httpupgrade&host=bad%0D%0AInjected",
               prefix+b"type=httpupgrade&ed=4294967296"],
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
                frame(4,0,0,b"")+frame(1,4,1,b"\x88\x00\x0ccontent-type\x10application/grpc")+frame(0,32,1,b"vless-core")+frame(1,5,1,b"\x00\x0bgrpc-status\x010"),
                frame(4,0,0,b"")+frame(1,20,1,b"\x88\x00\x0ccontent-type\x10application/grpc")+frame(1,5,1,b"\x00\x0bgrpc-status\x010")+frame(3,16,1,bytes(4)),
                frame(4,0,0,b"")+frame(1,4,3,b"\x88\x00\x0ccontent-type\x10application/grpc")+frame(3,0,1,bytes(4))+frame(0,2,3,b"vless-core"),
                frame(7,0,0,b"\x00\x00\x00\x01"+bytes(4)),frame(4,0,0,b"\x00\x04\x00\x00\x04\x00"),
                frame(4,0,0,b"")+frame(1,4,1,b"\x88\x00\x0ccontent-type\x10application/grpc")+frame(1,5,1,b"\x00\x0bgrpc-status\x010"),
                frame(4,0,0,b"")+frame(1,4,1,b"\x88\x40\x03x\x00y\x01v\x40\x01x\x01n")+frame(1,4,3,b"\x88\xbe"),
                frame(4,0,0,b"")+frame(2,0,1,bytes(4))+frame(1,4,3,b"\x88"),
                frame(4,0,0,b"")+frame(2,0,1,b"\x00\x00\x00\x01\x00")+frame(1,4,3,b"\x88"),
                frame(4,0,0,b"")+frame(1,32,1,b"\x00\x00\x00\x01\x00\x88\x40")+frame(9,4,1,b"\x01x\x01v")+frame(1,4,3,b"\x88\xbe"),
                *[frame(4,0,0,b"")+frame(1,4,1,b"\x88\x00\x0ccontent-type\x10application/grpc")+frame(0,flags,1,b"vless-core"*50)+suffix
                  for flags in (0,2) for suffix in (b"",frame(3,0,1,bytes(4)),frame(99,0,0,b""))]],
        "grpc":[b"\x00\x00\x00\x00\x0c\x0a\x0avless-core",b"\x0a\x0avless-core",b"\x00"*5,b"\xff"*12,
                b"\x00\x00\x00\x00\x08\x0a\x03abc\x0a\x01x",b"\x00\x01\x00\x00\x00\x0a\xfb\xff\xff\x07x",
                b"\x00\x00\x00\x00\x07\x0a\x03abc\x0a\x00",b"\x00\x00\x00\x00\x09\x13\x0a\x01x\x14\x0a\x02ok"],
        "http":[b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nvless-core",
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na\r\nvless-core\r\n0\r\n\r\n",
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: vless-core\r\n\r\n"],
        "xhttp":[b"a\r\nvless-core\r\n0\r\n\r\n",b"a;vless-core=value\r\nvless-core\r\n0\r\nTrailer: value\r\n\r\n",b"ffffffffffffffff\r\n",b"0\r\n\r\n"],
        "httpupgrade":[b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n\x00\x00last",
                       b"HTTP/1.1 101 Switching Protocols\r\nConnection: close\r\nUpgrade: websocket\r\n\r\n",
                       b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX-Large: "+b"x"*32768,
                       b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"*2],
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
        "shadowsocks":ss_frames,
        "vmess":[bytes([index])+bytes.fromhex(wire) for index,wire in (
            (0,"8e739d3ecdca9a91f13b0d502be14505dfbe2dd4de1d95f19597ba58acd8ab0183000102030405060708090a0b0c0d0e0f10"),
            (1,"8e73e9de6f49187cc2fd3924770f46360c94c95a8bc51bb435194c8de1c431c87f000102030405060708090a0b0c0d0e0f10"),
            (2,"fc9e564d657373204145414420626f6479"),(3,"564d657373204145414420626f6479"))]+vmess_frames,
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
                command = [str(binary),str(corpus),f"-runs={runs}","-seed=13371337",f"-max_len={65536 if parser == 'shadowsocks' else 32769 if parser == 'httpupgrade' else 16400 if parser == 'vmess' else 4096}","-timeout=3",
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
