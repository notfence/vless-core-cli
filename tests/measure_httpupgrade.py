import argparse
import collections
import concurrent.futures
import contextlib
import hashlib
import json
import os
from pathlib import Path
import selectors
import socket
import statistics
import tempfile
import time

def percentile(values,p):
    return sorted(values)[min(len(values)-1,int((len(values)-1)*p))]

def process_sample(pid):
    fields=Path(f"/proc/{pid}/stat").read_text().rsplit(")",1)[1].split()
    status=dict((key,value.strip()) for key,value in (line.split(":",1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line))
    return {"cpu_seconds":(int(fields[11])+int(fields[12]))/os.sysconf("SC_CLK_TCK"),
            "rss_kib":int(status["VmRSS"].split()[0]),"peak_rss_kib":int(status["VmHWM"].split()[0])}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--before",type=Path,required=True)
    parser.add_argument("--after",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--latest-xray",type=Path)
    parser.add_argument("--repeats",type=int,default=3)
    parser.add_argument("--bulk-bytes",type=int,default=8*1024*1024)
    parser.add_argument("--small-count",type=int,default=500)
    parser.add_argument("--only-known-bug",action="store_true")
    parser.add_argument("--controls-only",action="store_true")
    args=parser.parse_args()
    output=args.output.resolve(); output.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="private-",dir=output) as private:
        os.environ["TEST_PRIVATE_ROOT"]=private
        import fixtures as f
        original_build=f.BUILD; original_xray=f.XRAY
        cert,_=f.certificate()
        block=bytes(range(256))*256
        def chunks(length):
            while length:
                take=min(len(block),length); yield block[:take]; length-=take
        expected=hashlib.sha256()
        for chunk in chunks(args.bulk_bytes): expected.update(chunk)
        digest=expected.digest()
        def target(connection):
            mode=f.exact(connection,1)
            if mode==b"E":
                for _ in range(args.small_count+1): connection.sendall(f.exact(connection,1024))
                return
            if mode==b"U":
                connection.sendall(b"R")
                total=0; incoming=hashlib.sha256()
                while total<args.bulk_bytes:
                    data=connection.recv(min(65536,args.bulk_bytes-total))
                    if not data: raise EOFError("upload truncated")
                    total+=len(data); incoming.update(data)
                if incoming.digest()!=digest: raise AssertionError("upload SHA256 mismatch")
                connection.sendall(incoming.digest())
            elif mode==b"D":
                connection.sendall(b"R")
                for chunk in chunks(args.bulk_bytes): connection.sendall(chunk)
            else: raise AssertionError("invalid measurement mode")
        @contextlib.contextmanager
        def client(engine,reference,transport,security,protocol,early=False):
            if engine=="xray":
                with f.xray_client(reference.port,transport,security,protocol=protocol,fingerprint="chrome",mode="stream-one" if transport=="xhttp" else None,extra={"path":"/vless-core?ed=1"} if early else None) as value: yield value
            else:
                f.BUILD=(args.before if engine=="before" else args.after).resolve().parent
                try:
                    parameters={"ed":1} if early else {"mode":"stream-one"} if transport=="xhttp" else {}
                    with f.cli(f.uri(reference.port,transport,security,protocol=protocol,**parameters),environment={"VLESS_CA_BUNDLE":str(cert)}) as value: yield value
                finally: f.BUILD=original_build
        rows=[]
        def record(row):
            rows.append(row)
            with (output/"measurements.jsonl").open("a") as file: file.write(json.dumps(row)+"\n")
            print(json.dumps(row),flush=True)
        def measure(engine,reference,transport,security,protocol,server,repetition):
            with client(engine,reference,transport,security,protocol) as core:
                before=process_sample(core.process.pid)
                start=time.perf_counter()
                with f.socks_connect(core.port,server.port) as connection:
                    connected=time.perf_counter(); connection.sendall(b"E"); sample=b"\x00\x00"+b"v"*1022
                    connection.sendall(sample)
                    if f.exact(connection,len(sample))!=sample: raise AssertionError("first exchange mismatch")
                    first=time.perf_counter(); delays=[]
                    for _ in range(args.small_count):
                        then=time.perf_counter(); connection.sendall(sample)
                        if f.exact(connection,len(sample))!=sample: raise AssertionError("small exchange mismatch")
                        delays.append((time.perf_counter()-then)*1000)
                after=process_sample(core.process.pid)
                record(dict(engine=engine,transport=transport,security=security,protocol=protocol,repetition=repetition,
                    scenario="small",count=args.small_count,socks_connect_ms=(connected-start)*1000,first_exchange_ms=(first-start)*1000,
                    median_ms=statistics.median(delays),p95_ms=percentile(delays,.95),cpu_seconds=after["cpu_seconds"]-before["cpu_seconds"],
                    rss_kib=after["rss_kib"],peak_rss_kib=after["peak_rss_kib"],sha256=hashlib.sha256(sample).hexdigest()))
                for count in (1,4,16):
                    for direction in ("U","D"):
                        def transfer(_):
                            requested=time.perf_counter()
                            with f.socks_connect(core.port,server.port) as connection:
                                connection.sendall(direction.encode())
                                if f.exact(connection,1)!=b"R": raise AssertionError("transfer readiness mismatch")
                                ready=time.perf_counter()
                                if direction=="U":
                                    for chunk in chunks(args.bulk_bytes): connection.sendall(chunk)
                                    if f.exact(connection,32)!=digest: raise AssertionError("upload checksum mismatch")
                                    finished=time.perf_counter()
                                else:
                                    size=0; incoming=hashlib.sha256()
                                    while size<args.bulk_bytes:
                                        data=connection.recv(min(65536,args.bulk_bytes-size))
                                        if not data: raise EOFError("download truncated")
                                        incoming.update(data); size+=len(data)
                                    if incoming.digest()!=digest: raise AssertionError("download checksum mismatch")
                                    finished=time.perf_counter()
                                    if connection.recv(1)!=b"": raise AssertionError("download not terminated")
                                return requested,ready,finished,time.perf_counter()
                        before=process_sample(core.process.pid); start=time.perf_counter()
                        with concurrent.futures.ThreadPoolExecutor(max_workers=count) as workers: timings=list(workers.map(transfer,range(count)))
                        completion=time.perf_counter()-start; after=process_sample(core.process.pid)
                        elapsed=max(item[2] for item in timings)-min(item[1] for item in timings)
                        record(dict(engine=engine,transport=transport,security=security,protocol=protocol,repetition=repetition,
                            scenario="upload" if direction=="U" else "download",clients=count,bytes=count*args.bulk_bytes,seconds=elapsed,
                            completion_seconds=completion,readiness_ms=statistics.median((item[1]-item[0])*1000 for item in timings),
                            eof_tail_ms=max((item[3]-item[2])*1000 for item in timings),
                            mib_per_second=count*args.bulk_bytes/(1024*1024)/elapsed,cpu_seconds=after["cpu_seconds"]-before["cpu_seconds"],
                            rss_kib=after["rss_kib"],peak_rss_kib=after["peak_rss_kib"],sha256=digest.hex()))
                closed=process_sample(core.process.pid); time.sleep(.25); idle=process_sample(core.process.pid)
                idle["cpu_seconds"]-=closed["cpu_seconds"]
                record(dict(engine=engine,transport=transport,security=security,protocol=protocol,repetition=repetition,scenario="after-close",**idle))
        def coalesce(upstream):
            def handle(connection):
                data=bytearray()
                def receive():
                    chunk=connection.recv(16384)
                    if not chunk: raise EOFError("coalesced early request truncated")
                    data.extend(chunk)
                while b"\r\n\r\n" not in data: receive()
                prefix=data.index(b"\r\n\r\n")+4
                while len(data)<prefix+26: receive()
                with socket.create_connection(("127.0.0.1",upstream),timeout=5) as remote, selectors.DefaultSelector() as selector:
                    remote.sendall(data); selector.register(connection,selectors.EVENT_READ,remote); selector.register(remote,selectors.EVENT_READ,connection)
                    while True:
                        for key,_ in selector.select(timeout=.1):
                            chunk=key.fileobj.recv(16384)
                            if not chunk: return
                            key.data.sendall(chunk)
            return handle
        known=[]
        for version,binary in (("26.6.27",original_xray),("26.10.17",args.latest_xray.resolve() if args.latest_xray else None)):
            if args.controls_only: break
            if binary is None: continue
            f.XRAY=binary
            for engine in ("after","xray"):
                with f.Server() as server,f.xray_server("httpupgrade","none") as reference,f.Server(coalesce(reference.port)) as proxy:
                    with client(engine,proxy,"httpupgrade","none","vless",early=True) as core:
                        with f.socks_connect(core.port,server.port) as connection:
                            connection.settimeout(.4)
                            connection.sendall(b"vless-core known early-data failure")
                            try: reply=connection.recv(128); outcome="eof" if not reply else "data"
                            except TimeoutError: outcome="timeout"
                        known.append(dict(version=version,engine=engine,result=outcome))
                        print(json.dumps(known[-1]),flush=True)
            f.XRAY=original_xray
        (output/"known-server-bug.json").write_text(json.dumps(known,indent=2))
        if not args.only_known_bug:
            with f.Server(target) as server:
                for repetition in range(args.repeats):
                    for transport in ("tcp","ws","grpc","xhttp"):
                        options={"mode":"stream-one"} if transport=="xhttp" else {}
                        with f.xray_server(transport,"tls",**options) as reference:
                            for engine in (("before","after") if repetition%2==0 else ("after","before")):
                                measure(engine,reference,transport,"tls","vless",server,repetition)
                    for protocol in ("vless","trojan","vmess","shadowsocks"):
                        if args.controls_only: break
                        for security in ("none","tls"):
                            with f.xray_server("httpupgrade",security,protocol=protocol) as reference:
                                for engine in (("after","xray") if repetition%2==0 else ("xray","after")):
                                    measure(engine,reference,"httpupgrade",security,protocol,server,repetition)
        groups=collections.defaultdict(list)
        for row in rows: groups[(row["engine"],row["transport"],row["security"],row["protocol"],row["scenario"],row.get("clients",1))].append(row)
        summary=[]
        for key,items in groups.items():
            value=dict(zip(("engine","transport","security","protocol","scenario","clients"),key)); value["runs"]=len(items)
            for field in ("median_ms","p95_ms","socks_connect_ms","first_exchange_ms","mib_per_second","cpu_seconds","rss_kib","peak_rss_kib","completion_seconds","readiness_ms","eof_tail_ms"):
                if field in items[0]: value[field]=statistics.median(item[field] for item in items)
            summary.append(value)
        (output/"summary.json").write_text(json.dumps(summary,indent=2))

if __name__=="__main__": main()
