import hashlib
import gzip
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

def verify_binary(data, architecture):
    if architecture not in ("linux","armv7","arm64"):
        raise AssertionError(f"unknown binary architecture: {architecture}")
    if architecture == "linux":
        if data[:6] != b"\x7fELF\x02\x01" or len(data) < 64:
            raise AssertionError("expected little-endian ELF64")
        kind,machine = struct.unpack_from("<HH",data,16)
        if kind not in (2,3) or machine != 62:
            raise AssertionError("expected x86-64 executable")
        return
    wide = architecture == "arm64"
    magic,cpu,subtype,kind,count,size,flags = struct.unpack_from("<7I",data)
    if magic != (0xfeedfacf if wide else 0xfeedface) or cpu != (0x100000c if wide else 12) or (not wide and subtype & 0xffffff != 9):
        raise AssertionError(f"wrong Mach-O architecture: {architecture}")
    if kind != 2 or not flags & 0x200000:
        raise AssertionError("expected PIE Mach-O executable")
    offset = 32 if wide else 28
    end = offset + size
    if end > len(data):
        raise AssertionError("truncated Mach-O commands")
    minimum = None
    for _ in range(count):
        command,length = struct.unpack_from("<II",data,offset)
        if length < 8 or offset+length > end:
            raise AssertionError("invalid Mach-O command length")
        if command == 0x25:
            minimum = struct.unpack_from("<I",data,offset+8)[0]
        elif command == 0x32:
            platform,minimum = struct.unpack_from("<II",data,offset+8)
            if platform != 2:
                raise AssertionError("expected iOS build platform")
        elif command in (0xc,0x80000018,0x8000001f):
            name_offset = struct.unpack_from("<I",data,offset+8)[0]
            name = data[offset+name_offset:offset+length].split(b"\0",1)[0].decode()
            if not name.startswith(("/usr/lib/","/System/Library/")):
                raise AssertionError(f"unexpected runtime dependency: {name}")
        offset += length
    if minimum != (0xb0000 if wide else 0x50000):
        raise AssertionError(f"wrong minimum iOS: {minimum!r}")

def verify_archive(path, binary_name, architecture):
    with tarfile.open(path,"r:gz") as archive:
        entries = archive.getmembers()
        expected = {Path(binary_name).name,"THIRD_PARTY_LICENSES.txt"}
        if {entry.name for entry in entries} != expected or len(entries) != 2 or not all(entry.isfile() for entry in entries):
            raise AssertionError(f"archive contents: {[entry.name for entry in entries]}")
        verify_binary(archive.extractfile(Path(binary_name).name).read(),architecture)
        if archive.extractfile("THIRD_PARTY_LICENSES.txt").read() != (ROOT/"THIRD_PARTY_LICENSES.txt").read_bytes():
            raise AssertionError("third-party notices do not match the project document")
        if not archive.getmember(Path(binary_name).name).mode & 0o111:
            raise AssertionError("archive binary is not executable")

def verify_release(directory):
    expected = {f"vless-core-{suffix}.tar.gz":arch for suffix,arch in (("linux-amd64","linux"),("darwin-armv7","armv7"),("darwin-arm64","arm64"))}
    lines = (directory/"SHA256SUMS").read_text().splitlines()
    sums = dict(line.split(None,1)[::-1] for line in lines)
    if len(lines) != len(expected) or set(sums) != set(expected):
        raise AssertionError("SHA256SUMS must cover each release archive exactly once")
    for name,architecture in expected.items():
        if hashlib.sha256((directory/name).read_bytes()).hexdigest() != sums[name]:
            raise AssertionError(f"checksum mismatch: {name}")
        verify_archive(directory/name,name.removesuffix(".tar.gz"),architecture)

class BuildTests(unittest.TestCase):
    def binary_fixture(self, architecture):
        if architecture == "linux":
            data = bytearray(64); data[:6] = b"\x7fELF\x02\x01"; struct.pack_into("<HH",data,16,2,62)
        else:
            wide = architecture == "arm64"; offset = 32 if wide else 28
            data = bytearray(offset+16)
            struct.pack_into("<7I",data,0,0xfeedfacf if wide else 0xfeedface,0x100000c if wide else 12,0 if wide else 9,2,1,16,0x200000)
            struct.pack_into("<4I",data,offset,0x25,16,0xb0000 if wide else 0x50000,0)
        return data

    def archive_fixture(self, directory, architecture, notices=None, mode=0o755, extra=False):
        suffix = {"linux":"linux-amd64","armv7":"darwin-armv7","arm64":"darwin-arm64"}[architecture]
        name = "vless-core-"+suffix; binary = directory/name
        binary.write_bytes(self.binary_fixture(architecture)); binary.chmod(mode)
        document = directory/"THIRD_PARTY_LICENSES.txt"
        document.write_bytes((ROOT/document.name).read_bytes() if notices is None else notices)
        archive = directory/(name+".tar.gz")
        with tarfile.open(archive,"w:gz") as tar:
            tar.add(binary,arcname=name); tar.add(document,arcname=document.name)
            if extra:
                tar.add(binary,arcname="unexpected")
        return archive,name

    def test_all_binary_architectures(self):
        for architecture in ("linux","armv7","arm64"):
            with self.subTest(architecture=architecture):
                data = self.binary_fixture(architecture); verify_binary(data,architecture)
                for cut in (0,4,20):
                    with self.assertRaises((AssertionError,struct.error)):
                        verify_binary(data[:cut],architecture)
                changed = bytearray(data); changed[18 if architecture == "linux" else 4] ^= 0x80
                with self.assertRaises(AssertionError):
                    verify_binary(changed,architecture)
                if architecture != "linux":
                    offset = 32 if architecture == "arm64" else 28
                    changed = bytearray(data); struct.pack_into("<I",changed,offset+8,0x60000)
                    with self.assertRaises(AssertionError):
                        verify_binary(changed,architecture)

    def test_macho_runtime_dependencies_and_build_version(self):
        for architecture in ("armv7","arm64"):
            offset = 32 if architecture == "arm64" else 28
            for library, accepted in (("/usr/lib/libSystem.B.dylib",True),("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",True),("/home/vless-core/libssl.so",False)):
                with self.subTest(architecture=architecture,library=library):
                    data = self.binary_fixture(architecture); payload = library.encode()+b"\0"
                    command_length = (24+len(payload)+7)&~7
                    command = struct.pack("<6I",0xc,command_length,24,0,0,0)+payload+b"\0"*(command_length-24-len(payload))
                    struct.pack_into("<II",data,16,2,16+len(command)); data.extend(command)
                    if accepted:
                        verify_binary(data,architecture)
                    else:
                        with self.assertRaises(AssertionError): verify_binary(data,architecture)
            for platform in (1,2):
                with self.subTest(architecture=architecture,platform=platform):
                    data = self.binary_fixture(architecture); data[offset:] = struct.pack("<6I",0x32,24,platform,0xb0000 if architecture == "arm64" else 0x50000,0,0)
                    struct.pack_into("<I",data,20,24)
                    if platform == 2:
                        verify_binary(data,architecture)
                    else:
                        with self.assertRaises(AssertionError): verify_binary(data,architecture)

    def test_archive_contracts(self):
        with tempfile.TemporaryDirectory(prefix="vless-cli-package-") as temporary:
            directory = Path(temporary)
            for architecture in ("linux","armv7","arm64"):
                with self.subTest(architecture=architecture):
                    archive,name = self.archive_fixture(directory,architecture); verify_archive(archive,name,architecture)
                    for arguments in ({"mode":0o644},{"notices":b"wrong"},{"extra":True}):
                        with self.subTest(arguments=arguments):
                            archive,name = self.archive_fixture(directory,architecture,**arguments)
                            with self.assertRaises(AssertionError): verify_archive(archive,name,architecture)

    def test_release_checksum_contracts(self):
        with tempfile.TemporaryDirectory(prefix="vless-cli-checksums-") as temporary:
            directory = Path(temporary); archives = []
            for architecture in ("linux","armv7","arm64"):
                archive,_ = self.archive_fixture(directory,architecture); archives.append(archive)
            lines = [hashlib.sha256(archive.read_bytes()).hexdigest()+"  "+archive.name for archive in archives]
            sums = directory/"SHA256SUMS"; sums.write_text("\n".join(lines)+"\n"); verify_release(directory)
            for changed in (lines[:-1],lines+[lines[0]], ["0"*64+"  "+archives[0].name,*lines[1:]], [*lines[:-1],lines[-1].replace(archives[-1].name,"unknown.tar.gz")]):
                with self.subTest(lines=changed):
                    sums.write_text("\n".join(changed)+"\n")
                    with self.assertRaises(AssertionError): verify_release(directory)

    def test_native_registration_cannot_omit_tests(self):
        env = dict(os.environ,TEST_NATIVE_NAMES="test_uri")
        result = subprocess.run([sys.executable,str(ROOT/"tests/run.py")],env=env,capture_output=True,text=True,timeout=5)
        self.assertNotEqual(result.returncode,0); self.assertIn("native test registration mismatch",result.stdout+result.stderr)

    def test_binary_checker_rejects_corruption(self):
        with self.assertRaises((AssertionError,struct.error)):
            verify_binary(b"bad","armv7")
        data = bytearray(80); struct.pack_into("<7I",data,0,0xfeedface,12,9,2,1,16,0x200000); struct.pack_into("<4I",data,28,0x25,16,0x50000,0x60100)
        verify_binary(data,"armv7")
        for position in (4,8,12,20,26,28,32,36):
            with self.subTest(position=position), self.assertRaises((AssertionError,struct.error)):
                changed = bytearray(data); changed[position] ^= 0x20 if position == 26 else 0x80; verify_binary(changed,"armv7")

    def test_parallel_preflight(self):
        if not all(os.environ.get(name) for name in ("TEST_HOST_FLAGS","TEST_HOST_LIBS","TEST_HOST_CC")):
            raise RuntimeError("Preflight integration tests require the active host compiler, flags and libraries; run them through make test.")
        with tempfile.TemporaryDirectory(prefix="vless-cli-gate-") as temporary:
            directory = Path(temporary)
            project = directory/"project"; project.mkdir()
            shutil.copy2(ROOT/"Makefile",project/"Makefile")
            for name in ("src","include","tests"):
                shutil.copytree(ROOT/name,project/name,ignore=shutil.ignore_patterns("__pycache__"))
            (project/"third_party").symlink_to(ROOT/"third_party",target_is_directory=True)
            marker = directory/"compiler-called"
            compiler = directory/"compiler"
            compiler.write_text('#!/bin/sh\nprintf "called\\n" >>"$VC_TEST_COMPILER_MARKER"\nexit 91\n')
            compiler.chmod(0o700)
            env = dict(os.environ,VC_TEST_FAIL_SCENARIO="uri/tcp-defaults",VC_TEST_COMPILER_MARKER=str(marker))
            sentinel = directory/"outside-project"; sentinel.write_text("vless-core must preserve this file")
            env["BIN_LINUX"] = str(sentinel)
            for name in ("MAKEFLAGS","MFLAGS","MAKELEVEL","MAKEOVERRIDES"):
                env.pop(name,None)
            settings = [f"HOST_BUILD_DIR={directory/'host-tests'}",f"TEST_OPENSSL_PREFIX={os.environ['TEST_OPENSSL_PREFIX']}",f"TEST_XRAY_BIN={os.environ['TEST_XRAY_BIN']}",f"CC={compiler}",f"IOS_CC={compiler}",f"IOS_TOOLCHAIN={ROOT.parent/'toolchains/ios6'}",f"IOS_ARM64_SDK={ROOT.parent/'toolchains/sdks/iPhoneOS11.4.sdk'}",f"HOST_FLAGS={os.environ['TEST_HOST_FLAGS']}",f"HOST_LIBS={os.environ['TEST_HOST_LIBS']}",f"HOST_CC={os.environ['TEST_HOST_CC']}","BIN_LINUX=vless-core-linux-amd64","BIN_IOS=vless-core-darwin-armv7","BIN_IOS_ARM64=vless-core-darwin-arm64","RELEASE_DIR=build/release"]
            fixtures = [str(directory/"host-tests"/name) for name in ("fuzz-parsers","fuzz-encryption","fuzz-http2-pool")]
            prepared = subprocess.run(["make","-j8","-C",str(project/"tests"),"native",*fixtures,*settings],cwd=project,env=env,capture_output=True,text=True,timeout=180)
            self.assertEqual(prepared.returncode,0,prepared.stdout+prepared.stderr)
            self.assertFalse(marker.exists(),prepared.stdout+prepared.stderr)
            targets = ("linux","ios","ios-arm64","all","release-packages","build/linux/main.o","build/ios/main.o","build/ios-arm64/main.o","vless-core-linux-amd64","vless-core-darwin-armv7","vless-core-darwin-arm64")
            for target in targets:
                with self.subTest(target=target):
                    result = subprocess.run(["make","-j8",target,*settings],cwd=project,env=env,capture_output=True,text=True,timeout=45)
                    output = result.stdout+result.stderr
                    self.assertNotEqual(result.returncode,0,output)
                    self.assertIn("FAIL uri/tcp-defaults",output)
                    self.assertFalse(marker.exists(),output)
            for name in ("vless-core-linux-amd64","vless-core-darwin-armv7","vless-core-darwin-arm64"):
                (project/name).write_bytes(b"existing artifact")
            result = subprocess.run(["make","-j8","all",*settings],cwd=project,env=env,capture_output=True,text=True,timeout=45)
            self.assertNotEqual(result.returncode,0); self.assertIn("FAIL uri/tcp-defaults",result.stdout+result.stderr); self.assertFalse(marker.exists())
            env.pop("VC_TEST_FAIL_SCENARIO")
            missing = [setting for setting in settings if not setting.startswith("TEST_OPENSSL_PREFIX=")]+[f"TEST_OPENSSL_PREFIX={directory/'missing'}"]
            result = subprocess.run(["make","-j8","ios",*missing],cwd=project,env=env,capture_output=True,text=True,timeout=15)
            self.assertNotEqual(result.returncode,0); self.assertIn("Missing test OpenSSL dependency",result.stdout+result.stderr); self.assertFalse(marker.exists())
            result = subprocess.run(["make","clean",*missing],cwd=project,env=env,capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr); self.assertNotIn("requirements",result.stdout+result.stderr)
            self.assertEqual(sentinel.read_text(),"vless-core must preserve this file")

def main():
    action = sys.argv[1]
    if action == "binary":
        verify_binary(Path(sys.argv[2]).read_bytes(),sys.argv[3])
    elif action == "archive":
        verify_archive(Path(sys.argv[2]),sys.argv[3],sys.argv[4])
    elif action == "release":
        verify_release(Path(sys.argv[2]))
    elif action == "reset-coverage":
        directory = Path(sys.argv[2]).resolve()
        for obj in directory.rglob("*.gcno"):
            obj.with_suffix(".gcda").unlink(missing_ok=True)
    elif action == "coverage":
        directory = Path(sys.argv[2]).resolve()
        sources = {}
        objects = sorted(directory.rglob("*.gcno"))
        if not objects:
            raise AssertionError("no instrumented test objects")
        for obj in objects:
            result = subprocess.run(["gcov","--json-format","-b","-c",str(obj)],cwd=directory,capture_output=True,text=True,timeout=15)
            if result.returncode:
                raise AssertionError(result.stderr)
            compressed = directory/(obj.stem+".gcov.json.gz")
            with gzip.open(compressed,"rt") as data:
                profile = json.load(data)
            for entry in profile["files"]:
                path = Path(entry["file"])
                if not path.is_absolute():
                    path = Path(profile["current_working_directory"])/path
                path = path.resolve()
                if path.parent != ROOT/"src":
                    continue
                name = str(path.relative_to(ROOT))
                aggregate = sources.setdefault(name,{"lines":{},"branches_per_translation_unit":[]})
                branches = []
                for line in entry["lines"]:
                    number = line["line_number"]
                    aggregate["lines"][number] = aggregate["lines"].get(number,0)+line["count"]
                    branches.extend(line.get("branches",[]))
                aggregate["branches_per_translation_unit"].append({"object":str(obj.relative_to(directory)),"branches":len(branches),"covered":sum(branch["count"]>0 for branch in branches)})
        files = []
        for name,entry in sorted(sources.items()):
            total = len(entry["lines"]); covered = sum(count>0 for count in entry["lines"].values())
            files.append({"file":name,"executable_lines":total,"covered_lines":covered,"line_percent":round(100*covered/total,2) if total else 0,"branches_per_translation_unit":entry["branches_per_translation_unit"]})
        expected = {str(path.relative_to(ROOT)) for path in (ROOT/"src").glob("*.c")}
        if {entry["file"] for entry in files} != expected:
            raise AssertionError("coverage does not contain every production source")
        missing = [entry["file"] for entry in files if not entry["covered_lines"]]
        if missing:
            raise AssertionError(f"production sources have no executed coverage: {missing}")
        if not (directory/"src/main.gcda").is_file():
            raise AssertionError("CLI coverage profile was not saved")
        output = directory/"coverage.json"
        output.write_text(json.dumps({"files":files},indent=2))
        print(f"Coverage: {output}")
    else:
        raise AssertionError(f"unknown verification mode: {action}")
    print(f"PASS build/{action}")

if __name__ == "__main__":
    try:
        main()
    except (AssertionError,OSError,ValueError,struct.error,tarfile.TarError) as error:
        raise SystemExit(f"FAIL build/{sys.argv[1]}: {error}")
