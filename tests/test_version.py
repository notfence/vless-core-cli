import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BUILD = Path(os.environ.get("TEST_BUILD_DIR",ROOT/"build/host-tests"))


class VersionTests(unittest.TestCase):
    def test_version_aliases_and_current_revision(self):
        revision="unknown"
        try:
            top=subprocess.check_output(["git","rev-parse","--show-toplevel"],cwd=ROOT,text=True,stderr=subprocess.DEVNULL).strip()
            if Path(top) == ROOT:
                revision=subprocess.check_output(["git","rev-parse","--short=7","HEAD"],cwd=ROOT,text=True,stderr=subprocess.DEVNULL).strip()
                dirty=subprocess.check_output(["git","status","--porcelain","--untracked-files=normal","--","."],cwd=ROOT,text=True,stderr=subprocess.DEVNULL)
                if dirty: revision+="-dirty"
        except (OSError,subprocess.CalledProcessError): revision="unknown"
        expected=f"vless-core 2.0.0 ({revision})\n"
        for option in ("--version","-v"):
            with self.subTest(option=option):
                result=subprocess.run([str(BUILD/"vless-core-test"),option],capture_output=True,text=True,timeout=5)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(result.stdout,expected); self.assertEqual(result.stderr,"")

    def test_revision_dependencies_and_missing_history(self):
        self.assertTrue((ROOT/"include/build_version.mk").is_file())
        prefix=Path(os.environ.get("TEST_OPENSSL_PREFIX",Path.home()/".local/openssl-3.5"))
        flags=os.environ.get("TEST_HOST_FLAGS",f"-O1 -g -std=c11 -D_DEFAULT_SOURCE -I{ROOT}/include -I{prefix}/include")
        libs=os.environ.get("TEST_HOST_LIBS",f"{prefix}/lib/libssl.a {prefix}/lib/libcrypto.a -lpthread -ldl")
        objects=[path for path in sorted((BUILD/"src").glob("*.o")) if path.name not in ("main.o","cli_args.o")]
        self.assertTrue(objects)
        with tempfile.TemporaryDirectory(prefix="vless-core-version-") as temporary:
            directory=Path(temporary)
            (directory/"src").mkdir()
            for name in ("main.c","cli_args.c","vmess_stream.h"): shutil.copy2(ROOT/"src"/name,directory/"src"/name)
            shutil.copytree(ROOT/"include",directory/"include")
            (directory/".gitignore").write_text("build/\n")
            recipe=f"""CORE_VERSION_ROOT := $(abspath .)
CORE_VERSION_FILES := build/build_version.h
.DEFAULT_GOAL := all
all: build/vless-core
build/main.o: src/main.c build/build_version.h
\t{os.environ.get('TEST_HOST_CC','cc')} -Iinclude {flags} -include build/build_version.h -c $< -o $@
build/cli_args.o: src/cli_args.c | build/build_version.h
\t{os.environ.get('TEST_HOST_CC','cc')} -Iinclude {flags} -c $< -o $@
build/vless-core: build/main.o build/cli_args.o
\t{os.environ.get('TEST_HOST_CC','cc')} $^ {' '.join(map(str,objects))} {BUILD/'network_guard.o'} -o $@ {libs} -Wl,--wrap=getaddrinfo,--wrap=connect
include include/build_version.mk
"""
            (directory/"Makefile").write_text(recipe)
            environment=dict(os.environ,GIT_AUTHOR_NAME="vless-core",GIT_AUTHOR_EMAIL="vless-core@example.invalid",
                             GIT_COMMITTER_NAME="vless-core",GIT_COMMITTER_EMAIL="vless-core@example.invalid")
            for name in ("MAKEFLAGS","MFLAGS","MAKELEVEL","MAKEOVERRIDES"): environment.pop(name,None)

            def command(*arguments):
                result=subprocess.run(arguments,cwd=directory,env=environment,capture_output=True,text=True,timeout=30)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                return result.stdout.strip()

            def build(expected):
                command("make","-j4")
                for option in ("--version","-v"): self.assertEqual(command(str(directory/"build/vless-core"),option),f"vless-core 2.0.0 ({expected})")
                return tuple((directory/path).stat().st_mtime_ns for path in ("build/build_version.h","build/main.o","build/cli_args.o","build/vless-core"))

            original=build("unknown")
            self.assertEqual(build("unknown"),original)
            command("git","init","-q"); command("git","add","."); command("git","commit","-qm","version fixture")
            revision=command("git","rev-parse","--short=7","HEAD")
            clean=build(revision)
            self.assertNotEqual(clean[0],original[0]); self.assertNotEqual(clean[1],original[1]); self.assertEqual(clean[2],original[2]); self.assertNotEqual(clean[3],original[3])
            self.assertEqual(build(revision),clean)
            (directory/"build/ignored-artifact").write_text("vless-core")
            self.assertEqual(build(revision),clean)
            command("git","commit","--allow-empty","-qm","head-only fixture")
            next_revision=command("git","rev-parse","--short=7","HEAD")
            self.assertNotEqual(revision,next_revision)
            changed=build(next_revision)
            self.assertNotEqual(changed[0],clean[0]); self.assertNotEqual(changed[1],clean[1]); self.assertEqual(changed[2],clean[2]); self.assertNotEqual(changed[3],clean[3])
            source=directory/"src/main.c"; content=source.read_bytes(); source.write_bytes(content+b"\n")
            tracked=build(next_revision+"-dirty")
            self.assertEqual(tracked[2],changed[2]); self.assertEqual(build(next_revision+"-dirty"),tracked)
            source.write_bytes(content); build(next_revision)
            untracked=directory/"new-file"; untracked.write_text("vless-core")
            build(next_revision+"-dirty"); untracked.unlink(); build(next_revision)
            (directory/".git").rename(directory/"build/git-history")
            missing=build("unknown"); self.assertEqual(missing[2],changed[2])
            no_git=directory/"build/no-git-tools"; no_git.mkdir()
            (no_git/"python3").symlink_to(shutil.which("python3"))
            environment["PATH"]=str(no_git)
            command(shutil.which("make"),"build/build_version.h")
            self.assertEqual((directory/"build/build_version.h").read_text(),'#define VLESS_CORE_COMMIT "unknown"\n')
