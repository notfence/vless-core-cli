import importlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

BUILD = Path(os.environ["TEST_BUILD_DIR"])
NATIVE = tuple(os.environ["TEST_NATIVE_NAMES"].split())
MODULES = tuple(path.stem for path in sorted(Path(__file__).parent.glob("test_*.py")))

class Result(unittest.TextTestResult):
    def __init__(self, *args, records, **kwargs):
        super().__init__(*args, **kwargs)
        self.records = records

    def addSuccess(self, test):
        super().addSuccess(test)
        self.records.append({"scenario":test.id(),"passed":True})

    def addFailure(self, test, error):
        super().addFailure(test, error)
        self.records.append({"scenario":test.id(),"passed":False,"detail":self._exc_info_to_string(error,test)})

    def addError(self, test, error):
        super().addError(test, error)
        self.records.append({"scenario":test.id(),"passed":False,"detail":self._exc_info_to_string(error,test)})

    def addSubTest(self, test, subtest, error):
        super().addSubTest(test, subtest, error)
        record = {"scenario":subtest.id(),"passed":error is None}
        if error:
            record["detail"] = self._exc_info_to_string(error,test)
        self.records.append(record)

    def addSkip(self, test, reason):
        self.addFailure(test, (AssertionError,AssertionError(f"mandatory test skipped: {reason}"),None))

def main():
    records = []
    started = time.monotonic()
    if not NATIVE or len(set(NATIVE)) != len(NATIVE) or not MODULES:
        raise ValueError("empty or duplicate test registration")
    directory = Path(__file__).parent
    expected = {path.stem for pattern in ("test_*.c","*_test.c") for path in directory.glob(pattern)}
    if set(NATIVE) != expected:
        raise ValueError(f"native test registration mismatch: expected {sorted(expected)}, actual {sorted(NATIVE)}")
    private_parent = Path.home()/".local/state"
    private_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="vless-cli-tests-",dir=private_parent) as private:
        os.environ["TEST_PRIVATE_ROOT"] = private
        for name in NATIVE:
            log = BUILD/f"{name}.log"
            try:
                result = subprocess.run([str(BUILD/name)],capture_output=True,text=True,timeout=30)
                output = result.stdout + result.stderr
                log.write_text(output)
                for line in output.splitlines():
                    if line.startswith(("PASS ","FAIL ")):
                        scenario = line[5:].split(":",1)[0]
                        records.append({"scenario":scenario,"passed":line.startswith("PASS "),"detail":line if line.startswith("FAIL ") else ""})
                records.append({"scenario":f"native/{name}","passed":result.returncode == 0,"log":str(log),"returncode":result.returncode})
                print(f"{'PASS' if result.returncode == 0 else 'FAIL'} native/{name}: {log}",flush=True)
                if result.returncode:
                    print("\n".join(line for line in output.splitlines() if line.startswith("FAIL ")) or output[-3000:],flush=True)
                if os.environ.get("VC_TEST_FAIL_SCENARIO"):
                    if result.returncode:
                        return 1
            except (OSError,subprocess.TimeoutExpired) as error:
                records.append({"scenario":f"native/{name}","passed":False,"detail":str(error)})
                print(f"FAIL native/{name}: {error}",flush=True)
        suite = unittest.TestSuite()
        for name in MODULES:
            tests = unittest.defaultTestLoader.loadTestsFromModule(importlib.import_module(name))
            if not tests.countTestCases():
                raise ValueError(f"test module has no scenarios: {name}")
            suite.addTests(tests)
        runner = unittest.TextTestRunner(verbosity=2,resultclass=lambda *args,**kwargs: Result(*args,records=records,**kwargs))
        runner.run(suite)
    report = {"xray":"26.6.27","duration_seconds":round(time.monotonic()-started,2),"records":records}
    report_path = BUILD/"report.json"
    report_path.write_text(json.dumps(report,ensure_ascii=False,indent=2))
    failures = [record for record in records if not record["passed"]]
    print(f"{'FAIL' if failures else 'PASS'} regression suite: {len(records)} recorded results, {len(failures)} failures; {report_path}")
    return bool(failures)

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError,ValueError,ImportError) as error:
        raise SystemExit(f"FAIL test infrastructure: {error}")
