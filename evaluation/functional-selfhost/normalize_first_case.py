"""One CLOSED-data encoding join; never executes a subject or generated product."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import stat
import sys

if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit("Use assertions-enabled Python -I -B")
assert len(sys.argv) == 2 and len(os.sched_getaffinity(0)) == 1
for key,n in ((resource.RLIMIT_CPU,30),(resource.RLIMIT_AS,268435456),
              (resource.RLIMIT_FSIZE,1048576),(resource.RLIMIT_CORE,0)):
    resource.setrlimit(key,(n,n))
ROOT = Path.cwd().resolve(); OUT = Path(sys.argv[1]).absolute()
assert OUT == OUT.resolve() and OUT.parent == ROOT/"ignored/a3/functional-selfhost-proposal-v1" and not OUT.exists()
P = ROOT/"ignored/a3"; authorities = {}; snapshots = {}


def stamp(s):
    return (s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)


def read(path,n,d):
    fd = os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before = os.fstat(fd); assert stat.S_ISREG(before.st_mode) and before.st_size == n <= 4*1024**2
        chunks = []; count = 0
        while True:
            b = os.read(fd,65536)
            if not b: break
            count += len(b); assert count <= n; chunks.append(b)
        data = b"".join(chunks); assert count == n and hashlib.sha256(data).hexdigest() == d
        assert stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat())
        authorities[str(path.relative_to(ROOT))] = dict(bytes=n,sha256=d)
        snapshots[str(path)] = stamp(before); return data
    finally: os.close(fd)


def digest(rows):
    return hashlib.sha256(json.dumps(rows,separators=(",",":")).encode()).hexdigest()


root = json.loads(read(P/"overlapping-neighbor-functional-compare-owner-v1/root-closed.json",4307,"a42a64bc0344465ae1afa3506c3c8d57e13cd515baadfd5f037843c73538a1c4"))
assert root["source_unchanged"] and root["outer_pid_and_both_scopes_absent"] and root["comparison_status"] == "FAILED_OUTCOME_RETAINED"
closed = json.loads(read(P/"overlapping-neighbor-functional-compare-owner-v1/closed.json",893,"e36a0abf228a854fa9354df4c09f18a8aa0c6d84cdcc05cdc866146000049cc1"))
owned = json.loads(read(P/"overlapping-neighbor-functional-compare-owner-v1/owner-closed.json",432,"4d8196c1c74655180102ff1e4d64e41527834cf01e8658368cf946825610f0c3"))
assert root["outer"] == closed["result"] == owned["result"]
assert closed["normal"] and not closed["passed"] and closed["source_unchanged"]
assert root["outer"]["exit_code"] == 1 and root["outer"]["termination"] is None and root["outer"]["cleanup_complete"] and root["outer"]["reaped_descendants"] == 0
receipt = json.loads(read(P/"overlapping-neighbor-functional-compare-v1/receipt.json",24742,"b60232f9ebd523e9d0ee5c1ce3d9ce4de1b38a63f4dfd0e8db68a6e710391767"))
assert receipt["status"] == "FAILED_OUTCOME_RETAINED" and receipt["source_unchanged"]
assert receipt["dispatch_attempts"] == ["original","li2","e9"] and receipt["not_started"] == []
arm = receipt["arms"]["original"]; owner = arm["owner"]
assert owner["exit_code"] == 0 and owner["termination"] is None and owner["cleanup_complete"] and owner["reaped_descendants"] == 0
request = P/"overlapping-neighbor-functional-prepare-v1/cwd/request.jsonl"
read(request,2586720,"bb4146fe44138559a769376c215ccc40c32c203dd157aa7dfe32863bd8bd104e")
log = P/"overlapping-neighbor-functional-compare-v1/original.log"
raw = read(log,2043698,"bb4dc9850c143ed3df0f5b9092af9d063428a2ce66e9133ee992c47225cd0548")
assert owner["private_log_sha256"] == arm["log"]["sha256"] == hashlib.sha256(raw).hexdigest()
helper = ROOT/"evaluation/functional-corpus/run.py"
read(helper,26979,"69c7d87ecf8d249a0a7b325db78f05d770fad993994eba97a40bb8338c0c4f6a")
definitions = json.loads(read(ROOT/"evaluation/functional-corpus/definitions.json",3397,"3a9840b193779ec590cc5b189f3dac4b9671ffc55689b5caf18095de63a20d78"))
read(P/"upstream/e9patch-pldi2020/e9patch",93520,"890f76cb5741b6c7cfba3414ae72a64fd7deddc7d2dd33b17d53e8b906529fdb")
spec = importlib.util.spec_from_file_location("closed_first_case_helpers",helper)
h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
info,lengths = h.request(request,"e9patch",h.ACTIONS[0],definitions); info["source"] = "e9patch"
assert info["requested"] == 12924 and info["messages"] == 25851 and info["text"] == [9328,9328,52267]
stats = h.statistics(log,info,lengths,2329308)
assert stats["strict_full"] is False and (stats["successful"],stats["requested"],stats["failed"]) == (12919,12924,5)
address = rb"(?:\[absolute\] )?-?0x[0-9a-f]+"
good = list(re.finditer(rb"debug: patched instruction 0x([0-9a-f]+) \[size=([0-9]+), tactic=(B1|B2|T1|T2|T3), trampoline="+address+rb"\.\."+address+rb"\]",raw))
bad = list(re.finditer(rb"debug: failed to patch instruction at address 0x([0-9a-f]+) \(([0-9]+)\)",raw))
assert len(good) == raw.count(b"debug: patched instruction ") == 12919
assert len(bad) == raw.count(b"debug: failed to patch instruction") == 5
events = [(m.start(),int(m[1],16),int(m[2]),"success",m[3].decode()) for m in good]
events += [(m.start(),int(m[1],16),int(m[2]),"failure",None) for m in bad]
four = [(a,n,status,tactic) for pos,a,n,status,tactic in sorted(events)]
three = [(a,n,tactic if status == "success" else "FAILED") for a,n,status,tactic in four]
assert [(a,n) for a,n,status,tactic in four] == [(9328+j,n) for j,n in reversed(list(enumerate(lengths))) if n]
assert digest(four) == "81f80e7b4d8271b87b758e174acf2f2facd57325d0c0d24a06de64f5009e7e33"
assert digest(three) == stats["complete_ordered_outcomes_sha256"]
failed = [(a,n) for a,n,status,tactic in four if status == "failure"]
assert failed == [(55737,1),(53862,1),(48747,1),(43400,1),(14389,1)]
assert all(stamp(Path(p).lstat()) == q for p,q in snapshots.items())
result = dict(status="NORMALIZED_CLOSED_DATA_ONLY",first_generation_status="FAILED_OUTCOME_RETAINED",requested=12924,successful=12919,failed=failed,
              historical_four_field_sha256=digest(four),helper_three_field_sha256=digest(three),statistics=stats,authorities=authorities,
              source_unchanged=True,cpus=sorted(os.sched_getaffinity(0)),native_attempts=0,metadata_limits=dict(cpu=30,as_bytes=268435456,file_bytes=1048576,core=0))
with OUT.open("x") as f:
    json.dump(result,f,separators=(",",":")); f.write("\n"); f.flush(); os.fsync(f.fileno())
print(json.dumps(dict(status=result["status"],bytes=OUT.stat().st_size,sha256=hashlib.sha256(OUT.read_bytes()).hexdigest())))
