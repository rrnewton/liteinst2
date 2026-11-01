#!/usr/bin/env python3
"""Fixed stock backend matrix; strict coverage and descriptive equality are separate."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import stat
import struct
import subprocess
import sys

if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit("Use assertions-enabled Python -I -B")
ROOT, SELF = Path.cwd().resolve(), Path(__file__).resolve()
REV = "438954e0e1372fdb428b3446d69aca804ccd29ea"
M = 1024**2
ENV = dict(PATH="/usr/bin:/bin", LANG="C", LC_ALL="C", TZ="UTC", PYTHONDONTWRITEBYTECODE="1")
UP = "ignored/a3/upstream/e9patch-pldi2020/"
INPUTS = {
    "e9patch": (UP + "e9patch", 93520, "890f76cb5741b6c7cfba3414ae72a64fd7deddc7d2dd33b17d53e8b906529fdb"),
    "e9tool": (UP + "e9tool", 2622048, "36b05e9a47c9193041d71ed4e14dda87e835e0e2b47e4a82a7d30a7c0d4eeb5e"),
    "li2": ("ignored/a3/overlapping-neighbor-attempt-v1/li2-packed-overlapping-hull512m/candidate.elf", 8896819, "8ef3638015783562a440bd52811c525c3c7162d0177e2723e199bc07686fd76e"),
    "e9": ("ignored/a3/full-program-backend-36g-run-v1/retained/a.out", 282324, "eabf1d463a75d5644ec114bed7b66ace8c7a00f6a64892a4600e8a5661547afc"),
    "nop": ("ignored/a3/e9-upstream-corpus-v1/work/nop", 13216, "0014fa555659f12d6f44ab618a2afe235e9ec908b29706836693711e94dd2845"),
}
TOOLS = {
    "evaluation/admission/processes.py": (15760, "0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f"),
    "/usr/bin/python3.9": (15448, "9cfdf1a01d07dadb394dd2dc9fd8316254c36764076d23dc2c895c8401735576"),
    "/usr/bin/env": (45088, "1caef498bf8afe1633c37cbe6ec6e10908cfdf032505d85c0b14ce906bae489f"),
    "/usr/bin/git": (4397400, "55c09f77ea636d99e0c163c1e406ce44dfb125dd70a01c6ed6b5bbecd5f4b240"),
    "/usr/bin/du": (152832, "509baa6d93d9afb7aaecb4aed33bf87f5122e0ba64583614611b57f2c0b1ae2f"),
    "/usr/bin/prlimit": (28416, "942bcd8596c242d4d33dca657372a83e1f55908afd59b525389362cd6d282933"),
}
SIBLINGS = {
    "capture.py": (1065, "ef8e46eb42f44083cfd0988fe9116b20bf6aa7416158c0f19b13cb744655eb84"),
    "definitions.json": (3397, "3a9840b193779ec590cc5b189f3dac4b9671ffc55689b5caf18095de63a20d78"),
    "first-case.json": (7639, "1fd8e3cfe208becf992f8edbc990a0e6acdca45fef3a26c3a49cfc6e06652c0d"),
}
ACTIONS = ["=.*:passthru", "=.*:call entry@nop", "=.*:call[naked,after] entry@nop",
           "=.*:call entry(instrAsmStr,instrBytes,rflags,rdi,rip,instrAddr)@nop", "=.*:print"]
ROLES = ("original", "li2", "e9")


def stamp(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def fd_pin(fd, cap):
    s = os.fstat(fd); assert stat.S_ISREG(s.st_mode) and s.st_size <= cap
    os.lseek(fd, 0, 0); h = hashlib.sha256(); n = 0
    while True:
        b = os.read(fd, M)
        if not b: break
        n += len(b); assert n <= cap; h.update(b)
    assert n == s.st_size and stamp(s) == stamp(os.fstat(fd)); os.lseek(fd, 0, 0)
    return dict(bytes=n, sha256=h.hexdigest(), stat=stamp(s))


def pin(path, cap=512*M):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        q = fd_pin(fd, cap); assert q["stat"] == stamp(Path(path).lstat()); return q
    finally: os.close(fd)


def owned(path, expected):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    hold = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 10); os.close(fd)
    q = fd_pin(hold, expected[0]); assert (q["bytes"], q["sha256"]) == tuple(expected)
    assert q["stat"] == stamp(path.lstat()); return hold


def save(path, record):
    t = path.with_suffix(".tmp")
    with t.open("w") as f:
        json.dump(record, f, separators=(",", ":")); f.write("\n"); f.flush(); os.fsync(f.fileno())
    os.replace(t, path)


def ready(cpu, unit):
    assert os.sched_getaffinity(0) == {cpu} and Path.cwd().resolve() == ROOT
    git = ["/usr/bin/git", "--no-optional-locks", "-c", "index.threads=1", "-c", "core.preloadIndex=false"]
    assert subprocess.check_output(git+["rev-parse", "HEAD"], timeout=10).decode().strip() == REV
    assert not subprocess.check_output(git+["status", "--porcelain", "--untracked-files=no"], timeout=10)
    cg = Path("/proc/self/cgroup").read_text().strip()
    assert unit.startswith("li2core-functional-") and re.fullmatch(r"[A-Za-z0-9-]+", unit)
    assert cg.startswith("0::/") and "\n" not in cg and ".." not in Path(cg[3:]).parts
    assert cg.endswith("/"+unit+".scope"); path = Path("/sys/fs/cgroup")/cg[4:]
    v = {n:(path/n).read_text().strip() for n in ("memory.max", "memory.swap.max", "pids.max", "cpu.max", "cpuset.cpus.effective")}
    assert [v[n] for n in ("memory.max", "memory.swap.max", "pids.max", "cpuset.cpus.effective")] == [str(1024*M), "0", "64", str(cpu)]
    q, p = map(int, v["cpu.max"].split()); assert q == p and p > 0
    return dict(pid=os.getpid(), stat=Path("/proc/self/stat").read_text(), cgroup=cg, properties=v,
                load=os.getloadavg(), root_identity=[ROOT.stat().st_dev, ROOT.stat().st_ino],
                memory_events=(path/"memory.events").read_text(), memory_peak=(path/"memory.peak").read_text())


def elf(data):
    h = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    assert h[0][:6] == b"\x7fELF\x02\x01" and h[1] in (2,3) and h[2] == 62 and h[9] == 56
    ph = [struct.unpack_from("<IIQQQQQQ", data, h[5]+i*56) for i in range(h[10])]
    return h, ph


def text_section(data):
    h, ph = elf(data); assert h[11] == 64 and 0 < h[13] < h[12]
    sh = [struct.unpack_from("<IIQQQQIIQQ", data, h[6]+i*64) for i in range(h[12])]
    strings = data[sh[h[13]][4]:sum(sh[h[13]][4:6])]
    rows = [r for r in sh if strings[r[0]:].split(b"\0",1)[0] == b".text"]
    assert len(rows) == 1; r = rows[0]; assert r[1] == 1 and r[2]&6 == 6 and r[4]+r[5] <= len(data)
    return r[3:6], max(p[3]+p[6] for p in ph)


def request(path, source, action, definitions):
    data = (ROOT/INPUTS[source][0]).read_bytes(); (address, offset, size), free = text_section(data)
    limit = 8*M if (source, action) == ("e9patch", ACTIONS[0]) else 1024*size+65536
    before = pin(path, limit); lengths = bytearray(size); count = patches = 0; last = size
    target = definitions["inputs"][source]; assert target["free_addr"] == free
    base = (free+0x1000000+8*4096+4095)&~4095; assert base == target["nop_base"]
    template = json.loads(json.dumps(definitions["templates"][action]).replace('"@ENTRY_TARGET@"', str(target["entry_target"])))
    prefix = [("binary", dict(filename="/proc/self/fd/3", mode="exe"))]
    if "call" in action:
        nop = (ROOT/INPUTS["nop"][0]).read_bytes()
        for s in definitions["nop"]["load_segments"]:
            b = nop[s["offset"]:s["offset"]+s["filesz"]]+bytes(s["memsz"]-s["filesz"])
            assert hashlib.sha256(b).hexdigest() == s["bytes_sha256"]
            prefix.append(("reserve", dict(address=base+s["vaddr"], protection=s["protection"], bytes=list(b))))
    prefix.append(("trampoline", template)); emit = dict(filename="a.out", format="binary", mapping_size=32768)
    def unique(pairs):
        d = {}
        for k,v in pairs: assert k not in d; d[k] = v
        return d
    with path.open("rb") as f:
        for i, raw in enumerate(iter(lambda:f.readline(M+1), b"")):
            assert len(raw) <= M and raw.endswith(b"\n")
            row = json.loads(raw, object_pairs_hook=unique)
            assert set(row) == {"jsonrpc","method","params","id"} and row["jsonrpc"] == "2.0" and type(row["id"]) is int and row["id"] == i
            method, p = row["method"], row["params"]
            if i < len(prefix): assert (method,p) == prefix[i]; continue
            if method == "instruction":
                assert set(p) == {"address","offset","length"} and all(type(v) is int for v in p.values())
                n, j = p["length"], p["offset"]-offset
                assert 0 <= j < size and 1 <= n <= 15 and j+n <= size and not lengths[j] and p["address"] == address+j
                lengths[j] = n; count += 1
            elif method == "patch":
                j = p["offset"]-offset; assert 0 <= j < last and lengths[j] and p["trampoline"] == template["name"]; last = j; patches += 1
                keys = {"trampoline","offset"}
                if action in (ACTIONS[3], ACTIONS[4]):
                    keys.add("metadata"); md = p["metadata"]; s = md["$asmStr"]
                    assert isinstance(s,str) and "\0" not in s and len(s.encode()) <= 255
                    if action == ACTIONS[3]: assert set(md) == {"$asmStr","$bytes"} and md["$bytes"] == list(data[offset+j:offset+j+lengths[j]])
                    else: assert set(md) == {"$asmStr","$asmStrLen"} and s.endswith("\n") and md["$asmStrLen"] == {"int32":len(s.encode())}
                assert set(p) == keys
            else:
                assert method == "emit" and p == emit and not f.read(1)
        assert method == "emit" and i+1 == len(prefix)+2*count+1 and patches == count
    cursor = visited = 0
    while cursor < size: assert lengths[cursor]; cursor += lengths[cursor]; visited += 1
    assert cursor == size and visited == count == sum(bool(n) for n in lengths) and pin(path,limit) == before
    return dict(pin=before, requested=count, text=[address,offset,size], messages=i+1, limit=limit), lengths


def product(path):
    q = pin(path); assert q["bytes"] >= 64
    with path.open("rb") as f:
        data = f.read(64); h = struct.unpack("<16sHHIQQQIHHHHHH", data)
        assert h[0][:6] == b"\x7fELF\x02\x01" and h[1] in (2,3) and h[2] == 62
        assert h[9] == 56 and 0 < h[10] < 65535 and h[5]+h[10]*56 <= q["bytes"]
        f.seek(h[5]); ph = [struct.unpack("<IIQQQQQQ", f.read(56)) for _ in range(h[10])]
        loads = [p for p in ph if p[0] == 1]
        assert loads and all(p[2]+p[5] <= q["bytes"] and p[5] <= p[6] for p in loads)
        assert any(p[1]&1 and p[3] <= h[4] < p[3]+p[6] for p in loads)
    assert pin(path) == q; return q


def statistics(path, info, lengths, output_size):
    raw = path.read_bytes(); n = info["requested"]
    def one(pattern):
        r = re.findall(pattern,raw,re.MULTILINE); assert len(r) == 1; return r[0]
    total = tuple(map(int, one(rb"^num_patched + = ([0-9]+) / ([0-9]+) \((?:[0-9]+\.[0-9]{2}|~100\.00)%\)$")))
    assert total[1] == n and 0 <= total[0] <= n
    if total[0] == n: assert one(rb"^num_patched + = ([0-9]+) / ([0-9]+) \(100\.00%\)$") == (str(n).encode(),str(n).encode())
    tactics = {}
    for name in ("B1","B2","T1","T2","T3"):
        k,d = map(int, one(rb"^num_patched_"+name.encode()+rb" + = ([0-9]+) / ([0-9]+) \([0-9]+\.[0-9]{2}%\)$")); assert d == n; tactics[name] = k
    assert sum(tactics.values()) == total[0]
    address = rb"(?:\[absolute\] )?-?0x[0-9a-f]+"
    sm = list(re.finditer(rb"debug: patched instruction 0x([0-9a-f]+) \[size=([0-9]+), tactic=(B1|B2|T1|T2|T3), trampoline="+address+rb"\.\."+address+rb"\]",raw))
    fm = list(re.finditer(rb"debug: failed to patch instruction at address 0x([0-9a-f]+) \(([0-9]+)\)",raw))
    success, failures = [m.groups() for m in sm], [m.groups() for m in fm]
    assert raw.count(b"debug: patched instruction ") == len(success) == total[0]
    assert raw.count(b"debug: failed to patch instruction") == len(failures) == n-total[0]
    assert {k:sum(t == k.encode() for a,b,t in success) for k in tactics} == tactics
    expected = [(info["text"][0]+j,n) for j,n in reversed(list(enumerate(lengths))) if n]
    good = [(int(a,16),int(b)) for a,b,t in success]; bad = [(int(a,16),int(b)) for a,b in failures]
    assert len(set(good+bad)) == n and sorted(good+bad,reverse=True) == expected
    assert good == sorted(good,reverse=True) and bad == sorted(bad,reverse=True)
    events = [(m.start(),int(m[1],16),int(m[2]),m[3].decode()) for m in sm]
    events += [(m.start(),int(m[1],16),int(m[2]),"FAILED") for m in fm]
    outcomes = [(a,b,t) for pos,a,b,t in sorted(events)]
    assert [(a,b) for a,b,t in outcomes] == expected
    assert one(rb"^input_binary + = (.+)$") == b"/proc/self/fd/3" and one(rb"^input_mode + = (.+)$") == b"EXECUTABLE"
    assert int(one(rb"^input_file_size + = ([0-9]+)$")) == INPUTS[info["source"]][1]
    assert int(one(rb"^output_file_size + = ([0-9]+) \([0-9]+\.[0-9]{2}%\)$")) == output_size
    return dict(strict_full=total[0]==n, successful=total[0], requested=n, failed=len(bad), tactics=tactics,
                failed_tuples_sha256=hashlib.sha256(json.dumps(bad,separators=(",",":")).encode()).hexdigest(),
                complete_ordered_outcomes_sha256=hashlib.sha256(json.dumps(outcomes,separators=(",",":")).encode()).hexdigest(),
                ordered_coverage_sha256=hashlib.sha256(json.dumps(expected,separators=(",",":")).encode()).hexdigest())


def child(mode, source, action, role, cwd, inputs, request_path, size, digest, cpu):
    assert os.sched_getaffinity(0) == {cpu}
    factor = 4 if source == "e9tool" else 1
    limit = int(size) if mode == "--generate" else 512*M
    for which,value in [(resource.RLIMIT_CPU,(30 if mode=="--generate" else 60)*factor),
                        (resource.RLIMIT_AS,(1024 if mode=="--generate" else 36*1024)*M),
                        (resource.RLIMIT_FSIZE,limit),(resource.RLIMIT_CORE,0)]: resource.setrlimit(which,(value,value))
    exe_key = "e9tool" if mode == "--generate" else ("e9patch" if role == "original" else role)
    executable = owned(inputs/exe_key, INPUTS[exe_key][1:]); original = owned(inputs/source,INPUTS[source][1:])
    os.dup2(original,3,inheritable=True); os.close(original)
    if mode == "--generate":
        capture = owned(SELF.with_name("capture.py"), SIBLINGS["capture.py"]); os.dup2(capture,4,inheritable=True); os.close(capture)
        argv = ["e9tool","/proc/self/fd/3","--action="+action,"-c","6","-s","--backend","/proc/self/fd/4","-o","a.out"]
    else:
        rpc = owned(request_path,(int(size),digest)); os.dup2(rpc,0,inheritable=True); os.close(rpc)
        argv = ["e9patch","--static-loader","--debug"]
    assert os.fstat(executable).st_mode&0o777 == 0o500
    os.chdir(cwd); os.umask(0o077); os.execve(executable,argv,ENV)
    raise RuntimeError("execve returned")


def equal(left, right):
    with left.open("rb") as a, right.open("rb") as b:
        sa, sb = stamp(os.fstat(a.fileno())), stamp(os.fstat(b.fileno())); same = True
        while True:
            x,y = a.read(M),b.read(M)
            if x != y: same = False
            if not x and not y: break
        assert sa == stamp(os.fstat(a.fileno())) and sb == stamp(os.fstat(b.fileno()))
    return same


def main():
    parser = argparse.ArgumentParser(description=__doc__,allow_abbrev=False)
    parser.add_argument("--cpu",type=int,required=True); parser.add_argument("--unit",required=True)
    parser.add_argument("--out",type=Path,required=True); parser.add_argument("--cases",choices=("all","remaining-nine"),required=True)
    a = parser.parse_args(); out = a.out.absolute(); logs = ROOT/"target/evaluation"/out.name
    assert out == out.resolve() and out.parent == ROOT/"ignored/a3" and not out.exists() and not logs.exists()
    out.mkdir(mode=0o700); logs.mkdir(mode=0o700); (out/"inputs").mkdir(); (out/"logs").mkdir()
    cases = []
    for i,action in enumerate(ACTIONS):
        for source in ("e9tool","e9patch"):
            size = 198411 if source == "e9tool" else 52267; factor = (size+52266)//52267
            rpccap = 8*M if (source,action) == ("e9patch",ACTIONS[0]) else 1024*size+65536
            case = dict(id=str(i)+"-"+source,source=source,action=action,status="UNOBSERVED",execution="NOT_STARTED",
                        arms={r:dict(strict_full=False,valid_elf=False,status="UNOBSERVED") for r in ROLES},
                        factor=factor,text_bytes=size,rpc_limit=rpccap,environment=ENV,
                        generator=dict(argv=["e9tool","/proc/self/fd/3","--action="+action,"-c","6","-s","--backend","/proc/self/fd/4","-o","a.out"],
                                       cpu_seconds=30*factor,wall_seconds=45*factor,address_space_bytes=1024*M,file_bytes=rpccap,log_bytes=8*M*factor),
                        backend=dict(argv=["e9patch","--static-loader","--debug"],cpu_seconds=60*factor,wall_seconds=90*factor,
                                     address_space_bytes=36*1024*M,file_bytes=512*M,log_bytes=8*M*factor))
            if a.cases == "remaining-nine" and (source,action) == ("e9patch",ACTIONS[0]):
                case.update(status="FAILED_OUTCOME_RETAINED",execution="HISTORICAL",strict_pass=False,new_backend_attempts=0,
                            history=dict(zip(("bytes","sha256"),SIBLINGS["first-case.json"])),arms={})
            cases.append(case)
    record = dict(revision=REV, case_set=a.cases, status="PREFLIGHT", cases=cases, dispatch_attempts=[],
                  source_unchanged=False, qualification_complete=False, performance_qualified=False)
    frozen = {}; receipt = out/"receipt.json"; active = None; checked = False
    def persist(): save(receipt,record)
    def unchanged(): assert all(pin(Path(p)) == q for p,q in frozen.items())
    def charge():
        apparent = allocated = 0
        for root in (out,logs):
            for directory,dirs,files in os.walk(root,followlinks=False):
                for p in [Path(directory),*(Path(directory)/n for n in files)]:
                    s = p.lstat(); assert stat.S_ISREG(s.st_mode) or stat.S_ISDIR(s.st_mode)
                    apparent += s.st_size; allocated += s.st_blocks*512
                assert all(not (Path(directory)/n).is_symlink() for n in dirs)
        return dict(apparent=apparent,allocated=allocated,charged=max(apparent,allocated))
    def budget(allowance):
        v = charge(); assert v["charged"]+allowance+M <= 2048*M, "Run envelope exhausted; no next dispatch"
        assert record["baseline_slot"]+2048*M+64*M <= 20_000_000_000
        record["capacity"] = v; return v
    def dispatch(row,command,wall,cap,allowance):
        unchanged(); row.update(command=command,before=ready(a.cpu,a.unit),admission=budget(allowance),status="DISPATCHED")
        index = len(record["dispatch_attempts"]); record["dispatch_attempts"].append(row); persist()
        log = logs/(str(index)+".log")
        row["owner"] = owner.run_command(command,ENV,log,wall,cap); persist()
        r = row["owner"]; assert r["cleanup_complete"], "Unresolved ownership: no output read"
        q = pin(log,cap); assert q["sha256"] == r["private_log_sha256"]
        retained = out/"logs"/log.name
        with log.open("rb") as src, retained.open("xb") as dst:
            while True:
                b = src.read(M)
                if not b: break
                dst.write(b)
            dst.flush(); os.fsync(dst.fileno())
        assert pin(retained,cap)["sha256"] == q["sha256"]
        row.update(log=q,retained_log=str(retained),after=ready(a.cpu,a.unit),status="CLOSED"); unchanged(); persist()
        assert r["reaped_descendants"] == 0, "Lifecycle failure: stop campaign"
        return retained
    try:
        persist()
        for path,expected in [(ROOT/n,p) for n,p in TOOLS.items()]+[(ROOT/v[0],v[1:]) for v in INPUTS.values()]+[(SELF.with_name(n),p) for n,p in SIBLINGS.items()]:
            q = pin(path); assert (q["bytes"],q["sha256"]) == tuple(expected); frozen[str(path)] = q
        frozen[str(SELF)] = pin(SELF); definitions = json.loads(SELF.with_name("definitions.json").read_text())
        for n,p in definitions["source_pins"].items():
            path = ROOT/UP/n; q = pin(path); assert (q["bytes"],q["sha256"]) == (p["bytes"],p["sha256"]); frozen[str(path)] = q
        history = json.loads(SELF.with_name("first-case.json").read_text())
        assert history["case"] == "e9patch:passthru" and history["status"] == "FAILED_OUTCOME_RETAINED"
        record["before"] = ready(a.cpu,a.unit); checked = True
        spec = importlib.util.spec_from_file_location("corpus_owner",ROOT/"evaluation/admission/processes.py")
        owner = importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)
        capacity = []
        for apparent in (False,True):
            command = ["/usr/bin/prlimit","--cpu=30","--as=268435456","--fsize=65536","--core=0","--","/usr/bin/du","--block-size=1","--count-links","-s"]
            if apparent: command.append("--apparent-size")
            command += [str(ROOT),str(ROOT/"ignored"),str(ROOT/"target")]
            log = logs/("baseline-"+str(int(apparent))+".log")
            row = dict(command=command); capacity.append(row); record["capacity_queries"] = capacity; persist()
            row["owner"] = owner.run_command(command,ENV,log,60,65536); persist()
            r = row["owner"]; assert r["cleanup_complete"] and r["exit_code"] == 0 and r["termination"] is None and r["reaped_descendants"] == 0
            q = pin(log,65536); assert q["sha256"] == r["private_log_sha256"]
            values = [line.split("\t",1) for line in log.read_text().splitlines()]
            assert [p for n,p in values] == [str(ROOT),str(ROOT/"ignored"),str(ROOT/"target")]
            row.update(log=q,values={p:int(n) for n,p in values}); unchanged()
        record["baseline_slot"] = max(r["values"][str(ROOT)] for r in capacity)
        budget(12*M)
        copies = out/"inputs"
        for name,(p,n,h) in INPUTS.items():
            target = copies/name
            with (ROOT/p).open("rb") as src, target.open("xb") as dst: dst.write(src.read()); dst.flush(); os.fsync(dst.fileno())
            target.chmod(0o500); q = pin(target); assert (q["bytes"],q["sha256"]) == (n,h)
            assert q["stat"][:2] != frozen[str(ROOT/p)]["stat"][:2] and target.stat().st_nlink == 1; frozen[str(target)] = q
        assert len({tuple(frozen[str(copies/n)]["stat"][:2]) for n in INPUTS}) == len(INPUTS)
        record["inputs"] = frozen; persist()
        for case in record["cases"]:
            source,action = case["source"],case["action"]
            if case["execution"] == "HISTORICAL":
                case["history"] = pin(SELF.with_name("first-case.json")); persist(); continue
            active = case; case.update(status="IN_PROGRESS",execution="CURRENT"); persist()
            factor = case["factor"]; logcap = 8*M*factor
            size = text_section((copies/source).read_bytes())[0][2]; assert size == case["text_bytes"]
            rpccap = case["rpc_limit"]
            cwd = out/case["id"]; cwd.mkdir(); gen = cwd/"generate"; gen.mkdir()
            budget(rpccap+2*logcap+13216)
            if "call" in action:
                (gen/"nop").write_bytes((copies/"nop").read_bytes()); frozen[str(gen/"nop")] = pin(gen/"nop")
            command = ["/usr/bin/python3.9","-I","-B",str(SELF),"--generate",source,action,"none",str(gen),str(copies),str(gen/"request.jsonl"),str(rpccap),"none",str(a.cpu)]
            case["generation"] = {}; log = dispatch(case["generation"],command,45*factor,logcap,rpccap+2*logcap)
            try:
                r = case["generation"]["owner"]; assert r["exit_code"] == 0 and r["termination"] is None and not log.read_bytes()
                assert sorted(p.name for p in gen.iterdir()) == (["nop","request.jsonl"] if "call" in action else ["request.jsonl"])
                rpc = gen/"request.jsonl"; info,lengths = request(rpc,source,action,definitions); info["source"] = source
            except (AssertionError,OSError,ValueError,KeyError,TypeError,struct.error) as error:
                unchanged(); ready(a.cpu,a.unit)
                case.update(status="FAILED_OUTCOME_RETAINED",strict_pass=False,generation_error=dict(type=type(error).__name__,message=str(error)))
                active = None; persist(); continue
            unchanged(); case["request"] = info; frozen[str(rpc)] = info["pin"]; persist()
            for role in ROLES:
                work = cwd/role; work.mkdir(); arm = case["arms"][role]
                command = ["/usr/bin/python3.9","-I","-B",str(SELF),"--backend",source,action,role,str(work),str(copies),str(rpc),str(info["pin"]["bytes"]),info["pin"]["sha256"],str(a.cpu)]
                log = dispatch(arm,command,90*factor,logcap,512*M+2*logcap); r = arm["owner"]
                try:
                    assert r["exit_code"] == 0 and r["termination"] is None and sorted(p.name for p in work.iterdir()) == ["a.out"]
                    arm["output"] = product(work/"a.out"); arm["valid_elf"] = True
                    arm["statistics"] = statistics(log,info,lengths,arm["output"]["bytes"])
                    arm["strict_full"] = arm["statistics"]["strict_full"]
                except (AssertionError,OSError,ValueError,struct.error) as error:
                    arm["analysis_error"] = dict(type=type(error).__name__,message=str(error))
                arm["status"] = "STRICT_FULL" if arm["strict_full"] else "FAILED_OUTCOME_RETAINED"; persist()
            case["descriptive_byte_equal"] = {}
            case["descriptive_outcomes_equal"] = {}
            for role in ("li2","e9"):
                eligible = all(case["arms"][r]["valid_elf"] for r in ("original",role))
                case["descriptive_byte_equal"][role] = equal(cwd/"original/a.out",cwd/role/"a.out") if eligible else None
                stats = [case["arms"][r].get("statistics") for r in ("original",role)]
                case["descriptive_outcomes_equal"][role] = stats[0]["complete_ordered_outcomes_sha256"] == stats[1]["complete_ordered_outcomes_sha256"] if all(stats) else None
            for role in ROLES:
                if case["arms"][role]["valid_elf"]: assert product(cwd/role/"a.out") == case["arms"][role]["output"]
            case["strict_pass"] = all(case["arms"][r]["strict_full"] for r in ROLES) and all(v is True for v in case["descriptive_byte_equal"].values())
            case["status"] = "STRICT_COMPLETE_BYTE_EQUAL" if case["strict_pass"] else "FAILED_OUTCOME_RETAINED"; active = None; persist()
        unchanged(); record.update(after=ready(a.cpu,a.unit),source_unchanged=True,capacity=charge())
        assert record["capacity"]["charged"] <= 2048*M
        passed = all(c["strict_pass"] for c in record["cases"])
        record["status"] = "STRICT_COMPLETE_BYTE_EQUAL" if passed else "FAILED_OUTCOME_RETAINED"; persist()
        return 0 if passed else 1
    except BaseException as error:
        failure = dict(type=type(error).__name__,message=str(error))
        record.update(status="FAILED_OUTCOME_RETAINED",error=failure)
        if active is not None: active.update(status="FAILED_OUTCOME_RETAINED",strict_pass=False,error=failure)
        try:
            assert checked; unchanged(); record["source_unchanged"] = True
        except BaseException: pass
        persist(); return 1


if __name__ == "__main__":
    if len(sys.argv) == 11 and sys.argv[1] in ("--generate","--backend"):
        child(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4],Path(sys.argv[5]),Path(sys.argv[6]),Path(sys.argv[7]),sys.argv[8],sys.argv[9],int(sys.argv[10]))
    else: raise SystemExit(main())
