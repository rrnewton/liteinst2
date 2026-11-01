#!/usr/bin/env python3
"""One fixed six-chain STOCK action batch; ordered runtime diagnostics are unobserved."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import stat
import struct
import sys

if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit("Use assertions-enabled Python -I -B")
ROOT, SELF = Path.cwd().resolve(), Path(__file__).resolve()
REV = "10a778d6415e51c66dfdc122d1e019e5c8c94c3c"
MANIFEST = "43ce9ab04259b8bc551cd2ec2c093206710b60258b3e9e73ac351ddb7ea77733"
HELPER = "69c7d87ecf8d249a0a7b325db78f05d770fad993994eba97a40bb8338c0c4f6a"
M = 1024**2
CLOSER = "937d4377a640d6ea36b18101ff51e6e74e5d2f8a5656e495969353072131ebc5"


def load_source(path, digest, name):
    s = path.lstat(); assert stat.S_ISREG(s.st_mode) and s.st_size <= M
    data = path.read_bytes(); after = path.lstat()
    assert (s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns) == (after.st_dev,after.st_ino,after.st_mode,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
    assert hashlib.sha256(data).hexdigest() == digest
    spec = importlib.util.spec_from_file_location(name,path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    assert path.read_bytes() == data
    return module


h = load_source(ROOT/"evaluation/functional-corpus/run.py",HELPER,"first_generation_helpers")
# Only the reused readiness check's exact revision changes; helper bodies stay literal.
h.REV = REV
md = load_source(SELF.with_name("matrix_disk.py"),"d0202e52f4aaccc1c700e3043c497b0e7a140d8bc1f517445ed1d2a3a7882ac1","stock_matrix_disk")
manifest_path = SELF.with_name("inputs.json")
assert h.pin(manifest_path,M)["sha256"] == MANIFEST
INPUT = json.loads(manifest_path.read_text())
assert INPUT["revision"] == REV and INPUT["roles"] == list(h.ROLES)
# The inherited manifest remains literal; the separate stock profile selects
# current products through the complete authenticated fresh producer receipt.
join = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
join.add_argument("--first-generation", type=Path, required=True)
join.add_argument("--closure", type=Path, required=True)
join.add_argument("--closure-sha", required=True)
join.add_argument("--action-index", type=int, choices=(1,2,3,4), required=True)
join.add_argument("--matrix",type=Path,required=True)
join.add_argument("--matrix-sha",required=True)
fresh, remainder = join.parse_known_args()
sys.argv = [sys.argv[0], *remainder]
FIRST, CLOSURE = fresh.first_generation.absolute(), fresh.closure.absolute()
assert FIRST == FIRST.resolve() and FIRST.parent == ROOT/"ignored/a3" and FIRST.is_dir()
assert CLOSURE == CLOSURE.resolve() and CLOSURE.parent == ROOT/"ignored/a3"
closure_pin = h.pin(CLOSURE, M)
assert closure_pin["sha256"] == fresh.closure_sha
CLOSED = json.loads(CLOSURE.read_text()); assert h.pin(CLOSURE, M) == closure_pin
assert CLOSED["schema"] == 1 and CLOSED["status"] == "FRESH_FIRST_GENERATION_CLOSED"
assert CLOSED["producer_revision"] == REV and CLOSED["first_generation"] == str(FIRST)
assert CLOSED["source_unchanged"] is True and CLOSED["parent_and_worker_and_scopes_gone"] is True
assert CLOSED["cases"] == 10 and CLOSED["dispatches"] == 40 and CLOSED["native_dispatches"] == 0
assert CLOSED["strict_status"] == "FAILED_OUTCOME_RETAINED"
assert CLOSED["closure_script"]["sha256"] == CLOSER
closers = [Path(p) for p,q in CLOSED["frozen"].items()
           if Path(p).name == "close_first_generation.py" and q == CLOSED["closure_script"]]
assert len(closers) == 1
CLOSER_PATH = closers[0]
assert CLOSER_PATH == CLOSER_PATH.resolve() and h.pin(CLOSER_PATH) == CLOSED["closure_script"]
INDEX, ACTION = fresh.action_index, h.ACTIONS[fresh.action_index]
MATRIX = fresh.matrix.absolute(); matrix_pin = h.pin(MATRIX,M)
assert matrix_pin["sha256"] == fresh.matrix_sha
matrix = json.loads(MATRIX.read_text()); assert h.pin(MATRIX,M) == matrix_pin
paths = md.layout(ROOT,MATRIX,matrix); matrix_row = matrix["actions"][INDEX-1]
assert matrix["revision"] == REV and matrix["first_generation"] == str(FIRST.relative_to(ROOT))
assert matrix["closure"] == str(CLOSURE.relative_to(ROOT)) and matrix["closure_sha256"] == fresh.closure_sha
INITIAL = MATRIX.with_name("initial.json"); initial_pin = h.pin(INITIAL,M)
initial = json.loads(INITIAL.read_text()); assert h.pin(INITIAL,M) == initial_pin
assert initial["absent"] == [str(p) for p in paths["roots"]]
assert initial["matrix_sha256"] == matrix_pin["sha256"]
CANONICAL = ROOT/"evaluation/functional-corpus/receipt.json"
canonical_pin = h.pin(CANONICAL, M)
assert canonical_pin["sha256"] == "1e9e90d8fe9493c2dc071ca8126e5d2c4c616b0f83f04725f30b086705e3f184"
CANON = json.loads(CANONICAL.read_text()); assert h.pin(CANONICAL, M) == canonical_pin
producer_pin = h.pin(FIRST/"receipt.json", M)
assert producer_pin == CLOSED["receipt"]
PRODUCED = json.loads((FIRST/"receipt.json").read_text())
assert h.pin(FIRST/"receipt.json", M) == producer_pin
assert PRODUCED["revision"] == REV and PRODUCED["source_unchanged"] is True
assert PRODUCED["status"] == "FAILED_OUTCOME_RETAINED" and len(PRODUCED["dispatch_attempts"]) == 40
assert [c["id"] for c in PRODUCED["cases"]] == [str(i)+"-"+n for i in range(5) for n in ("e9tool","e9patch")]
SELECTED = {c["source"]:c for c in PRODUCED["cases"] if c["id"].startswith(str(INDEX)+"-")}
assert set(SELECTED) == {"e9tool","e9patch"}
EXPECTED = {c["source"]:c for c in CANON["cases"] if c["case"].startswith(str(INDEX)+"-")}
assert set(EXPECTED) == set(SELECTED)
INPUT["products"] = {r:{} for r in h.ROLES}
# The closer authenticated all ten cases/forty owners and complete request/event
# populations. Only current product bytes and preserved metadata are needed here;
# consumed first-generation logs and requests need not remain expanded.
for name, selected in SELECTED.items():
    expected = EXPECTED[name]
    assert selected["action"] == expected["action"] == ACTION and selected["execution"] == "CURRENT"
    assert selected["status"] == "FAILED_OUTCOME_RETAINED" and selected["strict_pass"] is False
    assert "error" not in selected and "generation_error" not in selected
    assert all(selected["request"]["pin"][k] == expected["rpc"][k] for k in ("bytes","sha256"))
    assert selected["request"]["requested"] == expected["requested"]
    assert selected["request"]["messages"] == expected["messages"]
    assert set(selected["arms"]) == set(h.ROLES)
    for role, arm in selected["arms"].items():
        assert arm["status"] == "FAILED_OUTCOME_RETAINED" and arm["valid_elf"] is True
        assert arm["strict_full"] is False and arm["statistics"]["strict_full"] is False
        assert "analysis_error" not in arm
        q = arm["owner"]
        assert q["exit_code"] == 0 and q["termination"] is None and q["cleanup_complete"] and q["reaped_descendants"] == 0
        assert all(arm["statistics"][k] == expected[k] for k in ("requested","successful","failed","complete_ordered_outcomes_sha256"))
        assert all(arm["output"][k] == expected["output"][k] for k in ("bytes","sha256"))
        INPUT["products"][role][name] = dict(path=str((FIRST/(str(INDEX)+"-"+name)/role/"a.out").relative_to(ROOT)),
            bytes=arm["output"]["bytes"], sha256=arm["output"]["sha256"])
INPUT.pop("requests"); INPUT.pop("expected_outcomes")

META = FIRST.with_name(FIRST.name+"-owner")
assert CLOSED["owner_directory"] == str(META)
INPUT["authorities"] = {str(CLOSURE.relative_to(ROOT)):closure_pin,
    str((FIRST/"receipt.json").relative_to(ROOT)):CLOSED["receipt"],
    str((FIRST/"first-generation-wrapper-closed.json").relative_to(ROOT)):CLOSED["wrapper_closed"],
    str((META/"live.json").relative_to(ROOT)):CLOSED["owner_live"],
    str((META/"closed.json").relative_to(ROOT)):CLOSED["owner_closed"]}
INPUT["authorities"][str(CANONICAL.relative_to(ROOT))] = canonical_pin
FRESH_ARGS = ["--first-generation", str(FIRST), "--closure", str(CLOSURE), "--closure-sha", fresh.closure_sha, "--action-index", str(INDEX), "--matrix",str(MATRIX),"--matrix-sha",fresh.matrix_sha]


def native(role, source, copies, cwd, cpu):
    assert role in h.ROLES and source in ("e9tool","e9patch") and os.sched_getaffinity(0) == {cpu}
    factor = 4 if source == "e9tool" else 1
    for key,value in ((resource.RLIMIT_CPU,60*factor),(resource.RLIMIT_AS,36*1024*M),
                      (resource.RLIMIT_FSIZE,512*M),(resource.RLIMIT_CORE,0)):
        resource.setrlimit(key,(value,value))
    frontend = copies/(role+"-e9tool"); backend = copies/(role+"-e9patch")
    fp,bp = INPUT["products"][role]["e9tool"],INPUT["products"][role]["e9patch"]
    f = h.owned(frontend,(fp["bytes"],fp["sha256"]))
    b = h.owned(backend,(bp["bytes"],bp["sha256"]))
    original = h.owned(copies/source,h.INPUTS[source][1:])
    assert all(os.fstat(fd).st_mode&0o777 == 0o500 for fd in (f,b,original))
    os.dup2(original,3,inheritable=True); os.close(original)
    os.dup2(b,4,inheritable=True); os.close(b)
    os.chdir(cwd); os.umask(0o077)
    argv = ["e9tool","--backend","/proc/self/fd/4","/proc/self/fd/3",
            "--action="+ACTION,"-o","a.out","-c","6","-s"]
    null = os.open("/dev/null", os.O_WRONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
    q = os.fstat(null)
    assert stat.S_ISCHR(q.st_mode) and (os.major(q.st_rdev),os.minor(q.st_rdev)) == (1,3)
    os.dup2(null,1,inheritable=True); os.dup2(null,2,inheritable=True); os.close(null)
    os.execve(f,argv,h.ENV)
    raise RuntimeError("execve returned")


def main():
    for key,value in ((resource.RLIMIT_CPU,2400),(resource.RLIMIT_AS,36*1024*M),
                      (resource.RLIMIT_FSIZE,512*M),(resource.RLIMIT_CORE,0)):
        resource.setrlimit(key,(value,value))
    parser = argparse.ArgumentParser(description=__doc__,allow_abbrev=False)
    parser.add_argument("--cpu",type=int,required=True); parser.add_argument("--unit",required=True)
    parser.add_argument("--out",type=Path,required=True); a = parser.parse_args()
    out = a.out.absolute(); logs = ROOT/"target/evaluation"/out.name
    assert out == out.resolve() and out.parent == ROOT/"ignored/a3" and not out.exists() and not logs.exists()
    assert out == ROOT/matrix_row["run"] and logs == ROOT/matrix_row["logs"]
    out.mkdir(mode=0o700); logs.mkdir(mode=0o700,parents=True)
    (out/"inputs").mkdir(mode=0o700); (out/"logs").mkdir(mode=0o700)
    root_ids = md.identities(paths)
    rows = [dict(role=r,source=s,status="UNOBSERVED",attempts=0,byte_equal=None,outcomes_equal=None,
                 ordered_outcomes_status="UNOBSERVED_STOCK_PROFILE",
                 factor=4 if s=="e9tool" else 1) for r in h.ROLES for s in ("e9tool","e9patch")]
    record = dict(revision=REV,status="PREFLIGHT",profile="stock-second-generation-action-v1",action_index=INDEX,action=ACTION,
                  ordered_outcomes_status="UNOBSERVED_STOCK_PROFILE",native_stdout="/dev/null",native_stderr="/dev/null",
                  first_generation_expected=EXPECTED,chains=rows,dispatch_attempts=[],source_unchanged=False,
                  first_generation_strict_status="FAILED_OUTCOME_RETAINED",strict_full_instrumentation="FAILED",
                  all_selected_sites_executed=False,qualification_complete=False,performance_qualified=False,
                  native_argv=["e9tool","--backend","/proc/self/fd/4","/proc/self/fd/3","--action="+ACTION,"-o","a.out","-c","6","-s"],
                  environment=h.ENV,limits=dict(as_bytes=36*1024*M,file_bytes=512*M,per_process_cpu_factor=60,
                  chain_wall_factor=135,log_factor=8*M,run_bytes=2048*M,outer_metadata_bytes=64*M,
                  outer_wall_seconds=2400,outer_cpu_seconds=2400,outer_log_bytes=8*M),
                  fresh_authorities=INPUT["authorities"], reproduction="SOURCE_AUTHORED_FRESH_DATA_PATH", producer_revision=REV, matrix=matrix_pin, matrix_profile=md.PROFILE)
    receipt = out/"receipt.json"; frozen = {}; active = None; checked = False
    def persist(): h.save(receipt,record)
    def freeze(path,expected=None):
        q = h.pin(path)
        if expected is not None: assert (q["bytes"],q["sha256"]) == (expected["bytes"],expected["sha256"])
        frozen[str(path)] = q; return q
    def unchanged():
        assert all(h.pin(Path(p)) == q for p,q in frozen.items())
        assert all(str(Path(p).resolve()) == q["resolved"] for p,q in INPUT["runtime_dependencies"].items())
    def charge():
        return md.charge(paths["data"])
    def budget(allowance):
        current = md.measure(paths,root_ids)
        md.local_admit(current,allowance,md.capture_remaining(ROOT,matrix_row))
        q = current["data"]; assert q["charged"]+allowance+M <= 2048*M, "No next dispatch: run envelope exhausted"
        assert record["matrix_slot_admission"]
        record["matrix_capacity"] = current
        return q
    try:
        persist(); freeze(SELF); freeze(manifest_path)
        freeze(SELF.with_name("matrix_disk.py")); freeze(MATRIX); freeze(INITIAL)
        freeze(CLOSER_PATH, CLOSED["closure_script"])
        for path,p in {**INPUT["sources"],**INPUT["authorities"]}.items(): freeze(ROOT/path,p)
        for path,p in INPUT["runtime_dependencies"].items():
            assert str(Path(path).resolve()) == p["resolved"]; freeze(Path(p["resolved"]),p)
        for path,p in h.TOOLS.items(): freeze(ROOT/path,dict(bytes=p[0],sha256=p[1]))
        for source in ("e9tool","e9patch"):
            path,n,d = h.INPUTS[source]; freeze(ROOT/path,dict(bytes=n,sha256=d))
        if INDEX in (1,2,3):
            path,n,d = h.INPUTS["nop"]; freeze(ROOT/path,dict(bytes=n,sha256=d))
        for pair in INPUT["products"].values():
            for q in pair.values(): freeze(ROOT/q["path"],q)
        before = h.ready(a.cpu,a.unit); record["before"] = before; checked = True
        q = CLOSED["outer"]
        assert q["exit_code"] == 1 and q["termination"] is None and q["cleanup_complete"] and q["reaped_descendants"] == 0
        assert q["child_discovery_strategy"] == "pidfd_authenticated_proc_candidates"
        for path, expected in INPUT["authorities"].items():
            assert h.pin(ROOT/path) == expected
        # Recheck actual metadata, then freeze the present identities of exact
        # content-matching products. Restored files need not have old inodes.
        assert h.pin(FIRST/"receipt.json", M) == producer_pin
        owner = load_source(ROOT/"evaluation/admission/processes.py",h.TOOLS["evaluation/admission/processes.py"][1],"selfhost_owner")
        capacity = []; record["capacity_queries"] = capacity
        def scan(label, first=False):
            before = md.measure(paths,root_ids); slot = {}
            for apparent in (False,True):
                argv = ["/usr/bin/prlimit","--cpu=30","--as=268435456","--fsize=65536","--core=0","--","/usr/bin/du","--block-size=1","--count-links","-s"]
                if apparent: argv.append("--apparent-size")
                argv += [str(ROOT),str(ROOT/"ignored"),str(ROOT/"target")]
                log = logs/("capacity-"+label+"-"+str(int(apparent))+".log"); q = dict(command=argv,status="DISPATCHED")
                capacity.append(q); persist(); q["owner"] = owner.run_command(argv,h.ENV,log,60,65536); persist()
                r = q["owner"]; assert r["cleanup_complete"] and r["reaped_descendants"] == 0 and r["exit_code"] == 0 and r["termination"] is None
                lp = h.pin(log,65536); assert lp["sha256"] == r["private_log_sha256"]
                values = [line.split("\t",1) for line in log.read_text().splitlines()]
                assert [p for n,p in values] == [str(ROOT),str(ROOT/"ignored"),str(ROOT/"target")]
                q.update(log=lp,values={p:int(n) for n,p in values},status="CLOSED"); unchanged(); persist()
                slot["apparent" if apparent else "allocated"] = q["values"][str(ROOT)]
            after = md.measure(paths,root_ids)
            admission = md.admit(slot,before,after,metadata_allowance=md.capture_remaining(ROOT,matrix_row),initial=first)
            record["baseline_slot"] = max(slot.values())
            record["matrix_slot_admission"] = admission
            record["matrix_capacity"] = after
            return admission
        record["matrix_initial_admission"] = scan("start",first=INDEX==1)
        copies = out/"inputs"; items = {}
        for source in ("e9tool","e9patch"):
            path,n,d = h.INPUTS[source]; items[source] = dict(path=path,bytes=n,sha256=d)
        for role,pair in INPUT["products"].items():
            for source,q in pair.items(): items[role+"-"+source] = q
        if INDEX in (1,2,3):
            path,n,d = h.INPUTS["nop"]; items["nop"] = dict(path=path,bytes=n,sha256=d)
        copy_reserve = sum(((q["bytes"]+4095)//4096)*4096 for q in items.values())+M
        record["copy_admission"] = budget(copy_reserve)
        for name,q in items.items():
            path = copies/name
            with (ROOT/q["path"]).open("rb") as src,path.open("xb") as dst:
                while True:
                    block = src.read(M)
                    if not block: break
                    dst.write(block)
                dst.flush(); os.fsync(dst.fileno())
            path.chmod(0o500); cp = freeze(path,q)
            assert path.stat().st_nlink == 1 and cp["stat"][:2] != frozen[str(ROOT/q["path"])]["stat"][:2]
        assert len({tuple(frozen[str(copies/n)]["stat"][:2]) for n in items}) == (9 if INDEX in (1,2,3) else 8)
        record["inputs"] = {p:q for p,q in frozen.items()}; persist()
        for row in rows:
            active = None; role,source,f = row["role"],row["source"],row["factor"]
            cwd = out/(role+"-"+source); cwd.mkdir(mode=0o700)
            cap = 8*M*f; unchanged()
            if INDEX in (1,2,3):
                record["capacity"] = budget(items["nop"]["bytes"]+8192)
                with (copies/"nop").open("rb") as src,(cwd/"nop").open("xb") as dst:
                    dst.write(src.read(items["nop"]["bytes"]+1)); dst.flush(); os.fsync(dst.fileno())
                (cwd/"nop").chmod(0o400); np = freeze(cwd/"nop",items["nop"])
                assert (cwd/"nop").stat().st_nlink == 1 and np["stat"][:2] != frozen[str(copies/"nop")]["stat"][:2]
                row["nop"] = np; persist()
            row.update(before=h.ready(a.cpu,a.unit),admission=budget(512*M+2*cap),status="DISPATCHED",attempts=1,
                       cpu_seconds_per_process=60*f,wall_seconds=135*f,log_bytes=cap)
            argv = ["/usr/bin/python3.9","-I","-B",str(SELF),*FRESH_ARGS,"--exec",role,source,str(copies),str(cwd),str(a.cpu)]
            row["command"] = argv; record["dispatch_attempts"].append(role+"-"+source); active = row; persist()
            log = logs/(role+"-"+source+".log")
            row["owner"] = owner.run_command(argv,h.ENV,log,135*f,cap); persist()
            r = row["owner"]; assert r["cleanup_complete"], "No capture reads before cleanup"
            lp = h.pin(log,cap); assert lp["sha256"] == r["private_log_sha256"]
            retained = out/"logs"/log.name
            with log.open("rb") as src,retained.open("xb") as dst:
                while True:
                    block = src.read(M)
                    if not block: break
                    dst.write(block)
                dst.flush(); os.fsync(dst.fileno())
            assert h.pin(retained,cap)["sha256"] == lp["sha256"]
            row.update(log=lp,retained_log=str(retained),after=h.ready(a.cpu,a.unit),status="CLOSED"); unchanged(); persist()
            assert r["reaped_descendants"] == 0, "Lifecycle failure: stop subsequent chains"
            try:
                assert r["exit_code"] == 0 and r["termination"] is None
                assert sorted(p.name for p in cwd.iterdir()) == (["a.out","nop"] if INDEX in (1,2,3) else ["a.out"])
                row["output"] = h.product(cwd/"a.out")
                assert stat.S_IMODE(row["output"]["stat"][2]) == 0o777 and (cwd/"a.out").stat().st_nlink == 1
                row["byte_equal"] = h.equal(cwd/"a.out",copies/(role+"-"+source))
                # Literal stock e9test.sh observes no native diagnostic stream.
                # First-generation failures are retained; no second-generation
                # statistics or ordered-outcome equality is asserted.
                assert row["outcomes_equal"] is None and row["ordered_outcomes_status"] == "UNOBSERVED_STOCK_PROFILE"
                assert h.product(cwd/"a.out") == row["output"]
                row["status"] = "STOCK_SECOND_GENERATION_BYTE_EQUAL" if row["byte_equal"] else "FAILED_OUTCOME_RETAINED"
            except (AssertionError,OSError,ValueError,KeyError,TypeError,struct.error) as error:
                row.update(status="FAILED_OUTCOME_RETAINED",error=dict(type=type(error).__name__,message=str(error)))
            active = None; unchanged(); record["capacity"] = budget(0); persist()
        record["matrix_final_admission"] = scan("closed")
        unchanged(); record.update(after=h.ready(a.cpu,a.unit),source_unchanged=True,capacity=charge())
        assert record["capacity"]["charged"] <= 2048*M
        success = all(row["status"] == "STOCK_SECOND_GENERATION_BYTE_EQUAL" for row in rows)
        record["status"] = "STOCK_SECOND_GENERATION_BYTE_EQUAL" if success else "FAILED_OUTCOME_RETAINED"
        record["byte_equality_gate"] = "PASS" if success else "FAILED"
        persist(); return 0 if success else 1
    except BaseException as error:
        failure = dict(type=type(error).__name__,message=str(error)); record.update(status="FAILED_OUTCOME_RETAINED",byte_equality_gate="FAILED",error=failure)
        if active is not None: active.update(status="FAILED_OUTCOME_RETAINED",error=failure)
        try:
            assert checked; unchanged(); record["source_unchanged"] = True
        except BaseException: pass
        persist(); return 1


if __name__ == "__main__":
    if len(sys.argv) == 7 and sys.argv[1] == "--exec":
        native(sys.argv[2],sys.argv[3],Path(sys.argv[4]),Path(sys.argv[5]),int(sys.argv[6]))
    else: raise SystemExit(main())
