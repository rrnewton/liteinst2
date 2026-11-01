# Identical partial results; strict matrix failed

All ten input/action cases produced byte-identical valid ELF outputs and identical ordered patch/refusal outcomes across original, LI2 and E9 backends. All 30 backend invocations exited 0. **Strict N/N failed in 10/10 cases**: each arm patched 295,210 of 296,245 requested input-instruction/action pairs, with the same 1,035 misses. The strict completeness requirement is stronger than stock e9test.sh's output diff; shared omissions remain failures.

| Action | e9tool patched / 46,325 | e9patch patched / 12,924 |
|---|---:|---:|
| Passthru |46,248|12,919|
| Clean call |46,143|12,888|
| Naked-after call |46,203|12,900|
| Six-argument call |46,046|12,865|
| Print |46,116|12,882|

Counts are identical for all three arms. [receipt.json](receipt.json) records exact commands, input/source/tool hashes, bounds, closure and common output/request hashes; [results.csv](results.csv) retains 30 arm outcomes, tactics, CPU/load and operational durations. Those durations are not benchmarks. Hardware: AMD EPYC Zen 5 dev host.

The unchanged LI2 executable is the 2,053-selected-site backend artifact from product 392e4fb. The 296,245 total counts requested input-instruction/action pairs, not executed instrumented sites or whole-program runtime coverage. Generated products were never executed.

The first e9patch/passthru case is retained in [first-case.json](first-case.json) and [first-case.csv](first-case.csv), with its original strict byte gate NOT_RUN_FAILED_ARM and separate closed descriptive analysis. It was not repeated. The remaining nine cases ran once: 9 generators + 27 backends, all normal 0 and zero rescues; the enclosing strict comparison exited 1. Source was unchanged, with an independent live witness and verified parent/scope release. The earlier [1 GiB help comparison](../overlapping-neighbor-corpus/README.md) and E9 SIGSEGV remain failed.

This uses the original stock frontend to generate requests for original/LI2/E9 **backends** across two inputs and five actions. It does not run generated products or repeat the stock test's patched-frontend self-hosting round. Action-major order is e9tool then e9patch: passthru, clean call, naked-after call, six-argument call, print. `remaining-nine` carries the historical first failure without rerunning it, so the complete ten-case strict result cannot become PASS. `all` is a separate fresh ten-case reproduction.

Copy these four exact assets outside the checkout before switching to clean revision `438954e0e1372fdb428b3446d69aca804ccd29ea`: [run.py](run.py), [capture.py](capture.py), [definitions.json](definitions.json), [first-case.json](first-case.json). Keep them siblings; set capture.py mode 0500. Their exact source hashes are in the receipt. The runner's pinned local tools must also match; differing builds are refused.

Stage the exact inputs at the relative paths embedded in run.py. Original e9tool/e9patch are from [PLDI2020](../e9-upstream-corpus-c66ea06/README.md), source `0d5d36e4c4edcac37ca2499694d64302a391136f` with Capstone `e3f106739a6ae78d47772dff31062d644ea21078`; historical build `make -j4 tool release`. The nop input is the retained 13,216-byte product of pinned examples/nop.c and e9compile.sh, not an arbitrary rebuilt helper. Obtain the exact [LI2 candidate](../overlapping-neighbor-corpus/README.md) and [E9 candidate](../full-program-backend-result-v1/README.md). All five sizes/hashes and helper provenance are in receipt.json; the runner authenticates them before making fresh distinct copies. It uses the measured LI2 product 392e4fb, not a new planner run.

Reserve one external HARD CPU for the entire closure. Let SCRIPTS be the absolute copied-asset directory and OUT a fresh absolute path directly under checkout ignored/a3. The following uses the existing public process owner around the required isolated physical scope. It records its own live identity; an independent observer must separately record that identity and verify parent/scope release to claim independent custody. Missing observation must be reported as missing.

```sh
/usr/bin/git switch --detach 438954e0e1372fdb428b3446d69aca804ccd29ea
chmod 0500 "$SCRIPTS/capture.py"
/usr/bin/prlimit --cpu=4800 --as=38654705664 --fsize=536870912 --core=0 -- \
/usr/bin/python3.9 -I -B - "$SCRIPTS" "$OUT" <<'PYRUN'
import hashlib, importlib.util, json, os, sys
from pathlib import Path
if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
 raise SystemExit("Use assertions-enabled Python -I -B")
root=Path.cwd().resolve(); scripts=Path(sys.argv[1]).resolve(); out=Path(sys.argv[2]).resolve()
cpus=sorted(os.sched_getaffinity(0)); assert len(cpus)==1
helper=root/'evaluation/admission/processes.py'
assert hashlib.sha256(helper.read_bytes()).hexdigest()=='0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
meta=out.with_name(out.name+'-owner'); logs=root/'target/evaluation'/(out.name+'-owner')
assert not meta.exists() and not out.exists() and not logs.exists()
meta.mkdir(mode=0o700); logs.mkdir(mode=0o700,parents=True); unit='li2core-functional-repro-'+str(os.getpid())
cmd=['/usr/bin/systemd-run','--user','--scope','--collect','--quiet','--unit='+unit,
 '-p','AllowedCPUs='+str(cpus[0]),'-p','CPUQuota=100%','-p','MemoryMax=1073741824',
 '-p','MemorySwapMax=0','-p','TasksMax=64','--','/usr/bin/python3.9','-I','-B',
 str(scripts/'run.py'),'--cpu',str(cpus[0]),'--unit',unit,'--out',str(out),'--cases','remaining-nine']
(meta/'live.json').write_text(json.dumps(dict(pid=os.getpid(),stat=Path('/proc/self/stat').read_text(),
 cgroup=Path('/proc/self/cgroup').read_text(),cpus=cpus,command=cmd,independent_witness=False)))
spec=importlib.util.spec_from_file_location('owner',helper); owner=importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)
r=owner.run_command(cmd,dict(os.environ,PYTHONDONTWRITEBYTECODE='1'),logs/'outer.log',9000,8388608)
with (meta/'closed.json').open('x') as f:
 json.dump(r,f); f.flush(); os.fsync(f.fileno())
assert r['cleanup_complete'] and r['termination'] is None and r['reaped_descendants']==0
raw=(logs/'outer.log').read_bytes()
assert len(raw)<=8388608 and hashlib.sha256(raw).hexdigest()==r['private_log_sha256']
with (meta/'outer.log').open('xb') as f:
 f.write(raw); f.flush(); os.fsync(f.fileno())
raise SystemExit(r['exit_code'] if r['exit_code'] in (0,1) else 125)
PYRUN
```

Per-input factor is ceil(.text bytes / 52,267): e9patch 1 / e9tool 4. Generator CPU 30f / wall 45f / AS 1 GiB; backend CPU 60f / wall 90f / AS 36 GiB / file 512 MiB; combined log 8 MiB × f. Physical memory remains 1 GiB, swap 0, tasks 64, one CPU. New streamed RPC ceilings are 53,586,944 and 203,238,400 bytes; historical e9patch/passthru retains 8 MiB. Initial capacity admits a 2 GiB run plus 64 MiB metadata under 20 GB; each stage charges fresh outputs and both log copies before dispatch. No automatic retry or deletion.

Every request must match the exact templates, helper reserves, complete .text partition and descending selected heads. Every success/refusal debug event must match that ordered request. A case passes only with all three normal successful N/N arms and exact output byte equality. Partial valid ELFs may have descriptive equality, never strict success. Local closed generation failures leave three unobserved arms; source/capacity/custody failures stop future cases. Published runner/capture/definitions are byte-identical to the executed assets. The illustrative shell/outer recipe is source-authored and unexecuted. Fresh runs require successful capacity admission; retaining an earlier campaign can leave insufficient headroom.

Five metadata-only [parser controls](parser_controls.py) passed once; their exact small receipt is [controls.json](controls.json). They need the pinned historical 2,586,720-byte request and 2,043,698-byte original log at the relative paths named in the script, plus run.py/definitions.json as siblings and a fresh controls output directory. They deliberately reject changed fixture hashes; a new timing-containing log is not the historical fixture. Under one externally reserved CPU:

```sh
/usr/bin/timeout --kill-after=5s 60s /usr/bin/python3.9 -I -B "$SCRIPTS/parser_controls.py" 69c7d87ecf8d249a0a7b325db78f05d770fad993994eba97a40bb8338c0c4f6a
```

[analyze.py](analyze.py) is the exact executed independent CLOSED-data readback, not a fresh-run adapter. It independently matched all nine new request partitions, combined success/refusal sequences and output bytes, carrying the authenticated first case. Replay requires the complete pinned historical root/receipt/first-case analysis and raw fixtures in their recorded path layout. Stage the source directly in a fresh ignored/a3/NAME directory (its parents[3] is the checkout), and run there from the checkout with one reserved CPU:

```sh
/usr/bin/timeout --kill-after=5s 90s /usr/bin/prlimit --cpu=60 --as=268435456 --fsize=1048576 --core=0 -- /usr/bin/python3.9 -I -B ignored/a3/NAME/analyze.py
```

Both metadata runs exited 0 but lacked an independent live witness and process-owner receipt; no subject/product was executed. The historical-fixture checker intentionally rejects newly generated timestamps/receipts. Fresh campaign validation is performed by run.py. The first-case metadata-schema correction and later source-only witness-ordering correction remain distinct from the actual failed backend outcomes.
