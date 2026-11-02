# Binding envelope

Evidence revision `32e7ee137bb38bebd1bc15e998126d4b9ec3e521`, tree `0567363546ac197f6dde3a8285e899826e3df980`, on an AMD EPYC Zen 5 dev host. BindingEnvelope retains the same Arc and records the pure immutable profile predicate, including false. Process checks and failed-flag Acquire reads remain fresh and ordered; model, journal, geometry, receipt and independent snapshot comparisons are unchanged.

- Focused precommit checks passed formatting, profiler library tests (590 passed, 37 ignored), and profiler Clippy. This one-CPU receipt records three input hashes, not a Git revision, workspace check, complete source freeze or postflight inventory. Their equivalence to the committed source is reviewed separately.
- Default native correctness passed all four cases: 4,136 calls, 4,072 observed, 4,056 sampled, 64 bypass, 1,034 batches, 16 unsampled, 24 history entries and eight epochs. All 29 owners closed cleanly.
- Strict 20,000-step qualification FAILED on the first enabled cohort. Eleven cohorts remain UNOBSERVED; no pair completed. The literal plan has one FAILED and 31 UNOBSERVED rows. Preparation passed 240 calibration controls with the original one ignore; that does not qualify the failed native run.
- Separate 80,000-step qualification passed 12 cohorts, 288 pairs and 576 children: 139,872 exact comparisons, zero mismatches, 16 coverage rows and 32 controller handshakes. All 54 owners closed cleanly. Of 288 candidate endpoints, 136 are at most 20,000 steps and 152 exceed it.
- The full correctness gate passed all five commands with nine clean owners: 4,565 top-level passes plus 11 nested children = 4,576 raw passes, 43 ignored; profiler 590/37, default calibrations 237/1, serial launch 1,039. The complete old contextual roster and ignore reasons remain.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.

| Candidate cohort | Observed step range | Matched change versus v23 |
|---|---:|---:|
| Enabled | 38,859–40,207 | −780 to −522 |
| Bypass | 14,020–15,395 | −582 to −279 |
| Scheduled | 15,349–40,240 | −710 to −315 |

All 288 matched candidate deltas are negative, with no unmatched pair. Original-side steps changed too: 105 increased (up to +71), 105 were equal and 78 decreased (down to −56). Both sides and every increase remain in the literal CSVs and matched summary. The prior 3581 ELF lacks the later PC recorder; these are arithmetic observations across different binaries, not isolated BindingEnvelope effects or timing measurements.

The full runner predeclared 4,563 top-level/4,574 raw passes. That expectation undercounted two registrations: 37 distinct new names produce 39 added executions because both new PC controls run in the calibration and ordinary-interval binaries. Those targets changed 235→237 and 520→522; profiler changed 555→590. The original expectation and actual mismatch are retained; no validation run was retried to fix the census.

The first metadata export refused its 15 KiB receipt-size aim. The complete receipt is 32,439 bytes; a 32 KiB export limit permits it without filtering outcomes. That export-only failure remains recorded, and no scientific run was repeated.

Admission used two eligible samples 60.060403 seconds apart; the final sample preceded the recorded full-run start by 5.241484 seconds. This is recorded timing, not an independent allocator witness or freshness guarantee. Workspace and serial commands took 798.6393/900 and 125.1341/180 seconds operationally. CPU family/model/stepping/microcode, affinity/load, tool/artifact pins, commands, owner results and capacities are in receipt.json; independent reviews and root attestations are labelled separately.

The earlier qualification build at cf22b6f13d55041ef64bb267c658723d24c120a3 differs from 32e only in two recipe files and the README correction. Current campaign artifacts still have their own exact 32e source/request joins; the earlier build is not relabelled. All 33 current CSVs (69,720 bytes) are copied literally. The [current-RET receipt](../current-ret/receipt.json) retains earlier failures, including 6a Clippy, and the [step-attribution receipt](../step-attribution/receipt.json) retains the diagnostic failure. No old raw captures are copied.

Reproduce from a clean checkout of this exact revision, using explicit absolute ROOT, TOOLCHAIN, USER_HOME and CARGO_HOME paths, fresh outputs and one externally reserved CPU. Run each [native](../reproduce.py), [strict](../state.py) and [80k](../state_wide_80k.py) recipe once, sequentially; the state scripts must execute from ROOT. The following is executable launch syntax, not the exact privately executed wrapper. It retains failures before proceeding to the separately named profile.

Before and after each recipe, externally measure allocated/apparent slot, ignored and target totals with the original single-traversal count-links inventory (30 CPU seconds, 180 wall seconds, 256 MiB address space, 64 KiB output). Authenticate cleanup before reading captures. The block below does not perform those scans or reserve CPUs. Preserve ceilings 19,994,091,520 allocated and 19,061,190,371 apparent bytes and the cumulative 2,214,592,512-byte reserve; no cache cleaning, re-reservation or retries. Focused checks used one CPU; the separate full gate used 12 CPUs and its admission rule.

```sh
export ROOT=/absolute/checkout TOOLCHAIN=/absolute/toolchain USER_HOME=/absolute/user-home CARGO_HOME=/absolute/cargo-home
python3.9 -I -B - <<'PY'
import hashlib, importlib.util, json, os
from pathlib import Path
root=Path(os.environ['ROOT']).resolve(strict=True)
assert len(os.sched_getaffinity(0))==1
owner_path=root/'evaluation/admission/processes.py'
assert hashlib.sha256(owner_path.read_bytes()).hexdigest()=='0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
spec=importlib.util.spec_from_file_location('owner',owner_path)
owner=importlib.util.module_from_spec(spec);spec.loader.exec_module(owner)
out=root/'ignored/binding-envelope-reproduction';out.mkdir(parents=False,exist_ok=False)
logs=root/'target/evaluation/binding-envelope-reproduction';logs.mkdir(parents=True,exist_ok=False)
env=dict(HOME=os.environ['USER_HOME'],PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',PYTHONDONTWRITEBYTECODE='1')
for name,script,wall in [('native','reproduce.py',1800),('strict','state.py',11000),('wide','state_wide_80k.py',11000)]:
    argv=['/usr/bin/python3.9','-I','-B',str(root/'evaluation/early-entry-module'/script),'--revision','32e7ee137bb38bebd1bc15e998126d4b9ec3e521','--root',str(root)]
    for flag,key in [('toolchain','TOOLCHAIN'),('user-home','USER_HOME'),('cargo-home','CARGO_HOME')]:argv+=['--'+flag,os.environ[key]]
    argv+=['--output',str(out/('binding-envelope-'+name))]
    result=owner.run_command(argv,env,logs/(name+'.log'),wall,8*1048576)
    with (out/(name+'-owner.json')).open('x') as f:
        json.dump(result,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
    assert result['cleanup_complete'] is True
    data=(logs/(name+'.log')).read_bytes()
    assert len(data)<=8*1048576 and hashlib.sha256(data).hexdigest()==result['private_log_sha256']
    with (out/(name+'.log')).open('xb') as f:f.write(data);f.flush();os.fsync(f.fileno())
    assert result['termination'] is None and result['reaped_descendants']==0
    print(name,result['exit_code'])
PY
```

A nonzero recipe exit remains failure; shell success of this outer block is not qualification success. Read each CLOSED result and exact comparator. Limits stay 20,000 strict / 80,000 separate steps, 15 seconds per pair, two seconds cleanup, and all 640 witness words. Build bounds remain one job, 120 CPU/180 wall seconds, 128 MiB file output and 205-second ownership; the file limit is not an address-space limit. Full commands and the serial RUST_TEST_THREADS=1 override are recorded separately. This publication makes no performance or strict-fit claim.
