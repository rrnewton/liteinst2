#!/usr/bin/env python3
"""Bounded local checks. Raw results live under ignored/a2/."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'ignored/a2'
OUT.mkdir(parents=True, exist_ok=True)
RUN = OUT / datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
RUN.mkdir()
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
env = dict(os.environ, CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4',
           CARGO_TARGET_DIR=str(ROOT / 'target'), RUST_TEST_THREADS='4',
           CARGO_NET_OFFLINE='true', TMPDIR=str(OUT))
commands = [
    ('fmt', ['cargo', 'fmt', '--check']),
    ('clippy', ['cargo', 'clippy', '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings']),
    ('test', ['cargo', 'test', '--workspace']),
    ('check', ['cargo', 'check', '--workspace', '--all-features', '--all-targets']),
    ('search-unit', ['cargo', 'test', '--lib']),
    ('search-contract', ['cargo', 'test', '--test', 'search_evidence', '--test', 'search_eviction_evidence', '--', '--test-threads=1']),
    ('contract', ['cargo', 'test', '--test', 'quiescent_contract', '--', '--test-threads=1', '--nocapture']),
    ('pun-contract', ['cargo', 'test', '--test', 'generalized_pun_contract', '--', '--test-threads=1', '--nocapture']),
    ('prefix-contract', ['cargo', 'test', '--test', 'prefixed_pun_contract', '--', '--test-threads=1', '--nocapture']),
    ('prefix-oracle', ['cargo', 'test', '--test', 'prefixed_pun_oracle', '--', '--test-threads=1', '--nocapture']),
    ('successor-contract', ['cargo', 'test', '--test', 'successor_eviction_contract', '--', '--test-threads=1', '--nocapture']),
    ('successor-oracle', ['cargo', 'test', '--test', 'successor_eviction_oracle', '--', '--test-threads=1', '--nocapture']),
    ('neighbor-contract', ['cargo', 'test', '--test', 'neighbor_eviction_contract', '--', '--test-threads=1', '--nocapture']),
    ('neighbor-oracle', ['cargo', 'test', '--test', 'neighbor_eviction_oracle', '--', '--test-threads=4', '--nocapture']),
    ('tactic-engine', ['cargo', 'test', '--test', 'tactic_engine', '--', '--test-threads=1', '--nocapture']),
    ('controls-contract', ['cargo', 'test', '--test', 'controlled_coalescing_contract', '--', '--test-threads=1', '--nocapture']),
    ('controls-oracle', ['cargo', 'test', '--test', 'controlled_oracle', '--', '--test-threads=1', '--nocapture']),
    ('bundle-contract', ['cargo', 'test', '--test', 'bundle_contract', '--', '--test-threads=1', '--nocapture']),
    ('a2-oracle', ['cargo', 'test', '--test', 'a2_oracle', '--', '--test-threads=1', '--nocapture']),
    ('oracle', ['cargo', 'test', '--test', 'quiescent_oracle', '--', '--test-threads=1', '--nocapture']),
]
records = []
head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
diff = subprocess.check_output(['git', 'diff', '--binary', 'HEAD'], cwd=ROOT)
sources = ['Cargo.toml', 'src/lib.rs', 'src/grouping.rs', 'src/eviction.rs',
           'src/bundle.rs', 'src/composition.rs', 'tests/bundle_contract.rs',
           'tests/a2_oracle.rs', 'src/contracts.rs', 'src/quiescent.rs', 'src/entry_router.rs',
           'src/trampoline.rs', 'tests/quiescent_contract.rs',
           'tests/quiescent_oracle.rs', 'tests/support/quiescent_oracle.rs',
           'tests/generalized_pun_contract.rs', 'tests/prefixed_pun_contract.rs',
           'tests/prefixed_pun_oracle.rs', 'tests/successor_eviction_contract.rs',
           'tests/successor_eviction_oracle.rs', 'src/neighbor.rs', 'src/engine.rs',
           'tests/neighbor_eviction_contract.rs', 'tests/neighbor_eviction_oracle.rs',
           'tests/tactic_engine.rs', 'evidence/a2/run-checks.py', 'src/controls.rs',
           'tests/controlled_coalescing_contract.rs', 'tests/controlled_oracle.rs',
           'src/search.rs', 'tests/search_evidence.rs', 'tests/search_eviction_evidence.rs']
source_sha256 = {path: hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
                 for path in sources}
for name, argv in commands:
    # The new controls target adds a separately bounded 170-second wrapper to
    # a measured 139-second workspace. Declare this aggregate expansion before
    # controls qualification; every focused command retains its 180-second cap.
    timeout_seconds = 360 if name == 'test' else 180
    start = time.monotonic()
    utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
    log = RUN / (name + '.log')
    with log.open('wb') as output:
        process = subprocess.Popen(argv, cwd=ROOT, env=env, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            code = 'timeout'
    record = dict(name=name, argv=argv, timeout_seconds=timeout_seconds, start_utc=utc, exit=code,
                  seconds=time.monotonic()-start, log=str(log.relative_to(ROOT)),
                  sha256=hashlib.sha256(log.read_bytes()).hexdigest())
    records.append(record)
    print(json.dumps(record), flush=True)
    if code != 0:
        print(log.read_text()[-16000:], flush=True)
        break
summary = dict(head=head, tracked_diff_sha256=hashlib.sha256(diff).hexdigest(),
               run_directory=str(RUN.relative_to(ROOT)),
               source_sha256=source_sha256, records=records)
(RUN/'commands.json').write_text(json.dumps(summary, indent=2)+'\n')
(OUT/'commands.json').write_text(json.dumps(summary, indent=2)+'\n')
assert len(records) == len(commands) and all(r['exit'] == 0 for r in records), 'validation failed'
