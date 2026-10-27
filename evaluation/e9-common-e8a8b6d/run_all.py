#!/usr/bin/env python3
"""Run the frozen full common corpus, then its E9-null continuation, once."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import traceback

FULL = '3ef4a5cd1a4c625c95aacc2d80adba750056ab686472a2508cf27a681dd72e78'
NULL = 'cdc1d33d313a4dc4566dbbc6a37f92bf4acf79231c6d5b6b340d344626534a93'
PROCESS = '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
REVISION = 'e8a8b6d447673aa7b98e00ff18df2eedf5e07d82'


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    with path.open('x') as f: json.dump(value, f, indent=2, sort_keys=True); f.write('\n')


def main():
    if sys.flags.optimize:
        raise SystemExit('assertions required')
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('repo', 'tools', 'raw'): ap.add_argument('--' + name, type=Path, required=True)
    a = ap.parse_args(); repo, raw = a.repo, a.raw; here = Path(__file__).resolve().parent
    assert repo.is_absolute() and repo.resolve(strict=True) == repo
    assert a.tools.is_absolute() and a.tools.resolve(strict=True) == a.tools
    assert raw.is_absolute() and raw.is_relative_to(repo/'ignored') and not raw.exists()
    assert raw.parent.resolve(strict=True) == raw.parent
    raw.mkdir(mode=0o700); state = dict(schema=1, status='FAILED', full='UNRUN', e9_null='UNRUN')
    try:
        recipe, continuation = here/'reproduce.py', here/'continue_null.py'
        process = repo/'evaluation/admission/processes.py'
        pins = {recipe: FULL, continuation: NULL, process: PROCESS, a.tools: sha(a.tools)}
        def stable():
            for path, expected in pins.items(): assert path.resolve(strict=True) == path and sha(path) == expected
        stable(); python = Path(json.loads(a.tools.read_text())['python'])
        assert python.is_absolute() and python.resolve(strict=True) == python
        cpus = sorted(os.sched_getaffinity(0))[:4]; assert len(cpus) == 4
        os.sched_setaffinity(0, cpus); assert set(os.sched_getaffinity(0)) == set(cpus)
        os.chdir(repo); sys.dont_write_bytecode = True
        spec = importlib.util.spec_from_file_location('common_public_processes', process)
        supervisor = importlib.util.module_from_spec(spec); spec.loader.exec_module(supervisor)
        assert supervisor.ROOT == repo
        log_root = repo/'target/evaluation'; log_root.mkdir(parents=True, exist_ok=True)
        logs = Path(tempfile.mkdtemp(prefix='common-public-', dir=log_root))
        for name in ('full', 'null'): (raw/name).mkdir(mode=0o700)
        full_raw = raw/'full'/('full-'+logs.name); null_raw = raw/'null'/('null-'+logs.name)
        env = dict(PATH='/usr/bin:/bin', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1', TMPDIR=str(raw))
        def run(name, argv, wall, child_raw, script_hash):
            state[name] = 'FAILED'
            save(raw/(name+'-command.json'), dict(argv=argv, env=env, affinity=cpus, wall_seconds=wall, script_sha256=script_hash, tools_sha256=pins[a.tools]))
            closed = supervisor.run_command(argv, env, logs/(name+'.log'), wall, 16*1024*1024)
            parent = raw/(name+'-closed.json'); save(parent, closed)
            shutil.copyfile(logs/(name+'.log'), raw/(name+'-parent.log'))
            assert closed['exit_code'] == 0 and closed['termination'] is None and closed['cleanup_complete'] is True and closed['reaped_descendants'] == 0
            stable(); receipt = json.loads((child_raw/'public/receipt.json').read_text())
            assert receipt['status'] == 'PASS' and receipt['revision'] == REVISION and receipt['script_sha256'] == script_hash
            return parent, receipt
        common = ['--repo', str(repo), '--tools', str(a.tools)]
        parent, receipt = run('full', [str(python), '-B', str(recipe), *common, '--raw', str(full_raw)], 7200, full_raw, FULL)
        rows = json.loads((full_raw/'results.json').read_text())
        assert len(rows) == 357 and all(row['status'] == 'PASS' for row in rows)
        assert receipt['observed']['passed_stages'] == 357 and receipt['observed']['failed_stages'] == receipt['observed']['unrun_stages'] == 0
        state['full'] = 'PASS'
        prior = dict(prior_parent_sha256=sha(parent), prior_receipt_sha256=sha(full_raw/'public/receipt.json'), prior_results_sha256=sha(full_raw/'results.json'))
        save(raw/'continuation-pins.json', prior)
        argv = [str(python), '-B', str(continuation), '--reproducer', str(recipe), '--prior-raw', str(full_raw), '--prior-parent', str(parent), *common, '--raw', str(null_raw)]
        for name, value in prior.items(): argv += ['--'+name.replace('_', '-'), value]
        _, receipt = run('e9_null', argv, 4500, null_raw, NULL)
        assert receipt['base_script_sha256'] == FULL and all(receipt[k] == v for k, v in prior.items())
        state['e9_null'] = state['status'] = 'PASS'
        state['public_receipts'] = {name: '$RAW/'+str(path.relative_to(raw))+'/public/receipt.json' for name, path in [('full', full_raw), ('e9_null', null_raw)]}
    except BaseException:
        (raw/'failure.txt').write_text(traceback.format_exc())
    save(raw/'orchestration.json', state); print(json.dumps(state, sort_keys=True))
    return 0 if state['status'] == 'PASS' else 1


if __name__ == '__main__': raise SystemExit(main())
