#!/usr/bin/env python3
"""Five fixed whole Exact37 qualifications; completion is not all-pass."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import subprocess
import tempfile

MIB = 1048576
ATTEMPTS, WALL, CAP = 5, 1200, 8 * MIB


def digest(path):
    data = path.read_bytes()
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def save(path, value):
    temporary = path.with_name(path.name+'.tmp')
    with temporary.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True); stream.write('\n')
    os.replace(temporary, path)


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--revision', required=True)
    for name in ('raw', 'toolchain', 'user-home', 'cargo-home'):
        parser.add_argument('--'+name, type=Path, required=True)
    a = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    assert Path(__file__).resolve() == repo/'evaluation/ordinary-exact-campaign/run.py'
    assert re.fullmatch('[0-9a-f]{40}', a.revision)
    for path in (repo, a.toolchain, a.user_home, a.cargo_home):
        assert path.is_absolute() and path.resolve(strict=True) == path and path.is_dir()
    assert a.raw.is_absolute() and a.raw.is_relative_to(repo/'ignored') and not a.raw.exists()
    assert a.raw.parent.resolve(strict=True) == a.raw.parent
    python = Path(sys.executable).resolve(strict=True)
    env = dict(HOME=str(a.user_home), CARGO_HOME=str(a.cargo_home), LC_ALL='C',
        PATH=str(a.toolchain/'bin')+':/usr/bin:/bin', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
    def git(*args):
        data = subprocess.check_output(['/usr/bin/git', '-C', str(repo), *args], env=env, timeout=15)
        assert len(data) <= CAP
        return data
    assert git('rev-parse', '--show-toplevel').decode().strip() == str(repo)
    sources = ('evaluation/ordinary-exact-campaign/run.py', 'evaluation/admission/processes.py',
               'tools/rapid-profiler/verify_normal_session_two.py')
    pins = {name: digest(repo/name) for name in sources}
    for name in sources:
        assert (repo/name).read_bytes() == git('show', a.revision+':'+name)
    cpus = sorted(os.sched_getaffinity(0))
    assert len(cpus) == 4, 'outer owner must reserve exactly four CPUs'
    tools = {str(path): digest(path) for path in (python, Path('/usr/bin/git').resolve(strict=True))}
    def snapshot():
        head = git('rev-parse', 'HEAD').decode().strip()
        clean = git('status', '--porcelain', '--untracked-files=no') == b''
        affinity = sorted(os.sched_getaffinity(0))
        assert head == a.revision and clean and affinity == cpus
        assert {name: digest(repo/name) for name in sources} == pins
        assert {name: digest(Path(name)) for name in tools} == tools
        load = list(os.getloadavg())
        assert len(load) == 3 and all(math.isfinite(n) and n >= 0 for n in load)
        with Path('/proc/loadavg').open('rb') as stream: raw = stream.read(257)
        assert len(raw) <= 256 and re.fullmatch(rb'[0-9]+\.[0-9]+ [0-9]+\.[0-9]+ [0-9]+\.[0-9]+ [0-9]+/[0-9]+ [0-9]+\n', raw)
        return dict(utc=utc(), head=head, tracked_clean=clean, affinity=affinity,
                    getloadavg=load, proc_loadavg_numeric=raw.decode('ascii').strip())
    before = snapshot()  # Authenticate before importing the sole project module.
    spec = importlib.util.spec_from_file_location('exact_five_processes', repo/sources[1])
    processes = importlib.util.module_from_spec(spec); spec.loader.exec_module(processes)
    a.raw.mkdir(mode=0o700)
    commands = [[str(python), '-B', str(repo/sources[2]), '--exact-work', '--revision', a.revision,
        '--raw', str(a.raw/f'attempt-{i:02d}'), '--toolchain', str(a.toolchain),
        '--user-home', str(a.user_home), '--cargo-home', str(a.cargo_home)] for i in range(1, ATTEMPTS+1)]
    manifest = dict(revision=a.revision, commands=commands, env=env, affinity=cpus,
        attempts=ATTEMPTS, wall_seconds=WALL, output_bytes=CAP, sources=pins, tools=tools,
        mapping=dict(producer=cpus[3], controller=cpus[0], two_workers=cpus[1:3], single_worker=cpus[1]),
        outer_authority='Root joins cpuset-alloc reservation/hard AllowedCPUs and selected quiet window; affinity alone is not that proof.',
        outer_owner_wall_seconds=7200)
    save(a.raw/'manifest.json', manifest)
    manifest_pin = digest(a.raw/'manifest.json')
    result = dict(schema=1, revision=a.revision, campaign_status='ABORTED', all_qualifications_pass=False,
        started_utc=before['utc'], before=before, manifest=manifest_pin, attempts=[
            dict(attempt=i, status='UNRUN') for i in range(1, ATTEMPTS+1)])
    save(a.raw/'campaign.json', result)
    try:
        logs_root = repo/'target/evaluation'; logs_root.mkdir(parents=True, exist_ok=True)
        assert logs_root.resolve(strict=True) == logs_root
        logs = Path(tempfile.mkdtemp(prefix='ordinary-exact-five-', dir=logs_root))
        for row, argv in zip(result['attempts'], commands):
            assert digest(a.raw/'manifest.json') == manifest_pin
            row.update(status='FAILED', before=snapshot(), started_utc=utc())
            save(a.raw/'campaign.json', result)
            log = logs/f'attempt-{row["attempt"]:02d}.log'
            assert not log.exists()
            closed = processes.run_command(argv, env, log, WALL, CAP)
            row.update(closed=closed, ended_utc=utc(), owner_log=digest(log))
            assert row['owner_log']['sha256'] == closed['private_log_sha256']
            # Never inspect partial child files or launch again without closure.
            if closed['cleanup_complete'] is not True:
                result['abort_reason'] = 'cleanup_not_proved'; break
            copied = a.raw/f'owner-{row["attempt"]:02d}.log'
            with copied.open('xb') as stream: stream.write(log.read_bytes())
            assert digest(copied) == row['owner_log']
            row['after'] = snapshot()
            directory = Path(argv[argv.index('--raw')+1])
            path = directory/'result.json'
            record = None
            if path.exists():
                row['result'] = digest(path)
                try:
                    assert row['result']['bytes'] <= CAP
                    record = json.loads(path.read_bytes()); assert type(record) is dict
                    row.update(result_status=record.get('status'), stage=record.get('stage'), error_type=record.get('error_type'))
                except (AssertionError, ValueError, UnicodeError) as error:
                    row['result_error'] = type(error).__name__
            if (directory/'failure.txt').exists(): row['failure'] = digest(directory/'failure.txt')
            normal = (closed['termination'] is None and closed['reaped_descendants'] == 0)
            row['status'] = 'PASS' if (normal and closed['exit_code'] == 0 and type(record) is dict
                and record.get('revision') == a.revision and record.get('status') == 'PASS'
                and record.get('stage') == 'complete' and type(record.get('exact_work')) is dict
                and record['exact_work'].get('status') == 'PASS') else 'FAILED'
            save(a.raw/'campaign.json', result)  # Closed failures do not stop the fixed population.
        else:
            result['campaign_status'] = 'COMPLETE'
        if result.get('abort_reason') != 'cleanup_not_proved':
            result['after'] = snapshot()
        assert digest(a.raw/'manifest.json') == manifest_pin
        result['all_qualifications_pass'] = (result['campaign_status'] == 'COMPLETE'
            and all(row['status'] == 'PASS' for row in result['attempts']))
    except BaseException as error:
        result['campaign_status'] = 'ABORTED'
        result['abort_reason'] = type(error).__name__
    finally:
        result['ended_utc'] = utc()
        result['attempts_started'] = sum(row['status'] != 'UNRUN' for row in result['attempts'])
        result['closed_attempts'] = sum(row.get('closed', {}).get('cleanup_complete') is True for row in result['attempts'])
        save(a.raw/'campaign.json', result)
    # Only closed vocabulary, counts/hashes/UTC/load numbers reach this summary.
    public = {key: result[key] for key in ('schema', 'revision', 'campaign_status',
        'all_qualifications_pass', 'started_utc', 'ended_utc', 'attempts_started', 'closed_attempts')}
    public['affinity'] = cpus; public['manifest'] = manifest_pin
    public['abort_reason'] = result.get('abort_reason')
    public['attempts'] = []
    for row in result['attempts']:
        item = {key: row[key] for key in ('attempt', 'status')}
        for key in ('started_utc', 'ended_utc', 'result', 'failure', 'owner_log'):
            if key in row: item[key] = row[key]
        for key in ('stage', 'error_type'):
            if type(row.get(key)) is str and re.fullmatch('[A-Za-z0-9_-]{1,100}', row[key]): item[key] = row[key]
        for key in ('before', 'after'):
            if key in row: item[key] = dict(utc=row[key]['utc'], load=row[key]['getloadavg'])
        if 'closed' in row:
            item['closure'] = {key: row['closed'][key] for key in ('exit_code', 'termination', 'cleanup_complete', 'reaped_descendants')}
        public['attempts'].append(item)
    save(a.raw/'summary.json', public)
    print(json.dumps(public, sort_keys=True))
    return 0 if result['all_qualifications_pass'] else 1


if __name__ == '__main__': raise SystemExit(main())
