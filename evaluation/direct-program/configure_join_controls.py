#!/usr/bin/env python3
"""Three owned controls for the configure join adapter; no configure or cat run."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

OWNER_SHA = '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
FIXTURE = '''import os,signal,sys
read,write=os.pipe()
if os.fork()==0:
    os.close(write)
    assert os.read(read,1)==b''
    if sys.argv[1]=='live':
        os.write(1,b'live adopted child\\n')
        signal.pause()
        os._exit(99)
    os._exit(int(sys.argv[1]))
os.close(read)
os._exit(0)
'''


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--revision', required=True); parser.add_argument('--adapter', required=True, type=Path)
    parser.add_argument('--adapter-sha256', required=True); parser.add_argument('--work', required=True, type=Path); args = parser.parse_args()
    root = Path.cwd().resolve(); work = args.work.absolute(); adapter = args.adapter.resolve(strict=True)
    logs = root/'target/evaluation/direct-program-configure-controls'/work.name
    assert work == work.resolve() and work.is_relative_to(root/'ignored') and work != root/'ignored' and work.parent.is_dir()
    assert not work.exists() and not logs.exists() and len(os.sched_getaffinity(0)) == 1
    helper = root/'evaluation/admission/processes.py'
    assert hashlib.sha256(helper.read_bytes()).hexdigest() == OWNER_SHA
    assert hashlib.sha256(adapter.read_bytes()).hexdigest() == args.adapter_sha256
    source_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    cpus = sorted(os.sched_getaffinity(0)); env = dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')
    def unchanged():
        assert subprocess.check_output(['/usr/bin/git', 'rev-parse', 'HEAD'], timeout=10).decode().strip() == args.revision
        assert not subprocess.check_output(['/usr/bin/git', 'status', '--porcelain', '--untracked-files=no'], timeout=10)
        assert sorted(os.sched_getaffinity(0)) == cpus and hashlib.sha256(adapter.read_bytes()).hexdigest() == args.adapter_sha256
        assert hashlib.sha256(helper.read_bytes()).hexdigest() == OWNER_SHA
        assert hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == source_sha
    unchanged(); work.mkdir(); logs.mkdir(parents=True)
    spec = importlib.util.spec_from_file_location('join_controls_owner', helper)
    owner = importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)
    results = {name: dict(status='UNOBSERVED') for name in ('normal-orphan', 'nonzero-orphan', 'live-orphan')}
    record = dict(status='FAILED', revision=args.revision, cpus=cpus, source_sha256=source_sha, adapter_sha256=args.adapter_sha256, results=results)
    save(work/'planned.json', record); safe = True
    try:
        for name, mode in (('normal-orphan', '0'), ('nonzero-orphan', '7'), ('live-orphan', 'live')):
            unchanged(); receipt = work/(name+'-join.json')
            command = ['/usr/bin/prlimit', '--cpu=3', '--as=268435456', '--fsize=65536', '--core=0', '--', sys.executable, '-I', '-B', str(adapter), '--receipt', str(receipt), '--', sys.executable, '-I', '-B', '-c', FIXTURE, mode]
            row = results[name]; row.update(status='DISPATCHED_UNKNOWN', command=command, wall_seconds=5, capture_bytes=65536)
            save(work/(name+'-intent.json'), row); safe = False
            result = owner.run_command(command, env, logs/(name+'.log'), 5, 65536)
            save(work/(name+'-owner.json'), result); row['owner'] = result; safe = result['cleanup_complete'] is True
            assert safe, 'incomplete cleanup: no payload or further process'
            raw = (logs/(name+'.log')).read_bytes()
            assert len(raw) <= 65536 and hashlib.sha256(raw).hexdigest() == result['private_log_sha256']
            with (work/(name+'.log')).open('xb') as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            if mode == 'live':
                assert result['termination'] == 'timeout' and result['exit_code'] == -signal.SIGKILL and result['reaped_descendants'] == 1
                assert raw == b'live adopted child\n' and not receipt.exists()
            else:
                assert result['termination'] is None and result['exit_code'] == (0 if mode == '0' else 1) and result['reaped_descendants'] == 0 and raw == b''
                assert receipt.stat().st_size <= 65536; joined = json.loads(receipt.read_bytes()); row['join'] = joined
                assert joined['initial_echild'] is True and joined['joined_echild'] is True and joined['command'] == command[command.index('--receipt')+3:]
                assert joined['leader']['exit_code'] == 0 and joined['leader']['wait_status'] == 0 and len(joined['adopted']) == 1
                child = joined['adopted'][0]; assert child['pid'] != joined['leader']['pid']
                assert child['exit_code'] == int(mode) == os.waitstatus_to_exitcode(child['wait_status'])
                assert joined['status'] == ('PASS' if mode == '0' else 'FAILED')
            unchanged(); row['status'] = 'PASS'
        record['status'] = 'PASS'
    except BaseException as error: record['error'] = type(error).__name__+': '+str(error)
    finally:
        record['cleanup_complete'] = safe; save(work/'closed.json', record)
    return int(record['status'] != 'PASS')


if __name__ == '__main__':
    assert __debug__ and sys.flags.isolated and sys.dont_write_bytecode
    raise SystemExit(main())
