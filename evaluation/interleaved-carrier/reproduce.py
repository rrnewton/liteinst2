#!/usr/bin/env python3
"""Build and normally execute four finite ELF carrier fixtures with fixed bounds."""
import argparse
import csv
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import subprocess
import sys

HELPER_SHA = 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
PROCESS_SHA = '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
CASES = ('original', 'below', 'gap', 'above')


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def main():
    if sys.flags.optimize:
        raise SystemExit('Python assertions must remain enabled')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', type=Path, required=True)
    parser.add_argument('--user-home', type=Path, required=True)
    parser.add_argument('--cargo-home', type=Path, required=True)
    parser.add_argument('--raw', type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    assert Path.cwd() == repo
    raw = args.raw.absolute()
    assert raw.parent.resolve(strict=True) == raw.parent and raw.is_relative_to(repo/'ignored')
    raw.mkdir()
    env = dict(PATH='/usr/bin:/bin', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')
    def git(*argv):
        return subprocess.check_output(['/usr/bin/git', *argv], cwd=repo, env=env, timeout=30)
    def capacity():
        row = subprocess.check_output(['/usr/bin/du', '-s', '-B1', '--apparent-size', str(repo)],
                                      env=env, timeout=30).decode().strip().split('\t')
        assert row[1] == str(repo)
        return int(row[0])
    before_bytes = capacity()
    assert before_bytes + 2_000_000_000 < 20_000_000_000
    save(raw/'capacity-before.json', dict(slot_bytes=before_bytes, cap_bytes=20_000_000_000))
    revision = git('rev-parse', 'HEAD').decode().strip()
    assert len(revision) == 40 and not git('diff', 'HEAD', '--')
    affinity = sorted(os.sched_getaffinity(0))[:4]
    assert affinity
    os.sched_setaffinity(0, affinity)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    helper = repo/'tools/unwind-oracle/bounded_command.py'
    process_path = repo/'evaluation/admission/processes.py'
    assert digest(helper) == HELPER_SHA and digest(process_path) == PROCESS_SHA
    spec = importlib.util.spec_from_file_location('bounded_processes', process_path)
    processes = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(processes)
    tools = {name: (args.toolchain/'bin'/name).resolve(strict=True) for name in ('cargo', 'rustc')}
    tools.update(python=Path('/usr/bin/python3.9').resolve(strict=True),
                 timeout=Path('/usr/bin/timeout').resolve(strict=True))
    tools_before = {name: digest(path) for name, path in tools.items()}
    roles = [(str(raw), '${RAW}'), (str(repo), '${REPO}'),
             (str(args.toolchain.resolve()), '${TOOLCHAIN}'),
             (str(args.cargo_home.resolve()), '${CARGO_HOME}'),
             (str(args.user_home.resolve()), '${USER_HOME}')]
    def normalized(value):
        if isinstance(value, str):
            for path, role in sorted(roles, key=lambda row: -len(row[0])):
                value = value.replace(path, role)
            return value
        if isinstance(value, list):
            return [normalized(x) for x in value]
        if isinstance(value, dict):
            return {k: normalized(v) for k, v in value.items()}
        return value
    rows, commands = [], []
    def execute(name, argv, child_env, limits):
        directory = raw/name
        directory.mkdir()
        cpu, wall, mib = limits
        request = dict(argv=list(map(str, argv)), cwd=str(repo), env=child_env,
                       stdout=str(directory/'stdout'), stderr=str(directory/'stderr'),
                       cpu_seconds=cpu, wall_seconds=wall, file_bytes=mib*1024*1024)
        save(directory/'request.json', request)
        parent = [str(tools['timeout']), '--signal=TERM', '--kill-after=10s', str(wall+10)+'s',
                  str(tools['python']), '-B', str(helper), '--request', str(directory/'request.json'),
                  '--receipt', str(directory/'receipt.json')]
        log = repo/'target/evaluation'/('carrier-'+raw.name+'-'+name+'.log')
        log.parent.mkdir(exist_ok=True, parents=True)
        assert not log.exists()
        closed = processes.run_command(parent, env, log, wall+25, 1024*1024)
        save(directory/'parent.json', closed)
        (directory/'parent.log').write_bytes(log.read_bytes())
        assert closed['exit_code'] == 0 and closed['termination'] is None
        assert closed['cleanup_complete'] and closed['reaped_descendants'] == 0
        receipt = json.loads((directory/'receipt.json').read_bytes())
        assert receipt['exit'] == 0 and receipt['absence_proof'] == 'ECHILD'
        assert not receipt['wall_timeout'] and not receipt['unexpected_descendants']
        assert receipt['aborted'] is None and receipt['cleanup_error'] is None and not receipt['cleanup_events']
        assert receipt['inputs_unchanged'] and receipt['helper_sha256'] == HELPER_SHA
        assert receipt['request_sha256'] == digest(directory/'request.json')
        assert all(receipt[s+'_sha256'] == digest(directory/s) for s in ('stdout', 'stderr'))
        commands.append(normalized(dict(name=name, request=request, parent_argv=parent,
                                       parent_wall_seconds=wall+25, parent_env=env)))
        rows.append(dict(stage=name, exit=0, seconds=receipt['elapsed_seconds'],
                         receipt_sha256=digest(directory/'receipt.json'),
                         stdout_sha256=digest(directory/'stdout')))
        return directory
    compile_env = dict(env, HOME=str(args.user_home.resolve()), CARGO_HOME=str(args.cargo_home.resolve()),
                       RUSTC=str(tools['rustc']), CARGO_TARGET_DIR=str(repo/'target'),
                       CARGO_BUILD_JOBS='4', CARGO_INCREMENTAL='0', CARGO_NET_OFFLINE='true',
                       CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0',
                       CARGO_PROFILE_DEV_OPT_LEVEL='0', CARGO_PROFILE_DEV_DEBUG_ASSERTIONS='true',
                       CARGO_PROFILE_DEV_OVERFLOW_CHECKS='true')
    build = execute('build', [tools['cargo'], 'build', '--locked', '--offline', '-p', 'liteinst-rewrite',
                             '--example', 'emit_interleaved_carrier', '--message-format=json'],
                    compile_env, (120, 180, 128))
    artifacts = [json.loads(line) for line in (build/'stdout').read_text().splitlines()]
    selected = [row for row in artifacts if row.get('reason') == 'compiler-artifact'
                and row['target']['name'] == 'emit_interleaved_carrier' and row.get('executable')]
    assert len(selected) == 1
    profile = selected[0]['profile']
    assert type(profile['opt_level']) is str and type(profile['debuginfo']) is int
    assert all(type(profile[name]) is bool for name in ('debug_assertions', 'overflow_checks', 'test'))
    assert profile == dict(opt_level='0', debuginfo=0, debug_assertions=True,
                           overflow_checks=True, test=False)
    product = Path(selected[0]['executable'])
    assert product.is_relative_to(repo/'target')
    product_sha = digest(product)
    fixture_dir = raw/'fixtures'
    execute('emit', [product, fixture_dir], env, (2, 5, 1))
    assert digest(product) == product_sha
    assert {p.name for p in fixture_dir.iterdir()} == {name+'.elf' for name in CASES}
    expected = b'42\n'
    cases = []
    for name in CASES:
        path = fixture_dir/(name+'.elf')
        before = digest(path)
        output = execute('run-'+name, [path], env, (2, 5, 1))
        assert (output/'stdout').read_bytes() == expected and not (output/'stderr').read_bytes()
        assert digest(path) == before
        cases.append(dict(case=name, status='PASS', exit=0, stdout_sha256=digest(output/'stdout'),
                          image_sha256=before, bytes=path.stat().st_size))
    assert git('rev-parse', 'HEAD').decode().strip() == revision and not git('diff', 'HEAD', '--')
    assert tools_before == {name: digest(path) for name, path in tools.items()}
    assert digest(helper) == HELPER_SHA and digest(process_path) == PROCESS_SHA
    after_bytes = capacity()
    save(raw/'capacity-after.json', dict(slot_bytes=after_bytes, cap_bytes=20_000_000_000))
    assert after_bytes < 20_000_000_000
    model = next(line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines()
                 if line.startswith('model name'))
    save(raw/'receipt.json', dict(revision=revision, status='PASS', cases=4, rewritten_cases=3,
         strict_receipts=len(rows), producer_sha256=product_sha, tools_sha256=tools_before,
         source_sha256=digest(Path(__file__)), affinity=affinity,
         hardware=dict(label=('AMD EPYC Zen 5 dev host' if model.startswith('AMD EPYC 9D85') else model), cpu_model=model,
                       architecture=os.uname().machine, kernel=os.uname().release),
         build_profile='dev-debug0-opt0', performance_claim=False,
         scope='Finite freestanding ET_EXEC kernel loading and exact stdout/exit; no general loader or state-equivalence claim.'))
    save(raw/'commands.json', commands)
    for filename, values in [('stages.csv', rows), ('cases.csv', cases)]:
        with (raw/filename).open('x', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=list(values[0]))
            writer.writeheader()
            writer.writerows(values)
    print(json.dumps(dict(revision=revision, cases=4, status='PASS')))


if __name__ == '__main__':
    main()
