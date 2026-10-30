#!/usr/bin/env python3
"""One whole-authored material/importer attempt; external root owns capture provenance and custody."""
import argparse
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import types

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
sha = lambda b: hashlib.sha256(b).hexdigest()
PINS = {}


def load(name, digest):
    path = HERE / name
    with path.open('rb') as stream: raw = stream.read(1048577)
    assert len(raw) <= 1048576 and sha(raw) == digest
    module = types.ModuleType('_whole_' + path.stem); module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


assert not sys.flags.optimize, 'assertions required'
B = load('build_whole.py', '2731a71ee7848098be194111baf240b498dbbaf18c82252877d1a95345d1d3d2')
H = load('head_capture.py', 'ae10489d1ff6449a596d491f5732cc58c95040e7353d6815b4c00e0f49eb0d01')
D = H.D


def read(path, expected=None, cap=256 * 1048576):
    path = Path(path); pin = B.identity(path)
    assert pin['bytes'] <= cap and (expected is None or pin == expected)
    with path.open('rb') as stream: raw = stream.read(cap + 1)
    assert len(raw) == pin['bytes'] and sha(raw) == pin['sha256'] and B.identity(path) == pin
    key = str(path); assert key not in PINS or PINS[key] == pin; PINS[key] = pin
    return raw


def jread(path): return json.loads(read(path, cap=1048576))


def closed(directory, request, recorded=None):
    parent = jread(directory / 'parent-closed.json')
    assert parent['wait_returned'] is True and parent['error'] is None
    receipt = jread(directory / 'receipt.json')
    assert receipt['absence_proof'] == 'ECHILD' and receipt['cleanup_error'] is None
    assert receipt['helper_sha256'] == B.HELPER_SHA and receipt['inputs_unchanged'] is True
    assert sha(read(directory / 'request.json')) == receipt['request_sha256']
    assert jread(directory / 'request.json') == request
    if recorded is not None:
        assert receipt == recorded['receipt'] and parent['exit'] == recorded['helper_exit']
    streams = {s: read(directory / (s + '.txt'), cap=request['file_bytes']) for s in ('stdout', 'stderr')}
    assert all(sha(streams[s]) == receipt[s + '_sha256'] for s in streams)
    assert type(receipt['exit']) is int and parent['exit'] == (0 if receipt['exit'] == 0 else 1)
    assert not receipt['wall_timeout'] and receipt['aborted'] is None
    assert receipt['cleanup_events'] == receipt['unexpected_descendants'] == []
    assert read(directory / 'helper.stderr', cap=1048576) == b''
    return receipt['exit'], streams


def invoke(directory, argv, env, tools):
    request = dict(argv=argv, cwd=str(ROOT), env=env, stdout=str(directory / 'stdout.txt'),
                   stderr=str(directory / 'stderr.txt'), cpu_seconds=20, wall_seconds=30, file_bytes=16 * 1048576)
    B.write(directory / 'request.json', request)
    command = [tools['timeout']['path'], '--signal=TERM', '--kill-after=10s', '40s',
               tools['python']['path'], '-B', tools['helper']['path'], '--request',
               str(directory / 'request.json'), '--receipt', str(directory / 'receipt.json')]
    B.write(directory / 'command.json', dict(argv=command, cwd=str(ROOT), env=env, parent_seconds=55, cleanup_seconds=10))
    child = None; parent = dict(wait_returned=False, exit=None, error=None)
    try:
        with (directory / 'helper.stdout').open('xb') as stdout, (directory / 'helper.stderr').open('xb') as stderr:
            child = subprocess.Popen(command, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                     stdout=stdout, stderr=stderr, start_new_session=True)
            try: child.wait(timeout=55); parent['wait_returned'] = True
            except BaseException as error:
                parent['error'] = type(error).__name__
                if child.poll() is None:
                    try: os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                child.wait(timeout=10); parent['wait_returned'] = True
                raise
    finally:
        parent['exit'] = child.returncode if child else None; B.write(directory / 'parent-closed.json', parent)
    return closed(directory, request)


def importer_metadata(profile):
    assert profile in (D.PROFILE, D.WINDOW_PROFILE, D.BROAD_PROFILE, D.SHORT_PROFILE, D.SHORT_T3_OWNERSHIP_PROFILE), 'explicit placement profile'
    if profile == D.SHORT_T3_OWNERSHIP_PROFILE:
        return [['profile', 'elf-disassembly-null-jumps-short-t3-ownership-v1'],
                ['neighbor_victims', 'short-only'], ['neighbor_ownership', 'inherited-t3']]
    if profile == D.SHORT_PROFILE:
        return [['profile', 'elf-disassembly-null-jumps-short-only-v1'],
                ['neighbor_victims', 'short-only']]
    return [['profile', 'elf-disassembly-null-jumps-v1']]


def importer_arguments(binary, original, ledger, policy, output, material, profile):
    importer_metadata(profile)
    mode = ['--short-neighbors-only'] if profile == D.SHORT_PROFILE else []
    if profile == D.SHORT_T3_OWNERSHIP_PROFILE:
        mode = ['--short-neighbors-owned']
    return [str(binary), *mode, str(original), str(ledger), sha(material['ledger.txt']),
            str(policy), sha(material['policy.txt']), str(output)]


def importer_stdout(raw, profile, exit_code):
    importer_metadata(profile)
    if profile == D.SHORT_T3_OWNERSHIP_PROFILE:
        assert exit_code in (0, 2)
        complete = 'true' if exit_code == 0 else 'false'
        assert raw == (f'profile=elf-disassembly-null-jumps-short-t3-ownership-v1 '
                       f'neighbor_victims=short-only neighbor_ownership=inherited-t3 '
                       f'candidate_complete={complete} qualification_complete=false\n').encode('ascii')
    if profile == D.SHORT_PROFILE:
        assert exit_code in (0, 2)
        complete = 'true' if exit_code == 0 else 'false'
        assert raw == (f'profile=elf-disassembly-null-jumps-short-only-v1 neighbor_victims=short-only '
                       f'candidate_complete={complete} qualification_complete=false\n').encode('ascii')


def inventory(directory, original, material, exit_code, *, profile=D.PROFILE):
    table = lambda raw: list(csv.reader(io.StringIO(raw.decode('ascii')), delimiter='\t'))
    mode = importer_metadata(profile)
    index = table(read(directory / 'COMPLETE', cap=1048576))
    prefix = [['LI2DISASSEMBLY-DIRECTORY', '1'], *mode,
              ['observed_original_sha256', sha(original)], ['candidate_complete', 'true' if exit_code == 0 else 'false'], ['qualification_complete', 'false']]
    assert exit_code in (0, 2) and index[:len(prefix)] == prefix
    names = [r[1] for r in index[len(prefix):]]; assert len(names) == len(set(names)) <= 256
    for row in index[len(prefix):]:
        assert len(row) == 4 and row[0] == 'file' and Path(row[1]).name == row[1] and row[1] not in ('.', '..')
        data = read(directory / row[1]); assert str(len(data)) == row[2] and sha(data) == row[3]
    assert 'disassembly-inventory.tsv' in names and ('candidate.elf' in names) == (exit_code == 0)
    source = list(csv.DictReader(io.StringIO(material['source-inventory.tsv'].decode()), delimiter='\t'))
    selected = [r for r in source if r['selected_jump'] == '1']
    actual = table(read(directory / 'disassembly-inventory.tsv', cap=1048576))
    header = [['LI2DISASSEMBLY-INVENTORY', '1'], *mode, ['original_sha256', sha(original)],
              ['ledger_sha256', sha(material['ledger.txt'])], ['complete_jump_count', str(len(selected))], ['qualification_complete', 'false']]
    assert actual[:len(header)] == header
    assert actual[len(header)] == ['id', 'pc', 'length', 'file_offset', 'region_pc', 'region_length', 'block_pc', 'block_length']
    records = actual[len(header) + 1:]
    assert all(len(r) == 8 for r in records)
    assert [r[:4] for r in records] == [[str(i), r['pc'], r['length'], r['file_offset']] for i, r in enumerate(selected, 1)]
    if profile == D.SHORT_PROFILE:
        assert 'planning-profile.tsv' in names or 'program-failure.tsv' in names
        assert exit_code == 2 or 'program-failure.tsv' not in names
        for name, tag in (('planning-profile.tsv', 'LI2PLANNING'),
                          ('program-failure.tsv', 'LI2DISASSEMBLY-FAILURE')):
            if name in names:
                rows = table(read(directory / name, cap=1048576))
                assert rows[:3] == [[tag, '1'], *mode]
                assert sum(r[:1] == ['profile'] for r in rows) == 1
                assert sum(r[:1] == ['neighbor_victims'] for r in rows) == 1
    if profile == D.SHORT_T3_OWNERSHIP_PROFILE:
        assert 'planning-profile.tsv' in names or 'program-failure.tsv' in names
        assert exit_code == 2 or 'program-failure.tsv' not in names
        for name, tag in (('planning-profile.tsv', 'LI2PLANNING'),
                          ('program-failure.tsv', 'LI2DISASSEMBLY-FAILURE')):
            if name in names:
                rows = table(read(directory / name, cap=1048576))
                assert rows[:1 + len(mode)] == [[tag, '1'], *mode]
                assert sum(r[:1] == ['profile'] for r in rows) == 1
                assert sum(r[:1] == ['neighbor_victims'] for r in rows) == 1
                assert sum(r[:1] == ['neighbor_ownership'] for r in rows) == 1
    return exit_code == 0


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True); parser.add_argument('--capture-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--placement-profile', choices=(D.PROFILE, D.WINDOW_PROFILE, D.BROAD_PROFILE, D.SHORT_PROFILE, D.SHORT_T3_OWNERSHIP_PROFILE), default=D.PROFILE,
                        help='fixed placement policy for both programs; default preserves fixed-page placement')
    return parser.parse_args(argv)


def material_attempt(program, inputs, expected, profile):
    assert profile in (D.PROFILE, D.WINDOW_PROFILE, D.BROAD_PROFILE, D.SHORT_PROFILE, D.SHORT_T3_OWNERSHIP_PROFILE), 'explicit placement profile'
    if profile == D.PROFILE:
        return D.attempt(program, inputs, expected)
    if profile == D.BROAD_PROFILE:
        return D.attempt(program, inputs, expected, profile=D.BROAD_PROFILE)
    if profile == D.SHORT_T3_OWNERSHIP_PROFILE:
        return D.attempt(program, inputs, expected, profile=D.SHORT_T3_OWNERSHIP_PROFILE)
    if profile == D.SHORT_PROFILE:
        return D.attempt(program, inputs, expected, profile=D.SHORT_PROFILE)
    return D.attempt(program, inputs, expected, profile=D.WINDOW_PROFILE)


def main():
    args = arguments()
    capture, output = args.capture, args.output
    assert capture.is_absolute() and capture.resolve(strict=True) == capture and capture.is_relative_to(ROOT / 'ignored')
    assert output.is_absolute() and output.is_relative_to(ROOT / 'ignored') and not output.is_relative_to(capture)
    assert not os.path.lexists(output) and output.parent.resolve(strict=True) == output.parent
    assert re.fullmatch('[0-9a-f]{64}', args.capture_sha256); output.mkdir(mode=0o700)
    report = dict(capture=str(capture), capture_sha256=args.capture_sha256, configuration_complete=False,
                  qualification_complete=False, scope='Material/structural importer only; no candidate execution, native or performance qualification',
                  programs={p: dict(status='UNRUN') for p in B.PROGRAMS})
    if args.placement_profile != D.PROFILE:
        report['placement_profile'] = args.placement_profile
    try:
        raw = read(capture / 'closed.json', cap=1048576); assert sha(raw) == args.capture_sha256
        captured, plan = json.loads(raw), jread(capture / 'planned.json'); env, tools = plan['env'], plan['tools']
        assert captured['revision'] == plan['revision'] and re.fullmatch('[0-9a-f]{40}', captured['revision'])
        assert captured['qualification_complete'] is plan['qualification_complete'] is False
        complete = all(r['state'] != 'READ_DENIED' for r in plan['configurations'].values())
        assert captured['configuration_complete'] is plan['configuration_complete'] is complete
        report.update(capture_revision=captured['revision'], configuration_complete=complete)
        git = lambda *a: subprocess.check_output(['/usr/bin/git', '-C', str(ROOT), *a], env=env, timeout=15)
        report['current_revision'] = git('rev-parse', 'HEAD').decode().strip(); assert not git('diff', '--binary', 'HEAD', '--')
        assert git('show', report['current_revision'] + ':evaluation/offline-corpus/reproduce_whole.py') == read(Path(__file__), cap=1048576)
        assert not git('diff', '--binary', captured['revision'], report['current_revision'], '--', 'Cargo.toml', 'Cargo.lock', 'build.rs', '.cargo', 'src', 'crates', 'tools/elf-rewrite', 'tests/support')
        assert all(captured['files'][p] == v for p, v in plan['inputs'].items())
        assert set(tools) == {'python', 'helper', 'as', 'ld', 'objdump', 'timeout', 'cargo', 'rustc'}
        for path, pin in captured['files'].items(): read(Path(path), pin)
        for path in (__file__, B.__file__, H.__file__, D.__file__, D.C.__file__, D.T.__file__): read(Path(path), cap=1048576)
        for pin in tools.values(): read(Path(pin['path']), pin)
        assert tools['helper']['sha256'] == B.HELPER_SHA and tools['helper']['path'] == str(ROOT / 'tools/unwind-oracle/bounded_command.py')
        assert B.identity(sys.executable) == tools['python'], 'same pinned Python for material transformation'
        assert B.configuration(ROOT, Path(env['CARGO_HOME'])) == plan['configurations']
        def stable():
            assert all(B.identity(path) == pin for path, pin in PINS.items())
            assert git('rev-parse', 'HEAD').decode().strip() == report['current_revision'] and not git('diff', '--binary', 'HEAD', '--')
            assert B.configuration(ROOT, Path(env['CARGO_HOME'])) == plan['configurations']
        streams = {}; expected_argv = {}
        for package, kind, name in [('liteinst-rewrite', 'example', 'disassembly_sites'), ('liteinst2', 'bin', 'elf-exec-oracle')]:
            expected_argv['build-' + name] = [tools['cargo']['path'], 'build', '--release', '--locked', '--offline', '--package', package, '--' + kind, name, '--message-format=json']
        expected_argv['target'] = [str(ROOT / 'target/release/elf-exec-oracle'), 'target']
        for program in B.PROGRAMS:
            obj, original = capture / program / 'subject.o', capture / program / 'original'
            expected_argv[program + '-as'] = [tools['as']['path'], '--64', str(HERE / (program + '.S')), '-o', str(obj)]
            expected_argv[program + '-ld'] = [tools['ld']['path'], '-static', '-nostdlib', '--build-id=none', '-z', 'noexecstack', '-T', str(HERE / 'layout.ld'), str(obj), '-o', str(original)]
            for symbol in ('_start', 'kernel', 'null_hook'):
                expected_argv[program + '-disassemble-' + symbol] = [tools['objdump']['path'], '-d', '-w', '--insn-width=16', '--disassemble=' + symbol, str(original)]
        assert [p['name'] for p in plan['phases']] == list(expected_argv) and set(captured['results']) == set(expected_argv)
        for phase in plan['phases']:
            name = phase['name']; directory = capture / name; row = captured['results'][name]
            assert phase['argv'] == expected_argv[name]
            assert phase['limits'] == ([120, 180, 128] if name.startswith('build-') else [60, 90, 128] if name.endswith(('-as', '-ld')) else [20, 30, 16])
            if row['status'] != 'PASS': continue
            cpu, wall, mib = phase['limits']
            request = dict(argv=phase['argv'], cwd=str(ROOT), env=env, stdout=str(directory / 'stdout.txt'),
                           stderr=str(directory / 'stderr.txt'), cpu_seconds=cpu, wall_seconds=wall, file_bytes=mib * 1048576)
            code, streams[name] = closed(directory, request, row); assert code == 0
        assert all(p in streams for p in ('build-disassembly_sites', 'build-elf-exec-oracle', 'target'))
        for kind, name, path in [('example', 'disassembly_sites', ROOT / 'target/release/examples/disassembly_sites'), ('bin', 'elf-exec-oracle', ROOT / 'target/release/elf-exec-oracle')]:
            messages = [json.loads(line) for line in streams['build-' + name]['stdout'].splitlines()]
            artifacts = [m for m in messages if m.get('reason') == 'compiler-artifact' and m['target']['name'] == name and m.get('executable')]
            assert len(artifacts) == 1 and artifacts[0]['profile'] == B.PROFILE and artifacts[0]['target']['kind'] == [kind] and artifacts[0]['executable'] == str(path)
            assert [m for m in messages if m.get('reason') == 'build-finished'] == [dict(reason='build-finished', success=True)]
            read(path, captured['files'][str(path)])
        binary = ROOT / 'target/release/examples/disassembly_sites'; read(binary, captured['files'][str(binary)])
        B.write(output / 'inputs.json', dict(report=report, first_pins=PINS, build_plan=plan))
        for program in B.PROGRAMS:
            row = report['programs'][program]; row['status'] = 'MATERIALS_REFUSED'; directory = output / program; directory.mkdir(); stable()
            try:
                inputs = {k: read(capture / program / v, captured['files'][str(capture / program / v)], D.CAP) for k, v in [('original', 'original'), ('object', 'subject.o')]}
                for suffix in ('as', 'ld', 'disassemble-_start', 'disassemble-kernel', 'disassemble-null_hook'): assert program + '-' + suffix in streams
                inputs.update(source=read(HERE / (program + '.S'), captured['files'][str(HERE / (program + '.S'))], D.CAP),
                              linker=read(HERE / 'layout.ld', captured['files'][str(HERE / 'layout.ld')], D.CAP), target=streams['target']['stdout'])
                captures = {r: streams[program + '-disassemble-' + s]['stdout'] for r, s in H.SYMBOLS.items()}
                B.write(directory / 'raw-input-hashes.json', dict(inputs={k: sha(v) for k, v in inputs.items()}, objdump={k: sha(v) for k, v in captures.items()}))
                inputs['heads'] = H.capture(program, inputs['original'], inputs['object'], captures)
                with (directory / 'heads.txt').open('xb') as stream: stream.write(inputs['heads'])
                expected = {k: sha(v) for k, v in inputs.items()}
                B.write(directory / 'input-hashes.json', expected); result = material_attempt(program, inputs, expected, args.placement_profile); material = result.pop('files')
                for name, data in material.items():
                    with (directory / name).open('xb') as stream: stream.write(data)
                    assert read(directory / name) == data
                B.write(directory / 'materials.json', dict(result, files={k: sha(v) for k, v in material.items()})); row.update(materials=result)
                if result['status'] != 'MATERIALS_READY': continue
            except Exception as error:
                row['error'] = type(error).__name__; continue
            stable(); row['status'] = 'IMPORTER_FAILED'; attempt = directory / 'importer'; attempt.mkdir()
            argv = importer_arguments(binary, capture / program / 'original', directory / 'ledger.txt',
                                      directory / 'policy.txt', attempt / 'product', material, args.placement_profile)
            code, importer_streams = invoke(attempt, argv, env, tools); row['importer_exit'] = code; stable()
            try:
                importer_stdout(importer_streams['stdout'], args.placement_profile, code)
                row['status'] = 'IMPORTER_COMPLETE' if inventory(attempt / 'product', inputs['original'], material, code,
                                                              profile=args.placement_profile) else 'IMPORTER_REFUSED'
                row['inventory_joined'] = True
            except Exception as error: row['error'] = type(error).__name__
        stable()
    except BaseException as error:
        report['error'] = type(error).__name__; raise
    finally: B.write(output / 'closed.json', dict(report, first_pins=PINS))
    return 1 if any(r['status'] != 'IMPORTER_COMPLETE' for r in report['programs'].values()) else 0 if report['configuration_complete'] else 2


if __name__ == '__main__': raise SystemExit(main())
