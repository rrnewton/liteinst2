#!/usr/bin/env python3
"""Pure D01 protocol/control tests; synthetic declarations are never core plans."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

assert not sys.flags.optimize, 'assertions required'
path = Path(__file__).resolve().with_name('reproduce_whole.py')
with path.open('rb') as stream:
    raw = stream.read(1048577)
assert len(raw) <= 1048576 and hashlib.sha256(raw).hexdigest() == 'cb88ef6a05e1a353e78a59c2a264c7a08bfdbe516c1f6982a43973125cc9d92c'
R = types.ModuleType('authenticated_d01_reproducer'); R.__file__ = str(path)
exec(compile(raw, str(path), 'exec'), R.__dict__)
A = R.load('adjacent_whole.py', 'a0da09ee3a65668a08e3dc0421dab36bfba4ae6a081f90318d736955680f081e')
B = R.load('build_adjacent_whole.py', '0def6474c15584dd168b74c2338311caa53d1864ab01d5805cb3a05c62960592')
COUNTS = {'checksum': (80, 16), 'rle-roundtrip': (107, 26)}
IMPORTER = 'elf-disassembly-null-jumps-adjacent-b2-short-t3-pending-v1'
MATERIAL = 'offline-whole-authored-adjacent-b2-short-t3-pending-2g-v1'
FAMILY = [['neighbor_victims', 'short-only'], ['neighbor_ownership', 'inherited-t3'],
          ['pending_selected', 'full-instruction-ownership'], ['adjacent_b2', 'fallback-two-site-v1']]
digest = lambda raw: hashlib.sha256(raw).hexdigest()
encoded = lambda value: (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
tsv = lambda rows: ('\n'.join('\t'.join(row) for row in rows) + '\n').encode()


def fixture(program, complete=True, preparation=None):
    """Only a publication protocol fixture. Original/codecs intentionally unverified."""
    heads, count = COUNTS[program]
    original = bytes(1024)
    ledger = ['LI2DISASM 1', 'original ' + digest(original),
              'contract complete-code no-overlap no-code-as-data private-image']
    inventory = [['role', 'index', 'pc', 'file_offset', 'length', 'selected_jump']]
    selected, geometry = [], {}
    for role, population, pc, offset, selected_count in [
        ('start', 61, 0x401000, 0, 14), ('kernel', heads - 62, 0x402000, 256, count - 14),
        ('hook', 1, 0x403000, 512, 0)]:
        ledger.append(f'region {pc} {offset} {population * 2}')
        for index in range(population):
            at, off = pc + 2 * index, offset + 2 * index
            ledger.append(f'head {at} 9090')
            chosen = index < selected_count
            inventory.append([role, str(index), str(at), str(off), '2', str(int(chosen))])
            if chosen:
                sid = len(selected) + 1
                selected.append([str(sid), str(at), '2', str(off)])
                geometry[sid] = (pc, population * 2)
    material = {'ledger.txt': ('\n'.join(ledger) + '\n').encode(),
                'source-inventory.tsv': tsv(inventory)}
    policy = ['LI2DISASM-POLICY 5', 'original ' + digest(original),
        'ledger ' + digest(material['ledger.txt']), 'neighbor-victims short-only',
        'neighbor-ownership inherited-t3', 'pending-selected full-instruction-ownership',
        'adjacent-b2 fallback-two-site-v1', 'adjacent-b2-budgets 2 1 2', 'target opaque-fixture',
        'domain 1', 'carrier 4718592',
        'limits 1048576 32 32 131072 128 2097152 1048576 128 2147483648', 'null-hook 4206592']
    for sid in range(1, count + 1):
        policy.extend([f'search {sid} preferred 64 256 64 none 256 4096',
            f'allocation {sid} selected 5242880 1 4096 4546560:172032 4726784:2146951168',
            f'allocation {sid} victim 6291456 1 4096 4546560:172032 4726784:2146951168'])
    material['policy.txt'] = ('\n'.join(policy) + '\n').encode()
    manifest = ['LI2TOOL 1', 'original ' + digest(original), 'neighbor-victims short-only',
        'neighbor-ownership inherited-t3', 'pending-selected full-instruction-ownership',
        'adjacent-b2 fallback-two-site-v1', 'adjacent-b2-budgets 2 1 2']
    for sid, pc, length, offset in selected:
        region, size = geometry[int(sid)]
        manifest.append(f'site {sid} {pc} {length} {offset} {region} {size} {region} {size} {pc} {length} 1 observe original-decode')
    selection = ('\n'.join(manifest) + '\n').encode()
    sid = digest(selection)
    rows = [['LI2DISASSEMBLY-INVENTORY', '1'], ['profile', IMPORTER], *FAMILY,
        ['original_sha256', digest(original)], ['ledger_sha256', digest(material['ledger.txt'])],
        ['complete_jump_count', str(count)], ['qualification_complete', 'false'],
        ['id', 'pc', 'length', 'file_offset', 'region_pc', 'region_length', 'block_pc', 'block_length']]
    for row in selected:
        region, size = geometry[int(row[0])]
        rows.append(row + [str(region), str(size), row[1], row[2]])
    source_inventory = tsv(rows)
    files = {'disassembly.txt': material['ledger.txt'], 'disassembly-policy.txt': material['policy.txt']}
    if preparation is not None:
        if preparation >= 1:
            files['disassembly-inventory.tsv'] = source_inventory
        if preparation >= 2:
            files['selection.txt'] = selection
        files['program-failure.tsv'] = tsv([['LI2DISASSEMBLY-FAILURE', '1'], ['profile', IMPORTER],
            ['observed_original_sha256', digest(original)], ['expected_ledger_sha256', digest(material['ledger.txt'])],
            ['expected_policy_sha256', digest(material['policy.txt'])], ['qualification_complete', 'false'],
            ['detail_hex', b'synthetic refusal'.hex()]])
        return original, material, indexed(files, original, 2)
    files.update({'disassembly-inventory.tsv': source_inventory, 'selection.txt': selection,
                  'target.tsv': b'opaque target\n', 'metadata.li2meta': b'opaque metadata'})
    files['planning-profile.tsv'] = tsv([['LI2PLANNING', '1'], ['profile', IMPORTER], *FAMILY,
        ['adjacent_upper', '2'], ['adjacent_lower', '1'], ['adjacent_joint', '2'],
        ['scope', 'artifact-code-regions-not-functions'], ['entries', 'all-verified-instruction-heads'],
        ['original_sha256', digest(original)], ['ledger_sha256', digest(material['ledger.txt'])],
        ['policy_sha256', digest(material['policy.txt'])], ['selection_sha256', sid],
        ['complete_jump_count', str(count)], ['qualification_complete', 'false']])
    reports = [['LI2REPORT', '1'], ['original_sha256', digest(original)], ['selection_sha256', sid],
        ['candidate_complete', str(complete).lower()], ['qualification_complete', 'false'],
        ['site', 'pc', 'file_offset', 'length', 'core_tactic', 'candidate_emitted', 'refusal_code', 'stage', 'detail_hex']]
    for row in selected:
        reports.append([row[0], row[1], row[3], row[2],
            'generalized-pun' if complete else 'none', str(complete).lower(),
            'none' if complete else '10003', 'none' if complete else 'atomic-selection',
            '' if complete else b'synthetic refusal'.hex()])
        files[f'site-{row[0]}.diagnostics.txt'] = b'opaque baseline diagnostics\n'
    files['report.tsv'] = tsv(reports)
    files['adjacent-b2-evidence.txt'] = tsv([['LI2ADJACENT-EVIDENCE', '1'], ['selection_sha256', sid],
        ['selected_count', str(count)], ['baseline_calls', str(count)], ['pair_calls', '0'],
        ['adjacent_counts', '0', '0', '0'], ['qualification_complete', 'false'],
        ['classification_complete', 'false'], ['legacy_image_slots', '0'],
        ['combined_image_work_upper_bound', '0']]) + b'resources\topaque\n\xffopaque Debug tail\n'
    if complete:
        files.update({'ledger.tsv': b'opaque ledger', 'plan-ledger.tsv': b'opaque plan ledger',
            'candidate.elf': b'opaque candidate', 'source.li2sparse': b'opaque sparse',
            'image-0000.bin': b'opaque generated image'})
    else:
        files['ledger.tsv'] = tsv([['LI2ADJACENT-NO-CANDIDATE', '1'],
                                   ['selection_sha256', sid], ['qualification_complete', 'false']])
    files['bundle-index.tsv'] = b''
    return original, material, indexed(files, original, 0 if complete else 2)


def indexed(files, original, code):
    files = dict(files)
    files.pop('COMPLETE', None)
    if 'bundle-index.tsv' in files:
        files['bundle-index.tsv'] = tsv([['LI2BUNDLE', '1'], ['original_sha256', digest(original)],
            ['qualification_complete', 'false'], ['consumer_action', 'RuntimeScan-while-gated-until-qualified'],
            *[['file', name, str(len(raw)), digest(raw)] for name, raw in sorted(files.items())
              if name != 'bundle-index.tsv']])
    files['COMPLETE'] = tsv([['LI2DISASSEMBLY-DIRECTORY', '1'], ['profile', IMPORTER],
        ['observed_original_sha256', digest(original)], ['candidate_complete', 'true' if code == 0 else 'false'],
        ['qualification_complete', 'false'],
        *[['file', name, str(len(raw)), digest(raw)] for name, raw in sorted(files.items())]])
    return files


def product_directory(root, files):
    output = root / 'importer/product'
    output.mkdir(parents=True)
    for name, raw in files.items():
        (output / name).write_bytes(raw)
    return output


def checked_fixture(program, files=None, complete=True, preparation=None):
    original, material, default = fixture(program, complete, preparation)
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary); product_directory(root, default if files is None else files)
        reader = A.OutputReader(root)
        try:
            return A.check_product(reader, program, original, material, 0 if complete else 2)
        finally:
            reader.close()


def declaration(program, material, ready=True):
    heads, selected = COUNTS[program]
    return dict(profile=MATERIAL, program=program, adjacent_b2='fallback-two-site-v1',
        adjacent_upper=2, adjacent_lower=1, adjacent_joint=2, neighbor_victims='short-only',
        neighbor_ownership='inherited-t3', pending_selected='full-instruction-ownership',
        qualification_complete=False, importer_verified=False, source_expected_heads=heads,
        source_expected_jumps=selected, roster_checked_heads=heads if ready else None,
        roster_checked_jumps=selected if ready else None,
        status='MATERIALS_READY' if ready else 'MATERIALS_REFUSED', files=material)



def write_json(path, value):
    path.write_bytes(encoded(value))


def closure_fixture(directory, request, command, helper_sha, code, stdout, stderr=b''):
    raw = encoded(request)
    files = {'request.json': raw, 'command.json': encoded(command),
        'stdout.txt': stdout, 'stderr.txt': stderr, 'helper.stdout': b'', 'helper.stderr': b'',
        'parent-closed.json': encoded(dict(wait_returned=True, exit=0 if code == 0 else 1, error=None)),
        'receipt.json': encoded(dict(absence_proof='ECHILD', cleanup_error=None,
            request_sha256=digest(raw), helper_sha256=helper_sha, inputs_unchanged=True,
            exit=code, wall_timeout=False, aborted=None, cleanup_events=[],
            unexpected_descendants=[], stdout_sha256=digest(stdout), stderr_sha256=digest(stderr)))}
    for name, raw in files.items():
        (directory / name).write_bytes(raw)


def capture_frame():
    """Synthetic custody protocol; no source, binary, helper or process is executed."""
    root, capture = Path('/fixture-repo'), Path('/fixture-repo/ignored/capture')
    here = root / 'evaluation/offline-corpus'
    paths = dict(python=str(Path(sys.executable)), helper=str(root / 'tools/unwind-oracle/bounded_command.py'),
                 cargo='/tools/bin/cargo', rustc='/tools/bin/rustc', timeout='/usr/bin/timeout',
                 **{'as': '/usr/bin/as', 'ld': '/usr/bin/ld', 'objdump': '/usr/bin/objdump'})
    memory, pins = {}, {}
    def put(path, raw):
        key = str(path); memory[key] = raw
        return dict(path=key, bytes=len(raw), sha256=digest(raw))
    tools = {name: put(path, ('synthetic tool ' + name).encode()) for name, path in paths.items()}
    env = dict(HOME='/fixture-home', CARGO_HOME='/fixture-cargo',
        PATH='/tools/bin:/usr/bin:/bin', RUSTC='/tools/bin/rustc', RUSTDOC='/tools/bin/rustdoc',
        CARGO_TARGET_DIR=str(root / 'target'), CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4',
        CARGO_NET_OFFLINE='true', CARGO_TERM_COLOR='never', CARGO_PROFILE_RELEASE_OPT_LEVEL='3',
        CARGO_PROFILE_RELEASE_DEBUG='0', CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true',
        CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true', LC_ALL='C', LANG='C',
        PYTHONDONTWRITEBYTECODE='1')
    configurations = {'synthetic': {'state': 'ABSENT'}}
    base = types.SimpleNamespace(__file__=str(here / 'build_whole.py'),
        HELPER_SHA=tools['helper']['sha256'], write=write_json)
    heads = types.SimpleNamespace(__file__=str(here / 'head_capture.py'))
    adapter = types.SimpleNamespace(__file__=str(here / 'disassembly.py'),
        C=types.SimpleNamespace(__file__=str(here / 'corpus.py')),
        T=types.SimpleNamespace(__file__='/fixture-render.py'))
    reproducer = str(here / 'reproduce_whole.py')
    for path in [reproducer, A.__file__, B.__file__, base.__file__, heads.__file__,
                 adapter.__file__, adapter.C.__file__, adapter.T.__file__]:
        put(path, ('synthetic source ' + path).encode())
    def identity(path):
        raw = memory[str(path)]
        return dict(path=str(path), bytes=len(raw), sha256=digest(raw))
    def read(path, expected=None, cap=256 * 1048576):
        key = str(path); raw = memory[key]; pin = identity(path)
        assert len(raw) <= cap and (expected is None or expected == pin)
        assert key not in pins or pins[key] == pin
        pins[key] = pin
        return raw
    base.identity = identity
    base.configuration = mock.Mock(return_value=configurations)
    phases = B.phase_plan(root, capture, tools, here)
    sources = [B.__file__, base.__file__, here / 'layout.ld', root / 'Cargo.toml',
               root / 'Cargo.lock', *(here / (p + '.S') for p in COUNTS)]
    for path in sources:
        if str(path) not in memory:
            put(path, ('synthetic input ' + str(path)).encode())
    inputs = {str(path): identity(path) for path in sources}
    files, results, streams = dict(inputs), {}, {}
    for phase in phases:
        name = phase['name']; directory = capture / name
        results[name] = dict(status='PASS')
        cpu, wall, mib = phase['limits']
        command = dict(argv=[tools['timeout']['path'], '--signal=TERM', '--kill-after=10s',
            str(wall + 10) + 's', tools['python']['path'], '-B', tools['helper']['path'],
            '--request', str(directory / 'request.json'), '--receipt', str(directory / 'receipt.json')],
            env=env, cwd=str(root), parent_seconds=wall + 25, cleanup_seconds=10)
        put(directory / 'command.json', encoded(command))
        put(directory / 'helper.stdout', b'')
        stdout = b'synthetic target or objdump\n'
        if 'product' in phase:
            files[phase['product']] = put(phase['product'], b'synthetic release binary')
            stdout = b'\n'.join(json.dumps(value).encode() for value in [
                dict(reason='compiler-artifact', target=dict(name=phase['product_name'], kind=[phase['product_kind']]),
                     executable=phase['product'], profile=dict(B.PROFILE)),
                dict(reason='build-finished', success=True)]) + b'\n'
        for path in phase.get('outputs', []):
            files[path] = put(path, b'synthetic captured output')
        streams[name] = dict(stdout=stdout, stderr=b'')
    plan = dict(B.labels(), qualification_complete=False, revision='a' * 40, env=env,
        tools=tools, phases=phases, inputs=inputs, configurations=configurations, configuration_complete=True)
    closed = dict(B.labels(), qualification_complete=False, revision='a' * 40, results=results,
        files=files, configuration_complete=True)
    args = types.SimpleNamespace(capture=capture, capture_sha256=digest(encoded(closed)))
    put(capture / 'planned.json', encoded(plan)); put(capture / 'closed.json', encoded(closed))
    def checked_closed(directory, request, recorded):
        phase = next(p for p in phases if p['name'] == directory.name)
        cpu, wall, mib = phase['limits']
        assert request == dict(argv=phase['argv'], cwd=str(root), env=env,
            stdout=str(directory / 'stdout.txt'), stderr=str(directory / 'stderr.txt'),
            cpu_seconds=cpu, wall_seconds=wall, file_bytes=mib * 1048576)
        assert recorded == closed['results'][directory.name]
        return 0, streams[directory.name]
    ctx = types.SimpleNamespace(ROOT=root, HERE=here, B=base, H=heads, D=adapter,
        PINS=pins, read=read, closed=mock.Mock(side_effect=checked_closed), load=mock.Mock(return_value=B),
        reproducer_file=reproducer)
    def git(argv, **keywords):
        assert argv[:3] == ['/usr/bin/git', '-C', str(root)]
        tail = argv[3:]
        if tail == ['rev-parse', 'HEAD']:
            return b'a' * 40 + b'\n'
        if tail == ['show', 'a' * 40 + ':evaluation/offline-corpus/reproduce_whole.py']:
            return memory[reproducer]
        assert tail[:2] == ['diff', '--binary']
        return b''
    def refresh():
        memory[str(capture / 'planned.json')] = encoded(plan)
        memory[str(capture / 'closed.json')] = encoded(closed)
        args.capture_sha256 = digest(encoded(closed))
    return types.SimpleNamespace(ctx=ctx, args=args, plan=plan, closed=closed, memory=memory,
        streams=streams, git=git, refresh=refresh)


def program_frame(root, mode='complete'):
    capture, output, here = root / 'capture', root / 'output', root / 'source'
    output.mkdir()
    material_calls, dispatches = [], []
    originals, materials, products, memory, captured_files, streams = {}, {}, {}, {}, {}, {'target': {'stdout': b'target'}}
    for program in COUNTS:
        originals[program], materials[program], products[program] = fixture(program, complete=mode != 'refused')
        for path, raw in [(capture / program / 'original', originals[program]),
                          (capture / program / 'subject.o', b'object'),
                          (here / (program + '.S'), b'source'), (here / 'layout.ld', b'linker')]:
            memory[str(path)] = raw
            captured_files[str(path)] = dict(bytes=len(raw), sha256=digest(raw))
        for suffix in ('as', 'ld', 'disassemble-_start', 'disassemble-kernel', 'disassemble-null_hook'):
            streams[program + '-' + suffix] = {'stdout': b'objdump'}
    def read(path, pin, cap):
        raw = memory[str(path)]
        assert len(raw) <= cap and pin == dict(bytes=len(raw), sha256=digest(raw))
        return raw
    def material_attempt(program, inputs, expected, **keywords):
        assert keywords == dict(upper=2, lower=1, joint=2)
        assert expected == {key: digest(raw) for key, raw in inputs.items()}
        material_calls.append(program)
        return declaration(program, materials[program], ready=mode != 'material-refused')
    ctx = types.SimpleNamespace(ROOT=root, HERE=here, read=read,
        B=types.SimpleNamespace(write=write_json, HELPER_SHA='c' * 64),
        H=types.SimpleNamespace(SYMBOLS={'start': '_start', 'kernel': 'kernel', 'hook': 'null_hook'},
                               capture=mock.Mock(return_value=b'synthetic full head transport')),
        D=types.SimpleNamespace(CAP=1048576, attempt_adjacent_b2=mock.Mock(side_effect=material_attempt)))
    args = types.SimpleNamespace(capture=capture, output=output)
    tools = {name: {'path': '/tool/' + name} for name in ('python', 'helper', 'timeout')}
    captured = dict(streams=streams, captured={'files': captured_files}, stable=mock.Mock(),
                    binary=root / 'target/release/examples/adjacent_b2_disassembly_sites', env={'LC_ALL': 'C'}, tools=tools)
    def invoke(context, directory, argv, env, actual_tools):
        program = directory.parent.name
        assert context is ctx and actual_tools == tools and env == captured['env']
        assert argv == [str(captured['binary']), str(capture / program / 'original'),
            str(output / program / 'ledger.txt'), digest(materials[program]['ledger.txt']),
            str(output / program / 'policy.txt'), digest(materials[program]['policy.txt']),
            str(output / program / 'importer/product')]
        dispatches.append(program)
        code = 2 if mode == 'refused' else 0
        stdout = (f'profile={IMPORTER} candidate_complete={"false" if code else "true"} qualification_complete=false\n').encode()
        request, command = {'argv': argv}, {'supervisor': 'synthetic'}
        closure_fixture(directory, request, command, ctx.B.HELPER_SHA, code, stdout)
        product_directory(directory.parent, products[program])
        return request, command
    return types.SimpleNamespace(ctx=ctx, args=args, captured=captured, invoke=invoke,
        material_calls=material_calls, dispatches=dispatches, products=products)


def retained_run_frame(root, second_refusal=False, mutate_after_second=None, mutate_before_second=None):
    """Actual run/program/collector path; only capture and child production are fabricated."""
    ignored = root / 'ignored'; ignored.mkdir()
    frame = program_frame(ignored)
    frame.args.output.rmdir()  # run itself must create the new complete-attempt directory.
    frame.args.capture.mkdir()
    frame.args.capture_sha256 = 'a' * 64
    frame.ctx.ROOT = root
    frame.ctx.PINS = {}
    frame.captured['plan'] = {'synthetic': True}
    if second_refusal:
        frame.products['rle-roundtrip'] = fixture('rle-roundtrip', False)[2]
    readers, saved = {}, {}
    original_adopt, original_product, original_attempt = A.OutputCustody.adopt, A.check_product, A.program_attempt
    def adopt(owner, program, row, reader):
        original_adopt(owner, program, row, reader)
        readers[program] = reader
        saved[program] = copy.deepcopy({key: row[key] for key in
                                      ('output_files', 'output_directories', 'output_read_bytes')})
    def authenticated(context, args, report):
        assert context is frame.ctx and args is frame.args
        report['configuration_complete'] = True
        return frame.captured
    def invoke(*args):
        request, command = frame.invoke(*args)
        if second_refusal and args[1].parent.name == 'rle-roundtrip':
            stdout = (f'profile={IMPORTER} candidate_complete=false qualification_complete=false\n').encode()
            closure_fixture(args[1], request, command, frame.ctx.B.HELPER_SHA, 2, stdout)
        return request, command
    def product(reader, program, *args):
        result = original_product(reader, program, *args)
        if program == 'rle-roundtrip' and mutate_after_second is not None:
            mutate_after_second(frame.args.output / 'checksum')
        return result
    def attempt(context, args, captured, program, row):
        original_attempt(context, args, captured, program, row)
        if program == 'checksum' and mutate_before_second is not None:
            mutate_before_second(frame.args.output / 'checksum')
    with mock.patch.object(A, 'authenticate_capture', side_effect=authenticated), \
         mock.patch.object(A, 'invoke', side_effect=invoke), \
         mock.patch.object(A, 'check_product', side_effect=product), \
         mock.patch.object(A, 'program_attempt', side_effect=attempt), \
         mock.patch.object(A.OutputCustody, 'adopt', adopt):
        code = A.run(frame.args, frame.ctx)
    report = json.loads((frame.args.output / 'closed.json').read_bytes())
    return frame, code, report, readers, saved


def initially_incomplete_run_frame(root, kind, mutate_retained=None):
    """Initial bad publication, then optional mutation after its bounded snapshot."""
    original_frame, original_adopt = program_frame, A.OutputCustody.adopt
    def frame_factory(*args, **kwargs):
        frame = original_frame(*args, **kwargs)
        files = frame.products['checksum']
        if kind == 'members':
            for index in range(257 - len(files)):
                files[f'excess-{index:04}.txt'] = b''
            assert len(files) == 257
        elif kind == 'name':
            files['bad name'] = b'initial invalid member'
        else:
            raise AssertionError('unknown prospective initial refusal')
        return frame
    def adopt(owner, program, row, reader):
        original_adopt(owner, program, row, reader)
        if program == 'checksum' and mutate_retained is not None:
            mutate_retained(reader.root)
    with mock.patch.dict(globals(), {'program_frame': frame_factory}), \
         mock.patch.object(A.OutputCustody, 'adopt', adopt):
        return retained_run_frame(root)

class DiagnosticControls(unittest.TestCase):
    def test_d01_material_accepts_exact_existing_broad_permits_and_rejects_mutants(self):
        source = R.load('disassembly_controls.py', 'f0d7f5572017fcc8a8f14c59e2980e97e50359e7d165c2b748de99439d93346d')
        for short in (False, True):
            for program, counts in COUNTS.items():
                inputs = source.fixture(program, short_jumps=short)
                result = R.D.attempt_adjacent_b2(program, inputs,
                    {key: digest(value) for key, value in inputs.items()}, upper=2, lower=1, joint=2)
                self.assertEqual(result['status'], 'MATERIALS_READY')
                selected = A.check_material(program, result, result['files'], inputs['original'])
                self.assertEqual(len(selected), counts[1])
                policy = result['files']['policy.txt'].decode('ascii').splitlines()
                for index, row in enumerate(policy):
                    if not row.startswith('allocation '):
                        continue
                    cells = row.split(' ')
                    self.assertEqual(cells[4:], ['1', '4096', '4546560:172032', '4726784:2146951168'])
                    alternatives = [cells[:6] + [cells[6]], cells + [cells[7]],
                        cells[:6] + list(reversed(cells[6:])),
                        cells[:6] + ['4546560:176128', cells[7]],
                        cells[:6] + [cells[6], '4722688:2146955264'],
                        cells[:4] + ['2'] + cells[5:],
                        cells[:5] + ['8192'] + cells[6:]]
                    for changed in alternatives:
                        bad = list(policy); bad[index] = ' '.join(changed)
                        material = dict(result['files'], **{'policy.txt': ('\n'.join(bad) + '\n').encode()})
                        with self.assertRaises(A.Failure) as failure:
                            A.check_material(program, result, material, inputs['original'])
                        self.assertEqual(failure.exception.stage, 'material')

    def test_d01_root_membership_rechecks_have_independent_directory_offsets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'a.txt').write_bytes(b'a')
            (root / 'sub').mkdir()
            (root / 'sub/nested.txt').write_bytes(b'n')
            reader = A.OutputReader(root)
            try:
                reader.read('a.txt', 1)
                for _ in range(3):
                    self.assertEqual(reader.names(''), ['a.txt', 'sub'])
                    self.assertEqual(reader.names('sub'), ['nested.txt'])
                retained = reader.seal()
                reader.verify_retained(retained)
                reader.verify_retained(retained)
                self.assertEqual(reader.used, 1)
                (root / 'added.txt').write_bytes(b'later mutation')
                with self.assertRaises(A.Failure) as failure:
                    reader.verify_retained(retained)
                self.assertEqual(failure.exception.stage, 'output-identity')
            finally:
                reader.close()

    def test_d01_c01_fixed_capture_and_release_provenance(self):
        self.assertEqual(A.COUNTS, COUNTS)
        self.assertEqual((A.PROFILE, A.IMPORTER, A.CAPTURE, A.OUTPUT_BYTES, A.FILE_BYTES),
            (MATERIAL, IMPORTER, 'offline-whole-capture-adjacent-b2-u2-l1-j2-v1', 64 * 1048576, 16 * 1048576))
        tools = {name: {'path': '/tool/bin/' + name} for name in ('cargo', 'as', 'ld', 'objdump')}
        phases = B.phase_plan(Path('/repo'), Path('/capture'), tools, Path('/repo/evaluation/offline-corpus'))
        self.assertEqual(len(phases), 13)
        self.assertEqual([p['name'] for p in phases[:3]],
            ['build-adjacent_b2_disassembly_sites', 'build-elf-exec-oracle', 'target'])
        phase = phases[0]
        self.assertEqual(phase['argv'], ['/tool/bin/cargo', 'build', '--release', '--locked', '--offline',
            '--package', 'liteinst-rewrite', '--example', 'adjacent_b2_disassembly_sites', '--message-format=json'])
        self.assertEqual(phase['product'], '/repo/target/release/examples/adjacent_b2_disassembly_sites')
        self.assertEqual([p['limits'] for p in phases], [[120, 180, 128]] * 2 + [[20, 30, 16]] +
            ([[60, 90, 128]] * 2 + [[20, 30, 16]] * 3) * 2)
        artifact = dict(reason='compiler-artifact', target=dict(name=phase['product_name'], kind=['example']),
                        executable=phase['product'], profile=dict(opt_level='3', debuginfo=0,
                        debug_assertions=True, overflow_checks=True, test=False))
        end = dict(reason='build-finished', success=True)
        wire = lambda rows: b'\n'.join(json.dumps(row).encode() for row in rows) + b'\n'
        B.check_artifact(wire([artifact, end]), phase)
        mutants = []
        for key, value in [('executable', '/repo/target/debug/examples/adjacent_b2_disassembly_sites'),
                           ('profile', dict(artifact['profile'], test=True)),
                           ('profile', dict(artifact['profile'], debug_assertions=1)),
                           ('target', dict(name='disassembly_sites', kind=['example'])),
                           ('target', dict(name=phase['product_name'], kind=['bin']))]:
            mutants.append([dict(artifact, **{key: value}), end])
        mutants += [[artifact, artifact, end], [end], [artifact, dict(end, success=1)], [artifact, dict(end, success=False)]]
        for rows in mutants:
            with self.assertRaises(AssertionError):
                B.check_artifact(wire(rows), phase)

    def test_d01_c02_exact_material_and_importer_dispatch(self):
        for program in COUNTS:
            original, material, _ = fixture(program)
            expected = declaration(program, material)
            self.assertEqual(len(A.check_material(program, expected, material, original)), COUNTS[program][1])
            argv = A.importer_arguments(Path('/exact/adjacent'), Path('/capture/original'), Path('/output'), material)
            self.assertEqual(argv, ['/exact/adjacent', '/capture/original', '/output/ledger.txt',
                digest(material['ledger.txt']), '/output/policy.txt', digest(material['policy.txt']), '/output/importer/product'])
            for key, value in [('adjacent_lower', True), ('adjacent_upper', 3), ('profile', 'old'),
                               ('source_expected_jumps', COUNTS[program][1] - 1), ('qualification_complete', True)]:
                with self.assertRaises(A.Failure):
                    A.check_material(program, dict(expected, **{key: value}), material, original)
            for old, new in [(b' 1 4096 ', b' 2 4096 '), (b'2147483648', b'4294967296'),
                             (b'adjacent-b2-budgets 2 1 2', b'adjacent-b2-budgets 2 2 2')]:
                changed = dict(material, **{'policy.txt': material['policy.txt'].replace(old, new)})
                with self.assertRaises(A.Failure):
                    A.check_material(program, expected, changed, original)

    def test_d01_c03_pin_and_capture_label_refusals(self):
        labels = B.labels()
        plan = dict(labels, qualification_complete=False)
        A.check_capture_labels(plan, dict(plan), B)
        for key, value in [('adjacent_lower', True), ('adjacent_joint', 1), ('expected_selected', 41),
                           ('capture_profile', 'old'), ('artifact_complete', True)]:
            with self.assertRaises(A.Failure):
                A.check_capture_labels(dict(plan, **{key: value}), plan, B)
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(R, 'HERE', Path(temporary)):
            path = Path(temporary) / 'adjacent_whole.py'
            for raw in (b'raise RuntimeError("must not execute")\n', b'x' * (1048576 + 1)):
                path.write_bytes(raw)
                with mock.patch.object(R, 'compile', create=True) as compile_source, self.assertRaises(AssertionError):
                    R.load('adjacent_whole.py', 'a0da09ee3a65668a08e3dc0421dab36bfba4ae6a081f90318d736955680f081e')
                compile_source.assert_not_called()

    def test_d01_c04_complete_input_roster_population(self):
        for program, (heads, selected) in COUNTS.items():
            _, material, _ = fixture(program)
            self.assertEqual(len(A.selected_rows(program, material)), selected)
            records = material['source-inventory.tsv'].splitlines(keepends=True)
            for changed in (b''.join(records[:-1]), b''.join(records + records[-1:]),
                            b''.join([records[0], records[2], records[1], *records[3:]]),
                            material['source-inventory.tsv'].replace(b'start\t0\t', b'start\t1\t', 1)):
                with self.assertRaises(A.Failure):
                    A.selected_rows(program, dict(material, **{'source-inventory.tsv': changed}))
            refused = declaration(program, {}, False)
            refused['failure'] = dict(stage='policy', error='ValueError')
            self.assertIsNone(A.check_material(program, refused, {}, b'original'))
            self.assertEqual((refused['source_expected_heads'], refused['source_expected_jumps']), (heads, selected))

    def test_d01_c05_closed_receipt_and_command(self):
        request = dict(argv=['/producer'], cwd='/repo', env={}, stdout='/out/stdout', stderr='/out/stderr',
                       cpu_seconds=20, wall_seconds=30, file_bytes=16 * 1048576)
        command = dict(argv=['/helper'], cwd='/repo', env={}, parent_seconds=55, cleanup_seconds=10)
        stdout = f'profile={IMPORTER} candidate_complete=false qualification_complete=false\n'.encode()
        for mutation in (None, 'absence_proof', 'inputs_unchanged', 'stream', 'command', 'wall_timeout', 'parent'):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); (root / 'importer').mkdir()
                receipt = dict(absence_proof='ECHILD', cleanup_error=None, helper_sha256='a' * 64,
                    inputs_unchanged=True, request_sha256=digest(encoded(request)), exit=2, wall_timeout=False,
                    aborted=None, cleanup_events=[], unexpected_descendants=[], stdout_sha256=digest(stdout),
                    stderr_sha256=digest(b''))
                parent = dict(wait_returned=True, error=None, exit=1)
                if mutation == 'absence_proof': receipt['absence_proof'] = 'unknown'
                if mutation == 'inputs_unchanged': receipt['inputs_unchanged'] = False
                if mutation == 'wall_timeout': receipt['wall_timeout'] = True
                if mutation == 'parent': parent['wait_returned'] = False
                files = {'request.json': encoded(request), 'command.json': encoded(command),
                    'receipt.json': encoded(receipt), 'parent-closed.json': encoded(parent),
                    'stdout.txt': stdout, 'stderr.txt': b'', 'helper.stdout': b'', 'helper.stderr': b''}
                if mutation == 'stream': files['stdout.txt'] += b'changed'
                if mutation == 'command': files['command.json'] = encoded(dict(command, parent_seconds=56))
                for name, raw in files.items(): (root / 'importer' / name).write_bytes(raw)
                reader = A.OutputReader(root)
                try:
                    if mutation:
                        with self.assertRaises(A.Failure): A.check_closed(reader, request, 'a' * 64, command)
                    else:
                        code, streams = A.check_closed(reader, request, 'a' * 64, command)
                        self.assertEqual(code, 2)
                        self.assertEqual(streams['stdout']['data'], stdout)
                finally: reader.close()

    def test_d01_c06_exact_read_caps_and_no_follow(self):
        self.assertEqual(A.OUTPUT_BYTES, 67108864)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            block = bytes(16 * 1048576)
            for index in range(4): (root / str(index)).write_bytes(block)
            (root / 'over').write_bytes(b'x')
            reader = A.OutputReader(root)
            try:
                for index in range(4): reader.read(str(index))
                self.assertEqual(reader.used, 64 * 1048576)
                with self.assertRaises(A.Failure): reader.read('over')
                self.assertEqual(reader.used, 64 * 1048576)
                reader.read('0')
                self.assertEqual(reader.used, 64 * 1048576)
                with self.assertRaises(A.Failure): reader.read('0', 1048576)
            finally: reader.close()
            (root / 'large').write_bytes(block + b'x')
            (root / 'link').symlink_to(root / '0')
            (root / 'directory').mkdir()
            reader = A.OutputReader(root)
            try:
                for name in ('large', 'link', 'directory', '../0'):
                    with self.assertRaises((A.Failure, OSError)): reader.read(name)
                self.assertEqual(reader.used, 0)
                reader.read('over')
                (root / 'over').write_bytes(b'changed')
                with self.assertRaises(A.Failure): reader.verify()
            finally: reader.close()

    def test_d01_c06_member_and_stricter_caps(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); directory = root / 'members'; directory.mkdir()
            for index in range(256):
                (directory / str(index)).write_bytes(b'')
            reader = A.OutputReader(root)
            try:
                self.assertEqual(len(reader.names('members')), 256)
            finally:
                reader.close()
            (directory / 'extra').write_bytes(b'')
            reader = A.OutputReader(root)
            try:
                with self.assertRaises(A.Failure): reader.names('members')
                self.assertEqual(reader.used, 0)
            finally:
                reader.close()
        for name, cap in [('COMPLETE', 1048576), ('candidate.elf', 2097152)]:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); (root / name).write_bytes(b'x' * (cap + 1))
                reader = A.OutputReader(root)
                try:
                    with self.assertRaises(A.Failure): reader.read(name, cap)
                    self.assertEqual(reader.used, 0)
                finally:
                    reader.close()

    def test_d01_c07_canonical_index_rows(self):
        prefix = [['INDEX', '1']]
        good = [['file', 'a', '0', digest(b'')], ['file', 'b', '1', digest(b'x')]]
        self.assertEqual(list(A.index_rows(tsv(prefix + good), prefix)), ['a', 'b'])
        variants = [list(reversed(good)), good + good[:1],
            [['file', '../x', '0', digest(b'')]], [['file', '.', '0', digest(b'')]],
            [['file', 'a', '00', digest(b'')]], [['file', 'a', '-1', digest(b'')]],
            [['file', 'a', '0', 'A' * 64]], [['file', 'a', '0', '0' * 63]]]
        for rows in variants:
            with self.assertRaises(A.Failure): A.index_rows(tsv(prefix + rows), prefix)
        with self.assertRaises(A.Failure): A.json_value(b'{"a":1,"a":2}')

    def test_d01_c07_exact_actual_and_nested_membership(self):
        for program in COUNTS:
            original, _, files = fixture(program)
            result = checked_fixture(program)
            self.assertTrue(result['producer_roster_join'])
            self.assertTrue(result['producer_candidate_complete'])
            variants = [dict(files, extra=b'unknown'),
                        {k: v for k, v in files.items() if k != 'site-1.diagnostics.txt'},
                        {k: v for k, v in files.items() if k != 'candidate.elf'}]
            for changed in variants:
                with self.assertRaises((A.Failure, KeyError)): checked_fixture(program, indexed(changed, original, 0))
            changed = dict(files); changed['candidate.elf'] += b'changed'
            with self.assertRaises(A.Failure): checked_fixture(program, changed)
            changed = dict(files); changed['bundle-index.tsv'] += b'file\tunknown\t0\t' + b'0' * 64 + b'\n'
            changed.pop('COMPLETE')
            changed['COMPLETE'] = tsv([['LI2DISASSEMBLY-DIRECTORY', '1'], ['profile', IMPORTER],
                ['observed_original_sha256', digest(original)], ['candidate_complete', 'true'],
                ['qualification_complete', 'false'],
                *[['file', k, str(len(v)), digest(v)] for k, v in sorted(changed.items())]])
            with self.assertRaises(A.Failure): checked_fixture(program, changed)

    def test_d01_c08_exact_normal_response(self):
        for code in (0, 2):
            raw = f'profile={IMPORTER} candidate_complete={"true" if code == 0 else "false"} qualification_complete=false\n'.encode()
            A.check_stdout(raw, b'', code)
            for changed, stderr, status in [(raw + b'\n', b'', code), (raw.replace(b'false', b'true'), b'x', code),
                                          (raw, b'x', code), (raw, b'', 1), (raw, b'', -9),
                                          (raw.replace(IMPORTER.encode(), b'old'), b'', code)]:
                with self.assertRaises(A.Failure): A.check_stdout(changed, stderr, status)

    def test_d01_c09_every_output_roster(self):
        for program in COUNTS:
            original, _, files = fixture(program)
            for name, header in [('disassembly-inventory.tsv', b'id\tpc\tlength'),
                                 ('report.tsv', b'site\tpc\tfile_offset')]:
                rows = files[name].splitlines(keepends=True)
                at = next(i for i, row in enumerate(rows) if row.startswith(header)) + 1
                for mutation in ('drop', 'duplicate', 'reorder', 0, 1, 2, 3):
                    changed = list(rows)
                    if mutation == 'drop': del changed[at]
                    if mutation == 'duplicate': changed.append(changed[-1])
                    if type(mutation) is int:
                        cells = changed[at].split(b'\t'); cells[mutation] = b'999999'; changed[at] = b'\t'.join(cells)
                    if mutation == 'reorder': changed[at], changed[at + 1] = changed[at + 1], changed[at]
                    altered = dict(files, **{name: b''.join(changed)})
                    with self.assertRaises(A.Failure): checked_fixture(program, indexed(altered, original, 0))
            selected = files['selection.txt'].splitlines(keepends=True)
            at = next(i for i, row in enumerate(selected) if row.startswith(b'site '))
            for field in (1, 2, 3, 4):
                changed = list(selected); cells = changed[at].split(b' ')
                cells[field] = b'999999'; changed[at] = b' '.join(cells)
                altered = dict(files, **{'selection.txt': b''.join(changed)})
                with self.assertRaises(A.Failure): checked_fixture(program, indexed(altered, original, 0))

    def test_d01_c10_identity_and_scalar_prefix(self):
        for program in COUNTS:
            original, _, files = fixture(program)
            for name, old, new in [('planning-profile.tsv', b'adjacent_lower\t1', b'adjacent_lower\t2'),
                ('disassembly-policy.txt', b'2 1 2', b'2 2 2'),
                ('adjacent-b2-evidence.txt', b'pair_calls\t0', b'pair_calls\t1'),
                ('adjacent-b2-evidence.txt', b'adjacent_counts\t0\t0\t0', b'adjacent_counts\t1\t1\t1'),
                ('adjacent-b2-evidence.txt', b'classification_complete\tfalse', b'classification_complete\ttrue'),
                ('adjacent-b2-evidence.txt', b'combined_image_work_upper_bound\t0', b'combined_image_work_upper_bound\t1')]:
                changed = dict(files, **{name: files[name].replace(old, new)})
                if old == b'pair_calls\t0':
                    changed[name] = changed[name].replace(b'pair_calls\t1', b'pair_calls\t999')
                with self.assertRaises(A.Failure): checked_fixture(program, indexed(changed, original, 0))
            for old, new in [(b'selected_count\t' + str(COUNTS[program][1]).encode(), b'selected_count\t0'),
                (b'baseline_calls\t' + str(COUNTS[program][1]).encode(), b'baseline_calls\t0'),
                (b'adjacent_counts\t0\t0\t0', b'adjacent_counts\t01\t0\t0'),
                (b'adjacent_counts\t0\t0\t0', b'adjacent_counts\t-1\t0\t0'),
                (b'legacy_image_slots\t0', b'legacy_image_slots\t18446744073709551616'),
                (b'qualification_complete\tfalse', b'qualification_complete\ttrue')]:
                changed = dict(files, **{'adjacent-b2-evidence.txt': files['adjacent-b2-evidence.txt'].replace(old, new)})
                with self.assertRaises(A.Failure): checked_fixture(program, indexed(changed, original, 0))
            for name in ('planning-profile.tsv', 'disassembly-inventory.tsv', 'selection.txt', 'report.tsv'):
                changed = dict(files, **{name: files[name].replace(digest(original).encode(), b'0' * 64)})
                with self.assertRaises(A.Failure): checked_fixture(program, indexed(changed, original, 0))
            self.assertFalse(checked_fixture(program)['scalar_evidence']['debug_association_verified'])

    def test_d01_c11_all_refusal_shapes(self):
        for program in COUNTS:
            result = checked_fixture(program, complete=False)
            self.assertFalse(result['producer_candidate_complete'])
            self.assertTrue(result['producer_roster_join'])
            for stage in (0, 1, 2):
                result = checked_fixture(program, complete=False, preparation=stage)
                self.assertFalse(result['producer_candidate_complete'])
                self.assertFalse(result['producer_roster_join'])
                self.assertTrue(result['preparation_failure'])
            original, _, files = fixture(program, False)
            for name in ('candidate.elf', 'source.li2sparse', 'plan-ledger.tsv', 'image-0000.bin'):
                changed = indexed(dict(files, **{name: b'partial'}), original, 2)
                with self.assertRaises(A.Failure): checked_fixture(program, changed, complete=False)

    def test_d01_c12_continuation_and_global_abort(self):
        for global_failure in (False, True):
            report = A.summary(); seen = []
            def action(program, row):
                seen.append(program)
                if program == 'checksum':
                    kind = A.CustodyFailure if global_failure else A.Failure
                    raise kind('injected', 'failure')
                row.update(status='PRODUCER_COMPLETE_UNVERIFIED', producer_candidate_complete=True,
                           diagnostic_capture_complete=True)
            A.drive_programs(report, action)
            self.assertEqual(seen, ['checksum'] if global_failure else ['checksum', 'rle-roundtrip'])
            self.assertEqual((report['expected_programs'], report['expected_heads'], report['expected_selected']), (2, 187, 42))
            self.assertEqual(set(report['programs']), set(COUNTS))
            if global_failure:
                self.assertEqual(report['programs']['rle-roundtrip']['status'], 'UNRUN')
                self.assertIn('blocked_by', report['programs']['rle-roundtrip'])
            self.assertEqual(A.finish(report), 1)

    def test_d01_c13_later_failure_no_retry_or_subset(self):
        report = A.summary(); calls = []
        def action(program, row):
            calls.append(program)
            row['producer_dispatches'] += 1
            if program == 'rle-roundtrip': raise A.Failure('later', 'refused')
            row.update(status='PRODUCER_COMPLETE_UNVERIFIED', producer_candidate_complete=True,
                       diagnostic_capture_complete=True)
        A.drive_programs(report, action)
        self.assertEqual(calls, list(COUNTS))
        self.assertEqual([row['producer_dispatches'] for row in report['programs'].values()], [1, 1])
        self.assertTrue(report['programs']['checksum']['producer_candidate_complete'])
        self.assertEqual(A.finish(report), 1)
        self.assertEqual(sum(row['expected_selected'] for row in report['programs'].values()), 42)

    def test_d01_c14_only_unverified_diagnostic_zero(self):
        for configuration in (False, True):
            report = A.summary(); report['configuration_complete'] = configuration
            for row in report['programs'].values():
                row.update(status='PRODUCER_COMPLETE_UNVERIFIED', producer_candidate_complete=True,
                           diagnostic_capture_complete=True)
            self.assertEqual(A.finish(report), 0 if configuration else 2)
            self.assertEqual(report['deferred_checks'], {'W01': 'NOT_EVALUATED', 'N01': 'NOT_EVALUATED'})
            for row in [report, *report['programs'].values()]:
                self.assertTrue(all(row[key] is False for key in A.FALSE_FLAGS))
        report['programs']['rle-roundtrip'].update(status='PRODUCER_REFUSED', producer_candidate_complete=False)
        self.assertEqual(A.finish(report), 1)
        self.assertTrue(report['diagnostic_capture_complete'])

    def test_d01_c15_partial_and_unsafe_retention(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); product = product_directory(root, {'partial.txt': b'bounded evidence'})
            reader = A.OutputReader(root)
            try:
                A.collect_partial(reader)
                self.assertEqual(reader.pins()['importer/product/partial.txt']['sha256'], digest(b'bounded evidence'))
            finally: reader.close()
            (product / 'unsafe').symlink_to(root / 'outside')
            reader = A.OutputReader(root)
            try:
                with self.assertRaises(OSError): A.collect_partial(reader)
            finally: reader.close()
        original, _, files = fixture('checksum')
        with self.assertRaises(A.Failure):
            checked_fixture('checksum', {k: v for k, v in files.items() if k != 'COMPLETE'})

    def test_d01_c16_protocol_fixtures_never_claim_real_artifacts(self):
        for program in COUNTS:
            original, material, files = fixture(program)
            self.assertEqual(files['candidate.elf'], b'opaque candidate')
            self.assertEqual(files['metadata.li2meta'], b'opaque metadata')
            result = checked_fixture(program)
            self.assertFalse(result['independent_image_associations_verified'])
            row = A.program_row(program); row.update(result)
            self.assertTrue(all(row[key] is False for key in A.FALSE_FLAGS))
            self.assertEqual(row['deferred_checks'], {'W01': 'NOT_EVALUATED', 'N01': 'NOT_EVALUATED'})
        # Real F02/F07/F24 positives and all inherited controls are separate required gates.


    def test_d01_c03_complete_capture_authentication_path(self):
        frame = capture_frame(); report = A.summary()
        with mock.patch.object(A.subprocess, 'check_output', side_effect=frame.git) as git:
            captured = A.authenticate_capture(frame.ctx, frame.args, report)
        frame.ctx.load.assert_called_once_with('build_adjacent_whole.py', '0def6474c15584dd168b74c2338311caa53d1864ab01d5805cb3a05c62960592')
        self.assertEqual(frame.ctx.closed.call_count, 13)
        self.assertEqual(captured['binary'], Path('/fixture-repo/target/release/examples/adjacent_b2_disassembly_sites'))
        self.assertTrue(report['configuration_complete'])
        self.assertEqual(report['expected_selected'], 42)
        self.assertTrue(all(report[key] is False for key in A.FALSE_FLAGS))
        self.assertGreater(git.call_count, 4)
        mutations = [
            lambda f: f.plan.update(adjacent_upper=3),
            lambda f: f.plan['env'].update(EXTRA='not permitted'),
            lambda f: f.plan['phases'][0]['argv'].append('--features=alternate'),
            lambda f: f.closed['results'].pop('target'),
            lambda f: f.closed['results']['build-elf-exec-oracle'].update(status='FAILED'),
            lambda f: f.closed['files'].update({'/extra': {'bytes': 0, 'sha256': digest(b'')}}),
            lambda f: f.plan['inputs'].pop(next(iter(f.plan['inputs']))),
            lambda f: f.closed.update(configuration_complete=False),
            lambda f: f.memory.update({str(f.args.capture / 'build-adjacent_b2_disassembly_sites/command.json'):
                encoded(dict(argv=['wrong'], env={}, cwd='/wrong'))}),
        ]
        for mutate in mutations:
            frame = capture_frame(); mutate(frame); frame.refresh()
            with mock.patch.object(A.subprocess, 'check_output', side_effect=frame.git), self.assertRaises((A.Failure, AssertionError)):
                A.authenticate_capture(frame.ctx, frame.args, A.summary())
        frame = capture_frame(); frame.args.capture_sha256 = '0' * 64
        with mock.patch.object(A.subprocess, 'check_output', side_effect=frame.git) as git, self.assertRaises(A.Failure):
            A.authenticate_capture(frame.ctx, frame.args, A.summary())
        git.assert_not_called()
        frame = capture_frame()
        with mock.patch.object(A.subprocess, 'check_output', side_effect=frame.git):
            captured = A.authenticate_capture(frame.ctx, frame.args, A.summary())
            frame.memory[frame.ctx.reproducer_file] += b'changed'
            with self.assertRaises(A.CustodyFailure):
                captured['stable']()

    def test_d01_c03_failed_capture_phase_also_requires_proven_closure(self):
        frame = capture_frame()
        failed = 'checksum-disassemble-kernel'
        frame.closed['results'][failed]['status'] = 'FAILED'; frame.refresh()
        original_closed = frame.ctx.closed.side_effect
        def closed(directory, request, recorded):
            code, streams = original_closed(directory, request, recorded)
            return (1 if directory.name == failed else code), streams
        frame.ctx.closed.side_effect = closed
        with mock.patch.object(A.subprocess, 'check_output', side_effect=frame.git):
            captured = A.authenticate_capture(frame.ctx, frame.args, A.summary())
        self.assertEqual(frame.ctx.closed.call_count, 13)
        self.assertNotIn(failed, captured['streams'])
        frame = capture_frame()
        frame.closed['results'][failed]['status'] = 'FAILED'; frame.refresh()
        original_closed = frame.ctx.closed.side_effect
        def uncertain(directory, request, recorded):
            if directory.name == failed:
                raise AssertionError('missing ECHILD for FAILED phase')
            return original_closed(directory, request, recorded)
        frame.ctx.closed.side_effect = uncertain
        with mock.patch.object(A.subprocess, 'check_output', side_effect=frame.git), self.assertRaises(AssertionError):
            A.authenticate_capture(frame.ctx, frame.args, A.summary())

    def test_d01_c04_actual_program_driver_fixed_once_both_programs(self):
        # Protocol-only positives exercise collection and dispatch; they do not
        # count as the unchanged real F02/F07/F24 frontend positives.
        for mode, status, dispatches in [('complete', 'PRODUCER_COMPLETE_UNVERIFIED', 2),
                                         ('refused', 'PRODUCER_REFUSED', 2),
                                         ('material-refused', 'MATERIALS_REFUSED', 0)]:
            with tempfile.TemporaryDirectory() as temporary:
                frame = program_frame(Path(temporary), mode); report = A.summary()
                with mock.patch.object(A, 'invoke', side_effect=frame.invoke):
                    A.drive_programs(report, lambda program, row:
                        A.program_attempt(frame.ctx, frame.args, frame.captured, program, row))
                self.assertEqual(frame.material_calls, ['checksum', 'rle-roundtrip'])
                self.assertEqual(frame.ctx.D.attempt_adjacent_b2.call_count, 2)
                self.assertEqual(len(frame.dispatches), dispatches)
                self.assertEqual([r['status'] for r in report['programs'].values()], [status, status])
                for program, row in report['programs'].items():
                    self.assertEqual(row['material_calls'], 1)
                    self.assertEqual(row['producer_dispatches'], int(dispatches != 0))
                    self.assertTrue(row['diagnostic_capture_complete'])
                    self.assertLessEqual(row['output_read_bytes'], 64 * 1048576)
                    self.assertEqual(row['expected_heads'], COUNTS[program][0])
                    self.assertEqual(row['expected_selected'], COUNTS[program][1])
                    self.assertTrue(all(row[key] is False for key in A.FALSE_FLAGS))
                    self.assertEqual((frame.args.output / program / 'ledger.txt').read_bytes(),
                                     fixture(program)[1]['ledger.txt'])

    def test_d01_c05_real_driver_uncertain_closure_aborts_later_program(self):
        with tempfile.TemporaryDirectory() as temporary:
            frame = program_frame(Path(temporary)); report = A.summary()
            def unclosed(*args):
                result = frame.invoke(*args); path = args[1] / 'receipt.json'
                receipt = json.loads(path.read_bytes()); receipt['absence_proof'] = 'missing'
                write_json(path, receipt)
                return result
            with mock.patch.object(A, 'invoke', side_effect=unclosed):
                A.drive_programs(report, lambda program, row:
                    A.program_attempt(frame.ctx, frame.args, frame.captured, program, row))
            self.assertEqual(frame.dispatches, ['checksum'])
            self.assertEqual(report['programs']['checksum']['status'], 'FAILED')
            self.assertEqual(report['programs']['rle-roundtrip']['status'], 'UNRUN')
            self.assertIn('blocked_by', report['programs']['rle-roundtrip'])
            self.assertEqual((report['expected_heads'], report['expected_selected']), (187, 42))
            self.assertEqual(A.finish(report), 1)

    def test_d01_c06_closed_stream_cap_failure_continues_without_widening(self):
        with tempfile.TemporaryDirectory() as temporary:
            frame = program_frame(Path(temporary)); report = A.summary()
            def oversized(*args):
                result = frame.invoke(*args)
                if args[1].parent.name == 'checksum':
                    request, command = result
                    closure_fixture(args[1], request, command, frame.ctx.B.HELPER_SHA,
                                    0, b'x' * (16 * 1048576 + 1))
                return result
            with mock.patch.object(A, 'invoke', side_effect=oversized):
                A.drive_programs(report, lambda program, row:
                    A.program_attempt(frame.ctx, frame.args, frame.captured, program, row))
            self.assertEqual(frame.dispatches, ['checksum', 'rle-roundtrip'])
            first, second = [report['programs'][p] for p in COUNTS]
            self.assertEqual((first['status'], first['failure']['stage'], first['producer_exit']),
                             ('FAILED', 'output-bound', 0))
            self.assertEqual(second['status'], 'PRODUCER_COMPLETE_UNVERIFIED')
            self.assertNotIn('error', report)
            self.assertEqual(A.finish(report), 1)
            self.assertLessEqual(first['output_read_bytes'], 64 * 1048576)

    def test_d01_c12_real_driver_local_hash_failure_keeps_other_outcome(self):
        with tempfile.TemporaryDirectory() as temporary:
            frame = program_frame(Path(temporary)); report = A.summary()
            frame.products['checksum']['candidate.elf'] += b'unindexed mutation'
            with mock.patch.object(A, 'invoke', side_effect=frame.invoke):
                A.drive_programs(report, lambda program, row:
                    A.program_attempt(frame.ctx, frame.args, frame.captured, program, row))
            self.assertEqual(frame.dispatches, ['checksum', 'rle-roundtrip'])
            self.assertEqual([r['status'] for r in report['programs'].values()],
                             ['FAILED', 'PRODUCER_COMPLETE_UNVERIFIED'])
            self.assertEqual(A.finish(report), 1)
            self.assertTrue(all(r['producer_dispatches'] == 1 for r in report['programs'].values()))

    def test_d01_c05_dispatch_supervisor_exact_bounds_without_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ctx = types.SimpleNamespace(ROOT=root, B=types.SimpleNamespace(write=write_json))
            tools = {name: {'path': '/tool/' + name} for name in ('timeout', 'python', 'helper')}
            env, argv = {'LC_ALL': 'C'}, ['/exact/adjacent', 'a', 'b', 'c', 'd', 'e', 'f']
            child = mock.Mock(returncode=0)
            with mock.patch.object(A.subprocess, 'Popen', return_value=child) as launch:
                request, command = A.invoke(ctx, root, argv, env, tools)
            child.wait.assert_called_once_with(timeout=55)
            self.assertEqual(request, dict(argv=argv, cwd=str(root), env=env,
                stdout=str(root / 'stdout.txt'), stderr=str(root / 'stderr.txt'),
                cpu_seconds=20, wall_seconds=30, file_bytes=16 * 1048576))
            self.assertEqual(command['argv'], ['/tool/timeout', '--signal=TERM', '--kill-after=10s',
                '40s', '/tool/python', '-B', '/tool/helper', '--request', str(root / 'request.json'),
                '--receipt', str(root / 'receipt.json')])
            self.assertEqual(launch.call_args.kwargs['start_new_session'], True)
            self.assertEqual(launch.call_args.kwargs['stdin'], A.subprocess.DEVNULL)
            self.assertEqual(json.loads((root / 'parent-closed.json').read_bytes()),
                             dict(wait_returned=True, exit=0, error=None))
            self.assertEqual((command['parent_seconds'], command['cleanup_seconds']), (55, 10))

    def test_d01_c14_actual_run_closes_both_rows_without_promotion(self):
        for failure in (False, True):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); ignored = root / 'ignored'; ignored.mkdir()
                capture = ignored / 'capture'; capture.mkdir()
                args = types.SimpleNamespace(capture=capture, output=ignored / 'new', capture_sha256='a' * 64)
                ctx = types.SimpleNamespace(ROOT=root, B=types.SimpleNamespace(write=write_json), PINS={})
                stable = mock.Mock()
                def authenticated(context, arguments, report):
                    self.assertIs(context, ctx); self.assertIs(arguments, args)
                    report['configuration_complete'] = True
                    return dict(plan={'synthetic': True}, stable=stable)
                calls = []
                def action(context, arguments, captured, program, row):
                    calls.append(program)
                    row.update(material_calls=1, producer_dispatches=1, producer_exit=0,
                               producer_candidate_complete=True, diagnostic_capture_complete=True)
                    if failure and program == 'rle-roundtrip':
                        raise A.Failure('synthetic-local', 'later failure remains failure')
                    row['status'] = 'PRODUCER_COMPLETE_UNVERIFIED'
                with mock.patch.object(A, 'authenticate_capture', side_effect=authenticated), \
                     mock.patch.object(A, 'program_attempt', side_effect=action):
                    code = A.run(args, ctx)
                self.assertEqual(code, 1 if failure else 0)
                report = json.loads((args.output / 'closed.json').read_bytes())
                self.assertEqual(calls, ['checksum', 'rle-roundtrip'])
                self.assertEqual(set(report['programs']), set(COUNTS))
                self.assertEqual((report['expected_programs'], report['expected_heads'], report['expected_selected']), (2, 187, 42))
                self.assertTrue(all(report[key] is False for key in A.FALSE_FLAGS))
                self.assertEqual(report['deferred_checks'], {'W01': 'NOT_EVALUATED', 'N01': 'NOT_EVALUATED'})
                self.assertEqual(report['diagnostic_status'], 'FAILED_OR_INCOMPLETE' if failure else 'COMPLETE_UNVERIFIED')


    def test_d01_r1_stable_actual_two_program_retention_and_close(self):
        for second_refusal in (False, True):
            with tempfile.TemporaryDirectory() as temporary:
                frame, code, report, readers, saved = retained_run_frame(Path(temporary), second_refusal)
                self.assertEqual(code, 1 if second_refusal else 0)
                self.assertEqual(frame.material_calls, ['checksum', 'rle-roundtrip'])
                self.assertEqual(frame.dispatches, ['checksum', 'rle-roundtrip'])
                self.assertEqual((report['expected_programs'], report['expected_heads'], report['expected_selected']),
                                 (2, 187, 42))
                self.assertTrue(report['retained_output_stability_complete'])
                self.assertTrue(report['diagnostic_capture_complete'])
                self.assertEqual(report['programs']['checksum']['status'], 'PRODUCER_COMPLETE_UNVERIFIED')
                self.assertEqual(report['programs']['rle-roundtrip']['status'],
                                 'PRODUCER_REFUSED' if second_refusal else 'PRODUCER_COMPLETE_UNVERIFIED')
                for program, reader in readers.items():
                    row = report['programs'][program]
                    self.assertEqual(row['output_stability'], 'VERIFIED')
                    self.assertEqual(row['output_files'], saved[program]['output_files'])
                    self.assertEqual(row['output_directories'], saved[program]['output_directories'])
                    self.assertEqual(row['output_read_bytes'], saved[program]['output_read_bytes'])
                    self.assertEqual(reader.used, row['output_read_bytes'])
                    self.assertLessEqual(reader.used, 64 * 1048576)
                    self.assertEqual((row['observed_heads'], row['observed_selected']), COUNTS[program])
                    self.assertEqual((row['material_calls'], row['producer_dispatches']), (1, 1))
                    self.assertTrue(all(row[key] is False for key in A.FALSE_FLAGS))
                    with self.assertRaises(OSError):
                        A.os.fstat(reader.fd)
                self.assertTrue(all(report[key] is False for key in A.FALSE_FLAGS))

    def test_d01_r1_final_mutations_during_second_refusal_preserve_verdicts(self):
        def mutate(root, kind):
            product = root / 'importer/product'
            path = product / 'candidate.elf'
            if kind == 'file':
                path.write_bytes(b'changed after first collection')
            elif kind == 'remove':
                path.unlink()
            elif kind == 'membership':
                (product / 'unexpected.txt').write_bytes(b'added after collection')
            elif kind == 'directory':
                product.rename(product.with_name('saved-product'))
                product.mkdir()
                for name, raw in fixture('checksum')[2].items():
                    (product / name).write_bytes(raw)
            elif kind == 'root-link':
                moved = root.with_name('saved-checksum'); root.rename(moved)
                root.symlink_to(moved, target_is_directory=True)
            else:
                raise AssertionError('unknown prospective mutation')
        for kind in ('file', 'remove', 'membership', 'directory', 'root-link'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                frame, code, report, readers, saved = retained_run_frame(Path(temporary), True,
                    mutate_after_second=lambda root: mutate(root, kind))
                self.assertEqual(code, 1)
                self.assertEqual(frame.material_calls, ['checksum', 'rle-roundtrip'])
                self.assertEqual(frame.dispatches, ['checksum', 'rle-roundtrip'])
                self.assertEqual((report['expected_programs'], report['expected_heads'], report['expected_selected']),
                                 (2, 187, 42))
                first, second = [report['programs'][p] for p in COUNTS]
                self.assertEqual((first['status'], first['producer_exit'], first['producer_candidate_complete']),
                                 ('PRODUCER_COMPLETE_UNVERIFIED', 0, True))
                self.assertEqual((second['status'], second['producer_exit'], second['producer_candidate_complete']),
                                 ('PRODUCER_REFUSED', 2, False))
                self.assertFalse(first['diagnostic_capture_complete'])
                self.assertTrue(second['diagnostic_capture_complete'])
                self.assertFalse(report['diagnostic_capture_complete'])
                self.assertFalse(report['retained_output_stability_complete'])
                self.assertEqual(first['output_stability'], 'FAILED')
                self.assertEqual(second['output_stability'], 'VERIFIED')
                self.assertEqual(report['output_stability_failure']['stage'], 'retained-output-stability')
                self.assertEqual(set(report['retained_output_failures']), {'checksum'})
                self.assertEqual(report['diagnostic_status'], 'FAILED_OR_INCOMPLETE')
                for program, reader in readers.items():
                    row = report['programs'][program]
                    for key in ('output_files', 'output_directories', 'output_read_bytes'):
                        self.assertEqual(row[key], saved[program][key])
                    self.assertEqual(reader.used, row['output_read_bytes'])
                    self.assertLessEqual(reader.used, 64 * 1048576)
                    self.assertEqual((row['material_calls'], row['producer_dispatches']), (1, 1))
                    self.assertTrue(all(row[key] is False for key in A.FALSE_FLAGS))
                    with self.assertRaises(OSError):
                        A.os.fstat(reader.fd)
                self.assertTrue(all(report[key] is False for key in A.FALSE_FLAGS))

    def test_d01_r1_prior_mutation_aborts_later_dispatch_and_closes_owner(self):
        with tempfile.TemporaryDirectory() as temporary:
            def mutate(root):
                (root / 'importer/product/candidate.elf').write_bytes(b'changed before later dispatch')
            frame, code, report, readers, saved = retained_run_frame(Path(temporary),
                mutate_before_second=mutate)
            self.assertEqual(code, 1)
            self.assertEqual(frame.material_calls, ['checksum'])
            self.assertEqual(frame.dispatches, ['checksum'])
            self.assertEqual(set(report['programs']), set(COUNTS))
            self.assertEqual((report['expected_programs'], report['expected_heads'], report['expected_selected']),
                             (2, 187, 42))
            first, second = [report['programs'][p] for p in COUNTS]
            self.assertEqual((first['status'], first['producer_exit'], first['producer_candidate_complete']),
                             ('PRODUCER_COMPLETE_UNVERIFIED', 0, True))
            self.assertEqual((second['material_calls'], second['producer_dispatches']), (0, 0))
            self.assertIsNone(second['producer_exit'])
            self.assertEqual(second['failure']['stage'], 'retained-output-stability')
            self.assertEqual(report['error']['stage'], 'retained-output-stability')
            self.assertFalse(report['diagnostic_capture_complete'])
            self.assertFalse(report['retained_output_stability_complete'])
            self.assertEqual(first['output_stability'], 'FAILED')
            self.assertEqual(first['output_files'], saved['checksum']['output_files'])
            self.assertEqual(first['output_directories'], saved['checksum']['output_directories'])
            self.assertEqual(first['output_read_bytes'], saved['checksum']['output_read_bytes'])
            self.assertEqual(readers['checksum'].used, first['output_read_bytes'])
            with self.assertRaises(OSError):
                A.os.fstat(readers['checksum'].fd)
            self.assertTrue(all(report[key] is False for key in A.FALSE_FLAGS))



    def test_d01_r2_initial_member_or_name_refusal_stays_local_in_real_run(self):
        for kind, stage in [('members', 'output-bound'), ('name', 'output-path')]:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                frame, code, report, readers, saved = initially_incomplete_run_frame(Path(temporary), kind)
                self.assertEqual((A.MEMBERS, A.OUTPUT_BYTES, A.FILE_BYTES), (256, 64 * 1048576, 16 * 1048576))
                self.assertEqual(code, 1)
                self.assertEqual(frame.material_calls, ['checksum', 'rle-roundtrip'])
                self.assertEqual(frame.dispatches, ['checksum', 'rle-roundtrip'])
                self.assertEqual((report['expected_programs'], report['expected_heads'], report['expected_selected']),
                                 (2, 187, 42))
                first, second = [report['programs'][p] for p in COUNTS]
                self.assertEqual((first['status'], first['failure']['stage']), ('FAILED', stage))
                self.assertEqual((first['producer_exit'], first['producer_candidate_complete']), (0, True))
                self.assertFalse(first['diagnostic_capture_complete'])
                self.assertFalse(first['output_membership_complete'])
                self.assertEqual(first['output_stability'], 'VERIFIED_INCOMPLETE')
                product = first['output_directories']['importer/product']
                self.assertIsNone(product['members'])
                self.assertEqual(product['membership_failure']['stage'], stage)
                self.assertIn('policy.txt', first['output_files'])
                self.assertFalse(any(name.startswith('importer/product/') for name in first['output_files']))
                if kind == 'members':
                    self.assertEqual(len(frame.products['checksum']), 257)
                else:
                    self.assertIn('bad name', frame.products['checksum'])
                    self.assertEqual(first['retention_failure']['stage'], 'output-path')
                self.assertEqual((second['status'], second['producer_exit'], second['producer_candidate_complete']),
                                 ('PRODUCER_COMPLETE_UNVERIFIED', 0, True))
                self.assertTrue(second['diagnostic_capture_complete'])
                self.assertTrue(second['output_membership_complete'])
                self.assertEqual(second['output_stability'], 'VERIFIED')
                self.assertFalse(report['diagnostic_capture_complete'])
                self.assertFalse(report['retained_output_stability_complete'])
                self.assertEqual(report['diagnostic_status'], 'FAILED_OR_INCOMPLETE')
                self.assertNotIn('error', report)
                self.assertNotIn('retained_output_failures', report)
                self.assertNotIn('output_stability_failure', first)
                for program, reader in readers.items():
                    row = report['programs'][program]
                    self.assertEqual((row['material_calls'], row['producer_dispatches']), (1, 1))
                    self.assertEqual((row['observed_heads'], row['observed_selected']), COUNTS[program])
                    for key in ('output_files', 'output_directories', 'output_read_bytes'):
                        self.assertEqual(row[key], saved[program][key])
                    self.assertEqual(reader.used, row['output_read_bytes'])
                    self.assertLessEqual(reader.used, 64 * 1048576)
                    self.assertTrue(all(row[key] is False for key in A.FALSE_FLAGS))
                    with self.assertRaises(OSError):
                        A.os.fstat(reader.fd)
                self.assertTrue(all(report[key] is False for key in A.FALSE_FLAGS))

    def test_d01_r2_later_change_to_partial_retained_custody_still_aborts(self):
        for kind, stage in [('members', 'output-bound'), ('name', 'output-path')]:
            for mutation in ('known-file', 'directory-membership'):
                with self.subTest(kind=kind, mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                    def mutate(root):
                        if mutation == 'known-file':
                            (root / 'policy.txt').write_bytes(b'changed after partial retention')
                        else:
                            (root / 'importer/product/later-added.txt').write_bytes(b'later membership mutation')
                    frame, code, report, readers, saved = initially_incomplete_run_frame(
                        Path(temporary), kind, mutate_retained=mutate)
                    self.assertEqual(code, 1)
                    self.assertEqual(frame.material_calls, ['checksum'])
                    self.assertEqual(frame.dispatches, ['checksum'])
                    self.assertEqual(set(report['programs']), set(COUNTS))
                    self.assertEqual((report['expected_programs'], report['expected_heads'], report['expected_selected']),
                                     (2, 187, 42))
                    first, second = [report['programs'][p] for p in COUNTS]
                    self.assertEqual((first['status'], first['failure']['stage']), ('FAILED', stage))
                    self.assertEqual((first['producer_exit'], first['producer_candidate_complete']), (0, True))
                    self.assertEqual(first['output_stability'], 'FAILED')
                    self.assertFalse(first['output_membership_complete'])
                    self.assertFalse(first['diagnostic_capture_complete'])
                    self.assertIsNone(first['output_directories']['importer/product']['members'])
                    self.assertEqual((second['material_calls'], second['producer_dispatches']), (0, 0))
                    self.assertIsNone(second['producer_exit'])
                    self.assertEqual(second['failure']['stage'], 'retained-output-stability')
                    self.assertEqual(report['error']['stage'], 'retained-output-stability')
                    self.assertEqual(set(report['retained_output_failures']), {'checksum'})
                    self.assertFalse(report['diagnostic_capture_complete'])
                    self.assertFalse(report['retained_output_stability_complete'])
                    for key in ('output_files', 'output_directories', 'output_read_bytes'):
                        self.assertEqual(first[key], saved['checksum'][key])
                    self.assertEqual(readers['checksum'].used, first['output_read_bytes'])
                    self.assertLessEqual(first['output_read_bytes'], 64 * 1048576)
                    self.assertTrue(all(first[key] is False and second[key] is False for key in A.FALSE_FLAGS))
                    with self.assertRaises(OSError):
                        A.os.fstat(readers['checksum'].fd)
                    self.assertTrue(all(report[key] is False for key in A.FALSE_FLAGS))



if __name__ == '__main__':
    unittest.main()
