#!/usr/bin/env python3
"""One release two-function functional qualification: K16 then K1, no retries.

Run from a clean exact revision inside a one-core cpuset reservation. Raw logs,
ELFs and receipts remain in a fresh ignored/ directory. No performance claim.
"""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
ROOT = Path.cwd()
SOURCES = {
    'tools/rapid-profiler/normal-work/csv_fields.c': 'f8f98cc0550cf3ba72d2f2558f45057d2889870e804b51f599d4050ffb37cddd',
    'tools/rapid-profiler/strnlen-work/strnlen.c': '969eb826cd618ff799cdc4fcc9d61edd044a314bd39208479787eda622c4f336'}
CFLAGS = ('-O2', '-fPIC', '-shared', '-nostdlib', '-fno-builtin', '-fno-stack-protector',
    '-fomit-frame-pointer', '-fno-tree-vectorize', '-fno-tree-slp-vectorize', '-fno-if-conversion',
    '-fno-if-conversion2', '-fno-asynchronous-unwind-tables', '-fno-unwind-tables', '-fcf-protection=none',
    '-Wl,--build-id=none,-z,now,-z,noexecstack', '-Wl,--version-script=tools/rapid-profiler/strnlen-work/localize.map')
OWNER_SHA = '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
BOUNDED_SHA = 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
CSV_RUNNER_SHA = 'ae70dac850876452d1f09a8480d4381a5814846e1a7e394a33f620bb00699cf3'
MODULE_TESTS = tuple('normal::module::tests::' + name for name in (
    'module_keeps_all_csv_and_length_inputs_and_per_function_counters',
    'module_batch_requires_function_entry_return_owner_and_final_ack_joins',
    'module_requires_both_ret_populations_and_all_512_words_for_each_k',
    'module_report_keeps_global_slots_and_function_local_ranks'))
CSV_TESTS = tuple('normal::csv::tests::' + name for name in (
    'csv_corpus_and_guarded_results_keep_every_literal_case',
    'csv_batch_refuses_identity_owner_acknowledgement_and_stack_corruption',
    'csv_all_return_roles_and_every_journal_word_are_mandatory',
    'csv_report_history_requires_all_slots_payloads_and_two_actions',
    'csv_failed_real_storage_postflight_withholds_transfer',
    'csv_output_keeps_all_cases_and_full_width_endpoint_words',
    'csv_mapping_classes_keep_private_source_and_shared_images_distinct'))


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, data):
    encoded = (json.dumps(data, indent=2, allow_nan=False) + '\n').encode('utf-8')
    with path.open('xb') as f:
        f.write(encoded)
    return hashlib.sha256(encoded).hexdigest()


def remember(pins, path, expected=None):
    key = str(path)
    actual = sha(path)
    wanted = actual if expected is None else expected
    assert actual == wanted
    if key in pins:
        assert pins[key] == wanted  # Never refresh a completed file's authority.
    else:
        pins[key] = wanted
    return wanted


def check_pins(pins):
    for path, digest in pins.items():
        assert sha(path) == digest


def control_inventory(names):
    module_tests = [n for n in names if n.startswith('normal::module::tests::')]
    csv_tests = [n for n in names if n.startswith('normal::csv::tests::')]
    assert len(module_tests) == 4 and len(csv_tests) == 7 and len(set(names)) == len(names)
    assert set(module_tests) == set(MODULE_TESTS) and set(csv_tests) == set(CSV_TESTS)


def caller_symbols(data, caller):
    rows = [line.split() for line in data.splitlines()]
    assert 1 <= len(rows) <= 2 and all(len(r) == 8 and r[3:6] == ['FUNC', 'GLOBAL', 'DEFAULT']
        and r[7] == 'liteinst_csv_call_and_store' and r[6].isdecimal() for r in rows)
    assert {(int(r[1], 16), int(r[2])) for r in rows} == {(caller['elf_va'], caller['length'])}
    assert caller['length'] > 0


def load(name, path, expected=None):
    if expected is not None:
        assert sha(path) == expected
    spec = importlib.util.spec_from_file_location('module_functional_' + name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def symbol(data, name):
    rows = [line.split() for line in data.splitlines() if line.split() and line.split()[-1] == name]
    assert len(rows) == 1
    r = rows[0]
    assert len(r) == 8 and r[3:6] == ['FUNC', 'LOCAL', 'DEFAULT'] and r[6].isdecimal()
    return int(r[1], 16), int(r[2])


def returns(data, name, va, length):
    assert re.findall(r'^([0-9a-f]+) <' + re.escape(name) + r'>:$', data, re.M) == [f'{va:016x}']
    instructions = []
    for line in data.splitlines():
        if not re.match(r'^\s+[0-9a-f]+:', line):
            continue
        parts = line.split('\t'); assert len(parts) == 3
        pc = int(parts[0].strip()[:-1], 16); encoded = bytes.fromhex(parts[1]); asm = parts[2].strip()
        assert 1 <= len(encoded) <= 15 and va <= pc < va + length
        instructions.append((pc, encoded, asm))
    assert instructions and instructions[0][0] == va
    assert all(a[0] + len(a[1]) == b[0] for a, b in zip(instructions, instructions[1:]))
    assert instructions[-1][0] + len(instructions[-1][1]) == va + length
    found = [pc - va for pc, encoded, asm in instructions if asm == 'ret' and encoded == b'\xc3']
    assert 1 <= len(found) <= 4
    return found


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--revision', required=True)
    p.add_argument('--toolchain', type=Path, required=True)
    p.add_argument('--cargo-home', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    assert re.fullmatch('[0-9a-f]{40}', args.revision)
    assert subprocess.check_output(['git', 'rev-parse', 'HEAD']).decode().strip() == args.revision
    assert subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no']) == b''
    affinity = sorted(os.sched_getaffinity(0)); assert len(affinity) == 1
    out = args.output.resolve(); assert out.is_relative_to(ROOT/'ignored') and not out.exists()
    out.mkdir(parents=True)
    logs = ROOT/'target/evaluation'/out.name; logs.mkdir(parents=True, exist_ok=False)
    tc = args.toolchain.resolve(strict=True)
    env = dict(HOME=os.environ['HOME'], PATH=str(tc/'bin')+':/usr/bin:/bin',
        RUSTC=str(tc/'bin/rustc'), RUSTDOC=str(tc/'bin/rustdoc'), CARGO_HOME=str(args.cargo_home.resolve(strict=True)),
        CARGO_TARGET_DIR=str(ROOT/'target'), CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4', CARGO_NET_OFFLINE='true',
        CARGO_TERM_COLOR='never', CARGO_PROFILE_RELEASE_OPT_LEVEL='3', CARGO_PROFILE_RELEASE_DEBUG='0',
        CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true', CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true',
        LANG='C.UTF-8', LC_ALL='C.UTF-8', PYTHONDONTWRITEBYTECODE='1', LITEINST_EVALUATION='1')
    owner_path = ROOT/'evaluation/admission/processes.py'
    csv_path = ROOT/'evaluation/ordinary-csv/reproduce.py'
    output_path = ROOT/'evaluation/ordinary-module/output.py'
    bounded = ROOT/'tools/unwind-oracle/bounded_command.py'
    assert sha(bounded) == BOUNDED_SHA
    # Establish and retain exact tracked source authority before importing local helpers.
    source_paths = [Path(__file__).resolve(), owner_path, csv_path, output_path, bounded,
        ROOT/'evaluation/ordinary-module/controls.py',
        ROOT/'tools/rapid-profiler/strnlen-work/localize.map', *[ROOT/name for name in SOURCES]]
    pins = {}
    for path in source_paths:
        relative = path.relative_to(ROOT)
        original = subprocess.check_output(['git', 'show', args.revision + ':' + str(relative)])
        assert path.read_bytes() == original
        remember(pins, path, hashlib.sha256(original).hexdigest())
    for path, digest in SOURCES.items(): remember(pins, ROOT/path, digest)
    for path in [Path('/usr/bin/gcc'), Path('/usr/bin/readelf'), Path('/usr/bin/objdump'),
                 Path('/usr/bin/bash'), Path('/usr/bin/rg'), Path(sys.executable),
                 tc/'bin/rustc', tc/'bin/rustdoc', tc/'bin/cargo']:
        remember(pins, path)
    check_pins(pins)
    owner = load('owner', owner_path, OWNER_SHA)
    csv = load('caller', csv_path, CSV_RUNNER_SHA)
    output = load('output', output_path)
    check_pins(pins)
    stanzas = [dict(line.split(':', 1) for line in s.splitlines() if ':' in line)
        for s in Path('/proc/cpuinfo').read_text().split('\n\n') if s.strip()]
    cpus = [{k.strip(): v.strip() for k, v in s.items()} for s in stanzas]
    cpu = [s for s in cpus if s.get('processor') == str(affinity[0])]; assert len(cpu) == 1
    hardware = {k: v for k, v in cpu[0].items() if k in ('processor', 'vendor_id', 'cpu family', 'model', 'model name', 'stepping', 'microcode')}
    result = dict(status='FAILED', revision=args.revision, hardware=hardware, affinity=affinity,
        load_before=list(os.getloadavg()), attempts_per_cohort=1, retries=0, commands=[], pins=pins,
        cohorts=[dict(k=k, status='UNRUN', attempts=0) for k in (16, 1)])
    remember(pins, out/'plan.json', save(out/'plan.json', dict(revision=args.revision, cohorts=[16, 1], originals_per_cohort=32, installed_per_cohort=32,
        cooperative_seconds=15, child_cpu_seconds=20, child_wall_seconds=30, file_bytes=1048576, retries=0,
        prerequisite='Reviewed source, four module controls and seven unchanged CSV controls; one exact release artifact and complete module/normal-caller geometry')))
    def step(name, argv, wall=180, closed_files=()):
        argv = list(map(str, argv)); log = logs/(name+'.log')
        command = out/(name+'-command.json')
        remember(pins, command, save(command, dict(argv=argv, env=env, cwd=str(ROOT),
            log=str(log), wall_seconds=wall, file_bytes=1048576,
            closed_outputs=list(map(str, closed_files)))))
        check_pins(pins)
        closed = owner.run_command(argv, env, log, wall, 1048576)
        result['commands'].append(dict(name=name, argv=argv, closed=closed))
        closure = out/(name+'-closure.json')
        remember(pins, closure, save(closure, closed))
        assert closed['cleanup_complete'] and closed['reaped_descendants'] == 0
        data = log.read_bytes(); assert hashlib.sha256(data).hexdigest() == closed['private_log_sha256']
        remember(pins, log, closed['private_log_sha256'])
        copied = out/log.name
        with copied.open('xb') as stream: stream.write(data)
        remember(pins, copied, closed['private_log_sha256'])
        # Raw failure bytes are retained only after the outer owner proves closure.
        for path in closed_files:
            if path.exists(): remember(pins, path)
        check_pins(pins)
        assert closed['exit_code'] == 0 and closed['termination'] is None
        return data.decode('utf-8')
    try:
        python_controls = step('python-controls', [sys.executable, '-B', ROOT/'evaluation/ordinary-module/controls.py'], 30)
        assert re.findall(r'Ran (\d+) tests? in ', python_controls) == ['8']
        assert python_controls.rstrip().endswith('OK')
        controls = step('release-copy-controls', [tc/'bin/cargo', 'test', '-p', 'rapid-profiler', '--bin', 'ordinary-interval', '--release', 'normal::', '--', '--list'])
        names = [line[:-6] for line in controls.splitlines() if line.endswith(': test')]
        control_inventory(names)
        for label, prefix, count in [('module', 'normal::module::tests::', 4), ('csv', 'normal::csv::tests::', 7)]:
            log = step('release-' + label + '-controls', [tc/'bin/cargo', 'test', '-p', 'rapid-profiler', '--bin', 'ordinary-interval', '--release', prefix])
            assert re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', log) == [(str(count), '0', '0')]
            required = MODULE_TESTS if label == 'module' else CSV_TESTS
            assert sorted(re.findall(r'^test ([^\s]+) \.\.\. ok$', log, re.M)) == sorted(required)
        build = step('release-build', [tc/'bin/cargo', 'build', '-p', 'rapid-profiler', '--bin', 'ordinary-interval', '--release', '--message-format=json'])
        messages = [json.loads(line) for line in build.splitlines() if line.startswith('{')]
        assert messages[-1] == dict(reason='build-finished', success=True)
        artifacts = [m for m in messages if m.get('reason') == 'compiler-artifact' and m['target']['name'] == 'ordinary-interval' and not m['profile']['test']]
        assert len(artifacts) == 1
        artifact = artifacts[0]
        assert artifact['profile'] == dict(opt_level='3', debuginfo=0, debug_assertions=True, overflow_checks=True, test=False)
        binary = ROOT/'target/release/ordinary-interval'; assert artifact['executable'] == str(binary)
        assert artifact['target']['src_path'] == str(ROOT/'tools/rapid-profiler/ordinary-interval/main.rs')
        remember(pins, binary)
        candidate = out/'module.so'; trusted = out/'trusted_module.so'
        step('module-build', ['/usr/bin/gcc', *CFLAGS, *SOURCES, '-o', candidate])
        remember(pins, candidate)
        shutil.copyfile(candidate, trusted)
        assert candidate.stat().st_ino != trusted.stat().st_ino and candidate.read_bytes() == trusted.read_bytes()
        remember(pins, trusted, pins[str(candidate)])
        symbols = step('module-symbols', ['/usr/bin/readelf', '--wide', '--syms', trusted], 30)
        geometry = [symbol(symbols, name) for name in ('csv_fields', 'strnlen')]
        assert geometry[0][0] + geometry[0][1] <= geometry[1][0]
        lengths = [g[1] for g in geometry]
        retsets = [returns(step('module-' + name, ['/usr/bin/objdump', '-d', '-M', 'intel', '--disassemble=' + name, trusted], 30), name, *g)
            for name, g in zip(('csv_fields', 'strnlen'), geometry)]
        caller = csv.caller_geometry(step('caller-disassembly', ['/usr/bin/objdump', '-d', '-M', 'intel', '--disassemble=liteinst_csv_call_and_store', binary], 30))
        caller_symbols(step('caller-symbols', ['/usr/bin/bash', '-o', 'pipefail', '-c',
            '/usr/bin/readelf --wide --syms "$1" | /usr/bin/rg \' liteinst_csv_call_and_store$\'',
            'module-caller-symbols', binary], 30), caller)
        result.update(geometry=geometry, returns=retsets, caller=caller,
            binary_sha256=pins[str(binary)], module_sha256=pins[str(candidate)])
        for cohort in result['cohorts']:
            k = cohort['k']; directory = out/f'k{k}'; directory.mkdir()
            request = dict(argv=[str(binary), 'normal-module-work', str(candidate), str(trusted), *[str(n) for g in geometry for n in g], str(k)],
                cwd=str(ROOT), env=env, stdout=str(directory/'stdout.txt'), stderr=str(directory/'stderr.txt'), cpu_seconds=20, wall_seconds=30, file_bytes=1048576)
            request_sha = remember(pins, directory/'request.json', save(directory/'request.json', request))
            check_pins(pins)
            cohort.update(status='FAILED', attempts=1)
            step(f'k{k}-native-owner', [sys.executable, '-B', bounded, '--request', directory/'request.json', '--receipt', directory/'native.json'], 55,
                (directory/'native.json', directory/'stdout.txt', directory/'stderr.txt'))
            native_bytes = (directory/'native.json').read_bytes()
            remember(pins, directory/'native.json', hashlib.sha256(native_bytes).hexdigest())
            native = json.loads(native_bytes)
            assert native['exit'] == 0 and native['absence_proof'] == 'ECHILD' and native['inputs_unchanged']
            assert not native['wall_timeout'] and not native['unexpected_descendants'] and not native['cleanup_events']
            assert native['aborted'] is None and native['cleanup_error'] is None
            assert native['request_sha256'] == request_sha == sha(directory/'request.json') and native['helper_sha256'] == BOUNDED_SHA
            assert native['stdout_sha256'] == sha(directory/'stdout.txt') and native['stderr_sha256'] == sha(directory/'stderr.txt')
            stdout = (directory/'stdout.txt').read_bytes(); stderr = (directory/'stderr.txt').read_bytes()
            assert hashlib.sha256(stdout).hexdigest() == native['stdout_sha256']
            assert hashlib.sha256(stderr).hexdigest() == native['stderr_sha256']
            remember(pins, directory/'stdout.txt', native['stdout_sha256'])
            remember(pins, directory/'stderr.txt', native['stderr_sha256'])
            checked = output.check(stdout, stderr, k, lengths, retsets, caller['continuation_offset'], affinity[0])
            with (directory/'results.csv').open('xb') as stream: stream.write(checked['table'])
            remember(pins, directory/'results.csv', hashlib.sha256(checked['table']).hexdigest())
            check_pins(pins)
            cohort.update(status='PASS', terminal=checked['terminal'], rows=len(checked['rows']), native=native)
        assert subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no']) == b''
        assert subprocess.check_output(['git', 'rev-parse', 'HEAD']).decode().strip() == args.revision
        check_pins(pins)
        result['status'] = 'PASS'
    finally:
        result['load_after'] = list(os.getloadavg())
        save(out/'receipt.json', result)
    print(json.dumps(dict(status=result['status'], cohorts=[{k: c[k] for k in ('k', 'status', 'attempts')} for c in result['cohorts']])))

if __name__ == '__main__':
    main()
