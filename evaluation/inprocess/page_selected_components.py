#!/usr/bin/env python3
"""Committed-source decoder/provider/step/fetch component validation."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
from checks import source
from run import hardware
from page_selected import ENV, fact, need, save, elf, bridge_check, retain_selected_build
from page_selected_process import invoke
from page_selected_component_build import provider as build_provider, symbols

REPO = Path(__file__).resolve().parents[2]
PRODUCT = REPO/'tools/page-entry/selected'
BUILD = REPO/'target/page-entry/selected'
PROFILES = {
    'archive': (120, 2 << 30, 128 << 20, 150),
    'link': (30, 512 << 20, 64 << 20, 60),
    'decoder': (3, 256 << 20, 1 << 20, 10),
    'provider': (3, 256 << 20, 1 << 20, 10),
    'step_link': (5, 512 << 20, 16 << 20, 15),
    'step': (5, 512 << 20, 16 << 20, 15),
    'fetch_link': (30, 1 << 30, 16 << 20, 60),
    'fetch': (5, 1 << 30, 16 << 20, 10),
    'inspect': (10, 256 << 20, 4 << 20, 20),
}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def plain_executable(path):
    data, head, ph = elf(path)
    need(head[1] == 2 and not any(p[0] in (2, 3, 7) for p in ph), 'freestanding static ET_EXEC')
    need(any(p[0] == 1 and p[1]&1 and p[3] <= head[4] < p[3]+p[6] for p in ph), 'actual executable entry')
    # Preserve the freestanding decoder's no-relocation assertion without a
    # locale-sensitive readelf sentence. Inspect actual ELF section headers.
    need(head[11] == 64 and head[6]+head[11]*head[12] <= len(data), 'section extent')
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, head[6]+i*head[11]) for i in range(head[12])]
    need(not any(s[1] in (4, 9) and s[5] for s in sections), 'no freestanding relocation')
    return {'type': 'ET_EXEC', 'interpreter': False, 'dynamic': False, 'tls': False, 'relocations': 0}


def publish(path, record, private_receipt):
    command_rows = record['commands']
    public = {key: record.get(key) for key in ('schema_version', 'profile', 'status', 'scope',
              'expected_revision', 'started_utc', 'cpu', 'source', 'source_unchanged', 'hardware',
              'toolchain', 'totals', 'reproduce', 'bounds', 'archive', 'elf', 'personality_text_definitions')}
    public.update(environment=ENV, command_count=len(command_rows), commands_sha256=digest(command_rows),
                  private_receipt=fact(private_receipt), case_records_sha256=digest(record['cases']),
                  planned_provider_cases_sha256=record.get('provider_cases_sha256'),
                  input_manifest_sha256=digest(record.get('inputs_before', {})),
                  binary_manifest_sha256=digest(record.get('binaries_before', {})),
                  tool_hashes={name: {key: value[key] for key in ('bytes', 'sha256')}
                               for name, value in record.get('tools', {}).items()},
                  failure_type=(record.get('error') or '').split(':')[0] or None,
                  final_error_count=len(record['final_errors']),
                  failed_commands=[{'name': c['name'], 'exit': c.get('exit'), 'timeout': c.get('timed_out'),
                                    'error_type': (c.get('error') or '').split(':')[0] or None,
                                    'cleanup_error_count': len(c.get('cleanup_errors', [])),
                                    'command_sha256': digest(c['argv'])}
                                   for c in command_rows if c.get('error') or c.get('cleanup_errors') or
                                   c.get('timed_out') or not c.get('reaped') or c.get('exit') != c.get('expected_exit')],
                  command_recipe={
                      'build': ['sh', 'tools/page-entry/selected/build.sh'],
                      'decoder': ['decoder-controls', '<empty|tiny_arena|personality>'],
                      'freestanding': ['decoder-freestanding'],
                      'provider': ['provider-<normal|nested>-fixture', '<actual record fd>', '<seven exact cohort arguments>'],
                      'step': ['step-fixture', '<empty|foreign|nested|tf|rf>'],
                      'fetch': ['fetch-fixture', '<exact CASES key>'],
                      'actual_commands': 'Private receipt records every argv and capture; commands_sha256 authenticates the complete ordered rows.'})
    text = json.dumps(public, indent=2, sort_keys=True, allow_nan=False)+'\n'
    need(not any(x and len(x)>1 and x in text for x in (str(Path.home()), str(REPO), platform.node(), '/home/')), 'public private-location guard')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as output:
        output.write(text)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    args = ap.parse_args()
    need(sys.flags.optimize == 0, 'Python assertions must remain enabled')
    need(len(args.expect_revision) == 40 and all(c in '0123456789abcdef' for c in args.expect_revision), 'exact revision')
    need(len(os.sched_getaffinity(0)) == 1, 'one externally reserved CPU')
    cpu = next(iter(os.sched_getaffinity(0)))
    os.chdir(REPO)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    name = stamp+'-page-selected-components-'+args.expect_revision[:12]
    private = REPO/'target/evaluation/inprocess'/name
    private.mkdir(parents=True, exist_ok=False)
    public = REPO/'evaluation/inprocess/results'/(name+'.json')
    record = {'schema_version': 1, 'profile': 'page-selected-components-v1', 'status': 'failed',
              'scope': 'Decoder112/fatal102/106/freestanding; provider385 native/scripted/refusal; step20 pairs+13 arm-refusal pairs+4 refusal processes; fetch18. No general B2 or full-program claim.',
              'expected_revision': args.expect_revision, 'started_utc': stamp, 'cpu': cpu,
              'source': None, 'source_unchanged': False, 'commands': [], 'cases': [], 'error': None,
              'final_errors': [], 'totals': {'decoder_forms': 0, 'decoder_fatal': 0, 'decoder_freestanding': 0,
              'provider_cases': 0, 'step_pairs': 0, 'step_arm_refusals': 0, 'step_false_claim_refusals': 0,
              'step_control_processes': 0, 'fetch_cases': 0}, 'bounds': PROFILES,
              'reproduce': ['python3', 'evaluation/inprocess/page_selected_components.py', '--expect-revision', args.expect_revision]}
    pins, binaries = {}, {}
    tools = {}

    def pin(path):
        path = Path(path).resolve()
        observed = fact(path)
        need(str(path) not in pins or pins[str(path)] == observed, 'pinned input changed')
        pins[str(path)] = observed
        return path

    def binary(path):
        path = Path(path).resolve()
        value = fact(path)
        need(str(path) not in binaries or binaries[str(path)] == value, 'binary changed')
        binaries[str(path)] = value
        return path

    def run(label, argv, profile='link', expected=0, capture=None, data=False, step=False, delta=None):
        need(all(fact(path) == value for path, value in pins.items()), 'source/tool changed before command')
        need(all(fact(path) == value for path, value in binaries.items()), 'artifact changed before command')
        row = {'name': label, 'argv': list(map(str, argv)), 'bounds': PROFILES[profile], 'expected_exit': expected,
               'profile': profile, 'capture_limit': capture or (128*1024 if profile == 'fetch' else 8192 if profile in ('provider', 'step') else 1024**2)}
        row['environment'] = dict(ENV, **(delta or {}))
        if profile == 'provider':
            row['nproc'] = 1
        if profile == 'archive':
            row['environment'].update(LI2_CC=str(tools['cc']), LI2_CARGO=str(tools['cargo']), RUSTC=str(tools['rustc']),
                                      CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='1', CARGO_NET_OFFLINE='true', CARGO_TARGET_DIR=str(REPO/'target'))
            for key in ('HOME', 'CARGO_HOME', 'RUSTUP_HOME'):
                if key in os.environ:
                    row['environment'][key] = os.environ[key]
        record['commands'].append(row)
        out, err = invoke(row, private, cpu, record=data, step=step)
        need(row['exit'] == expected, 'component exact exit: '+label)
        return out, err

    def no_undefined(label, path):
        out, err = run(label, [tools['nm'], '-u', path], 'inspect')
        need(out == err == b'', 'undefined symbols')

    try:
        record['source'] = source()
        need(record['source']['revision'] == args.expect_revision, 'revision differs')
        record['hardware'] = hardware(cpu)
        paths = subprocess.check_output(['git', 'ls-files', '-z', 'tools/page-entry', 'evaluation/inprocess'], cwd=REPO, timeout=5).split(b'\0')
        for value in paths:
            if value and not os.fsdecode(value).startswith('evaluation/inprocess/results/'):
                pin(REPO/os.fsdecode(value))
        tools = {name: pin(shutil.which(name, path=ENV['PATH'])) for name in ('cc', 'sh', 'nm', 'objdump')}
        tools['python3'] = pin(sys.executable)
        rustup = pin(shutil.which('rustup'))
        for name in ('cargo', 'rustc'):
            path = subprocess.check_output([rustup, 'which', name], text=True, timeout=5).strip()
            need(Path(path).is_absolute(), 'absolute installed Rust binary')
            tools[name] = pin(path)
        record['tools'] = {name: dict(path=str(path), **pins[str(path)]) for name, path in tools.items()}
        record['toolchain'] = {}
        for name in ('cc', 'cargo', 'rustc'):
            out, err = run('version-'+name, [tools[name], '--version'])
            need(not err, 'version stderr')
            record['toolchain'][name] = out.decode().strip()
        run('selected-build', [tools['sh'], PRODUCT/'build.sh'], 'archive')
        retained = retain_selected_build(private, record, binaries)
        archive = binary(retained/'decoder.a')
        record['archive'] = fact(archive)
        definitions, errors = run('decoder-defined-symbols', [tools['nm'], '-g', '--defined-only', archive], 'inspect')
        personality = [line for line in definitions.splitlines() if line.split()[-2:] == [b'T', b'rust_eh_personality']]
        need(len(personality) == 1 and not errors, 'exactly one real personality text definition')
        record['personality_text_definitions'] = len(personality)
        dep = pin(retained/'decoder.d').read_text()
        need(all(str(PRODUCT/'decoder/src'/name) in dep for name in ('lib.rs', 'abi.rs', 'arena.rs', 'decode.rs', 'scan.rs')), 'decoder actual source dep-info')
        for name in ('decoder-rustc.txt', 'decoder-cargo.txt', 'cc-version.txt'):
            record['toolchain'][name] = pin(retained/name).read_text().strip()
        bridge = binary(retained/'bridge-selected.so')
        binary(retained/'observe')
        record['elf'] = {'controller': bridge_check(bridge)}
        no_undefined('controller-undefined', bridge)
        out = private/'build'
        out.mkdir()
        decoder = PRODUCT/'tests/decoder'
        controls = out/'decoder-controls'
        run('decoder-link', [tools['cc'], '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-fno-builtin',
            '-fno-tree-loop-distribute-patterns', '-mgeneral-regs-only', decoder/'control_driver.c', decoder/'support.c',
            archive, '-Wl,--gc-sections', '-o', controls])
        binary(controls)
        stdout, stderr = run('decoder-supplied', [controls], 'decoder')
        need(not stderr, 'decoder positive stderr')
        stats = json.loads(stdout)
        need(set(stats) == {'forms', 'phase', 'first_fatal_reason', 'arena_bytes', 'retained_high_water', 'allocation_calls', 'deallocation_calls'}, 'decoder statistics shape')
        need(stats['forms'] == 112 and stats['phase'] == 2 and stats['first_fatal_reason'] == 0 and
             0 < stats['retained_high_water'] <= stats['arena_bytes'] == 16*1024**2, 'decoder statistics')
        record['cases'].append({'name': 'decoder-supplied', 'stats': stats})
        record['totals']['decoder_forms'] = 112
        for name, reason in (('tiny_arena', 102), ('personality', 106)):
            stdout, stderr = run('decoder-'+name, [controls, name], 'decoder', 125)
            need(stdout == b'' and stderr == ('LI2_DECODER_FATAL '+str(reason)+'\n').encode(), 'exact decoder fatal')
            record['cases'].append({'name': 'decoder-'+name, 'fatal_reason': reason})
            record['totals']['decoder_fatal'] += 1
        free = out/'decoder-freestanding'
        run('decoder-freestanding-link', [tools['cc'], '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-ffreestanding',
            '-fno-builtin', '-fno-tree-loop-distribute-patterns', '-fno-stack-protector', '-fno-pie', '-no-pie', '-mgeneral-regs-only',
            '-ffunction-sections', '-fdata-sections', '-nostdlib', decoder/'freestanding/entry.S', decoder/'freestanding/harness.c',
            decoder/'support.c', archive, '-Wl,--no-undefined,--gc-sections,-e,_start', '-o', free])
        binary(free)
        record['elf']['decoder'] = plain_executable(free)
        no_undefined('decoder-freestanding-undefined', free)
        stdout, stderr = run('decoder-freestanding', [free], 'decoder')
        need(not stderr, 'freestanding stderr')
        stats = json.loads(stdout)
        need(set(stats) == {'schema_version', 'decoded_classes', 'scan_starts', 'phase', 'arena_bytes', 'retained_high_water',
                           'allocation_calls', 'deallocation_calls', 'first_fatal_reason'}, 'freestanding stats shape')
        need(stats['schema_version'] == 1 and stats['decoded_classes'] == 7 and stats['scan_starts'] == 4110 and stats['phase'] == 2 and
             stats['first_fatal_reason'] == 0 and 0 < stats['retained_high_water'] <= stats['arena_bytes'] == 16*1024**2, 'freestanding stats')
        record['cases'].append({'name': 'decoder-freestanding', 'stats': stats})
        record['totals']['decoder_freestanding'] = 1

        provider_compare = module('component_provider_compare', PRODUCT/'tests/provider/compare.py')
        provider_cases = module('component_provider_cases', PRODUCT/'tests/provider/cases.py').cohort()
        need(len(provider_cases) == 385, 'full provider cohort')
        record['provider_cases_sha256'] = digest(provider_cases)
        def provider_invoke(label, argv, build=False):
            need(build, 'provider build-only callback')
            return run('provider-'+label, argv, 'link')
        provider_build = build_provider(out, provider_invoke, tools, archive)
        record['provider_build'] = provider_build
        for path in provider_build['binaries']:
            binary(path)
        for case in provider_cases:
            name = 'provider-'+case['name']
            row = {'name': name, 'case': case, 'accepted': False}
            record['cases'].append(row)
            nested = case['args'][4] == 38
            executable = provider_build['nested' if nested else 'normal']
            stdout, stderr = run(name, [executable, '{record_fd}', *map(str, case['args'])], 'provider',
                125 if nested else 0, data=True, delta={'LI2_FIXTURE_SCRIPT_CF0': '1'} if case['cf0'] else {})
            need(stderr == b'' and stdout == (b'' if nested else b'LI2_PROVIDER_CAPTURE 1\n'), 'provider capture protocol')
            data = (private/(name+'.record')).read_bytes()
            row['record'] = fact(private/(name+'.record'))
            if nested:
                row['comparison'] = provider_compare.nested(data)
                actual = struct.unpack('<64Q', data)
                bound = provider_build['isolated_page']
                provider_compare.need((actual[9], actual[10], actual[11]) == (bound['start'], bound['code_end'], bound['end']), 'nested.binary_binding')
            elif case['reject']:
                try:
                    provider_compare.check(data, case)
                except provider_compare.Mismatch as error:
                    provider_compare.need(error.field == case['reject'], 'negative.wrong_failure')
                    row['precise_rejection'] = error.field
                else:
                    raise ValueError('provider actual negative accepted')
            else:
                row['comparison'] = provider_compare.check(data, case)
            row['accepted'] = True
            record['totals']['provider_cases'] += 1

        step = PRODUCT/'tests/step'
        executable = out/'step-fixture'
        run('step-link', [tools['cc'], '-std=gnu11', '-O2', '-g', '-nostdlib', '-static', '-no-pie', '-fno-pie', '-fno-builtin',
            '-fno-stack-protector', '-fno-tree-loop-distribute-patterns', '-fno-tree-vectorize', '-mgeneral-regs-only',
            '-fno-asynchronous-unwind-tables', '-ffunction-sections', '-fdata-sections', '-Wall', '-Wextra', '-Werror',
            '-I'+str(PRODUCT), '-Wl,-e,_start,-z,noexecstack,--gc-sections,--build-id=none', step/'step_owner.c', step/'fixture.c',
            step/'fixture.S', archive, '-o', executable], 'step_link')
        binary(executable)
        record['elf']['step'] = plain_executable(executable)
        no_undefined('step-undefined', executable)
        by_name = {name: size for name, _, _, _, size in symbols(executable)}
        dump_names = ('samples', 'fixture_live_before', 'fixture_live_after', 'refused_samples', 'refused_claims', 'refusal_complete')
        need(all(by_name.get(name, 0) > 0 for name in dump_names), 'actual step dump symbols')
        dump_bytes = sum(by_name[name] for name in dump_names)
        need(0 < dump_bytes < 16*1024**2 and by_name['refusal_complete'] == 13*4, 'complete bounded step dump')
        record['step_dump'] = {name: by_name[name] for name in dump_names}
        cases = [('positive', [], 0, b'LI2_STEP_OWNER_PASS selftest=1 cases=20 native=20 trace=20 revoked=23 endpoints=20 source_unchanged=20 register_mov=15 refusals=13\n')]
        for name, code, opened, revoked in (('foreign', 7, 0, 0), ('nested', 8, 1, 1), ('tf', 5, 0, 0), ('rf', 5, 0, 0)):
            cases.append((name, [name], 125, f'LI2_STEP_OWNER_FAILURE {code}\nopened {opened}\nrevoked {revoked}\n'.encode()))
        for name, args_, expected, text in cases:
            label = 'step-'+name
            row = {'name': label, 'accepted': False}
            record['cases'].append(row)
            stdout, stderr = run(label, [executable, *args_], 'step', expected, data=True, step=True)
            need(stdout == text and not stderr, 'exact step outcome')
            data = (private/(label+'.record')).read_bytes()
            need(len(data) == dump_bytes, 'complete actual step dump')
            if name == 'positive':
                need(data[-13*4:] == struct.pack('<13I', *([1]*13)), 'all thirteen retained refusal completions')
                record['totals'].update(step_pairs=20, step_arm_refusals=13, step_false_claim_refusals=13)
            else:
                record['totals']['step_control_processes'] += 1
            row.update(accepted=True, record=fact(private/(label+'.record')), preparation=fact(private/(label+'.preparation')))

        fetch = PRODUCT/'tests/fetch'
        executable = out/'fetch-fixture'
        run('fetch-link', [tools['cc'], '-std=gnu11', '-O2', '-g', '-fno-builtin', '-fno-stack-protector',
            '-fno-tree-loop-distribute-patterns', '-fno-tree-vectorize', '-Wall', '-Wextra', '-Werror',
            '-I'+str(PRODUCT), '-I'+str(PRODUCT.parent), '-Wl,-z,noexecstack,-z,now,--build-id=none',
            fetch/'fixture.c', PRODUCT/'lifecycle_loader.c', '-o', executable], 'fetch_link')
        binary(executable)
        fetch_compare = module('component_fetch_compare', fetch/'compare.py')
        need(len(fetch_compare.CASES) == 18, 'full fetch cohort')
        for name in fetch_compare.CASES:
            row = {'name': 'fetch-'+name, 'accepted': False}
            record['cases'].append(row)
            stdout, stderr = run('fetch-'+name, [executable, name], 'fetch')
            need(not stderr, 'fetch stderr')
            result = fetch_compare.parse(name, stdout)
            row.update(accepted=True, expected_error=result['expected_error'])
            record['totals']['fetch_cases'] += 1
        need(record['totals'] == {'decoder_forms': 112, 'decoder_fatal': 2, 'decoder_freestanding': 1,
             'provider_cases': 385, 'step_pairs': 20, 'step_arm_refusals': 13, 'step_false_claim_refusals': 13,
             'step_control_processes': 4, 'fetch_cases': 18}, 'complete component cohort')
        record['source_unchanged'] = source() == record['source']
        need(record['source_unchanged'], 'source changed')
        record['status'] = 'passed'
    except BaseException as error:
        record['error'] = type(error).__name__+': '+str(error)
    finally:
        record['inputs_before'], record['binaries_before'] = pins, binaries
        for key, before in (('inputs_after', pins), ('binaries_after', binaries)):
            after = {}
            record[key] = after
            for path, expected in before.items():
                try:
                    after[path] = fact(path)
                    need(after[path] == expected, 'changed input/artifact')
                except BaseException as error:
                    record['final_errors'].append(path+': '+repr(error))
        try:
            record['source_unchanged'] = source() == record['source']
            need(record['source_unchanged'], 'source changed')
        except BaseException as error:
            record['final_errors'].append('source: '+repr(error))
        if record['final_errors']:
            record['status'] = 'failed'
            if record['error'] is None:
                record['error'] = 'FinalObservationError: input/source/artifact closure failed'
        private_receipt = private/'receipt.json'
        save(private_receipt, record)
        publish(public, record, private_receipt)
    print(json.dumps({'status': record['status'], 'totals': record['totals'],
                      'failure_type': (record['error'] or '').split(':')[0] or None}))
    return 0 if record['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
