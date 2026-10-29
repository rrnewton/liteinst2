#!/usr/bin/env python3
"""Six native/REP full-state pairs and one actual terminal store-fault control."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
from checks import source
from run import hardware
from page_selected import ENV, fact, need, save
from page_selected_components import plain_executable
from page_selected_generic_build import Build, PROFILES as BUILD_PROFILES
from page_selected_process import invoke

REPO = Path(__file__).resolve().parents[2]
PRODUCT = REPO/'tools/page-entry/selected'
FIXTURE = PRODUCT/'tests/repeat_dword'
PROFILES = dict(BUILD_PROFILES, fixture_link=[5, 512 << 20, 16 << 20, 15],
                native=[5, 512 << 20, 16 << 20, 15])
ORACLE_COMMANDS = ['header-dependencies', 'fixture-build', 'fixture-undefined',
                   'fixture-sections', 'positive', 'write-fault']


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def publish(path, record, receipt):
    build = record.get('build', {})
    public = {key: record.get(key) for key in (
        'schema_version', 'profile', 'status', 'scope', 'expected_revision', 'started_utc',
        'cpu', 'source', 'source_unchanged', 'hardware', 'totals', 'reproduce', 'bounds', 'elf',
        'cleanup_complete')}
    public.update(environment=ENV, private_receipt=fact(receipt),
        command_count=len(record['commands']), commands_sha256=digest(record['commands']),
        cases_sha256=digest(record['cases']), inputs_sha256=digest(record.get('inputs_before', {})),
        header_dependencies_sha256=digest(record.get('headers', {})), outcomes=record.get('outcomes'),
        binaries_sha256=digest(record.get('binaries_before', {})),
        tool_versions=build.get('numeric_versions', {}),
        tool_hashes={name: {k: value[k] for k in ('bytes', 'sha256')}
                     for name, value in build.get('tools', {}).items()},
        build_artifacts={name: {k: value[k] for k in ('bytes', 'sha256')}
                         for name, value in build.get('artifacts', {}).items()},
        fixture=record.get('fixture'),
        build_status=build.get('status', 'not_started'),
        configuration_unchanged=build.get('configuration_unchanged'),
        build_command_completed=build.get('command_completed'),
        failure_type=(record.get('error') or '').split(':')[0] or None,
        final_error_count=len(record['final_errors']),
        native_commands=[{'name': c['name'], 'exit': c.get('exit'), 'expected_exit': c['expected_exit'],
                          'duration_ns': c.get('duration_ns'), 'reaped': c.get('reaped'),
                          'timed_out': c.get('timed_out'),
                          'cleanup_error_count': len(c.get('cleanup_errors', [])),
                          'environment_delta': {k: v for k, v in c['environment'].items() if ENV.get(k) != v},
                          'captures': {n: {k: v[k] for k in ('bytes', 'sha256')}
                                       for n, v in c.get('captures', {}).items()}}
                         for c in record['commands'] if c['profile'] == 'native'],
        cases=[{k: c.get(k) for k in ('name', 'accepted', 'actual_exit', 'operation_completed',
                'actual_failed_operation', 'header', 'record')} for c in record['cases']],
        command_recipe={
            'selected_build': ['sh', 'tools/page-entry/selected/build.sh'],
            'fixture_build': ['sh', 'tools/page-entry/selected/tests/repeat_dword/build.sh',
                              '<retained decoder.a>', '<private run directory>'],
            'positive': ['repeat-dword-owner-fixture'],
            'write_fault': {'argv': ['repeat-dword-owner-fixture'], 'environment_delta': {'LI2_REPEAT_WRITE_FAULT': '1'}},
            'actual_commands': 'Complete ordered argv, environments and captures are retained privately and bound by commands_sha256.'})
    text = json.dumps(public, sort_keys=True, indent=2, allow_nan=False)+'\n'
    markers = (str(Path.home()), str(REPO), platform.node(), '/home/')
    need(not any(x and len(x) > 1 and x in text for x in markers), 'public private-location guard')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as output:
        output.write(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-revision', required=True)
    args = parser.parse_args()
    need(sys.flags.optimize == 0, 'Python assertions must remain enabled')
    need(len(args.expect_revision) == 40 and all(c in '0123456789abcdef' for c in args.expect_revision), 'exact revision')
    need(len(os.sched_getaffinity(0)) == 1, 'one externally reserved CPU')
    cpu = next(iter(os.sched_getaffinity(0)))
    os.chdir(REPO)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    name = stamp+'-page-selected-repeat-dword-oracle-'+args.expect_revision[:12]
    private = REPO/'target/evaluation/inprocess'/name
    private.mkdir(parents=True, exist_ok=False)
    public = REPO/'evaluation/inprocess/results'/(name+'.json')
    record = {'schema_version': 1, 'profile': 'page-selected-repeat-dword-oracle-v1', 'status': 'failed',
        'scope': 'Finite component: six native/REP STOSD full-state and memory pairs, 47 old generic and six STOSD classifier refusals, one actual failed first store. No connected-loader, general REP, signal-delivery, performance or full-B2 claim.',
        'expected_revision': args.expect_revision, 'started_utc': stamp, 'cpu': cpu,
        'source': None, 'source_unchanged': False, 'commands': [], 'cases': [],
        'error': None, 'final_errors': [], 'bounds': PROFILES,
        'cleanup_complete': False,
        'totals': {'positive_pairs': 0, 'positive_selftest_pairs': 0, 'repeat_traces': 0,
                   'old_refusal_encodings': 0, 'stosd_refusal_encodings': 0, 'verified_failed_operations': 0},
        'reproduce': ['python3', 'evaluation/inprocess/page_selected_repeat_dword_oracle.py',
                      '--expect-revision', args.expect_revision]}
    pins, binaries = {}, {}
    fixture = private/'repeat-dword-owner-fixture'
    build = None
    oracle_start = None

    def pin(path):
        path = Path(path).resolve()
        value = fact(path)
        need(str(path) not in pins or pins[str(path)] == value, 'pinned input changed')
        pins[str(path)] = value
        return path

    def binary(path):
        path = Path(path).resolve()
        value = fact(path)
        need(str(path) not in binaries or binaries[str(path)] == value, 'artifact changed')
        binaries[str(path)] = value
        return path

    def run(label, argv, expected=0, profile='native', env=None):
        need(all(fact(p) == v for p, v in pins.items()), 'input changed before command')
        need(all(fact(p) == v for p, v in binaries.items()), 'artifact changed before command')
        if oracle_start is not None:
            at = len(record['commands'])-oracle_start
            need(at < len(ORACLE_COMMANDS) and label == ORACLE_COMMANDS[at], 'exact oracle command prefix')
        native = profile == 'native'
        row = {'name': label, 'argv': list(map(str, argv)), 'bounds': PROFILES[profile],
               'expected_exit': expected, 'profile': profile,
               'capture_limit': 8192 if native else 1024*1024,
               'environment': dict(ENV, **(env or {}))}
        record['commands'].append(row)
        out, err = invoke(row, private, cpu, record=native, step=native)
        need(row['exit'] == expected, 'exact process exit: '+label)
        return row, out, err

    try:
        record['source'] = source()
        need(record['source']['revision'] == args.expect_revision, 'revision differs')
        record['hardware'] = hardware(cpu)
        paths = subprocess.check_output(['git', 'ls-files', '-z', 'tools/page-entry', 'evaluation/inprocess'],
                                        cwd=REPO, timeout=5).split(b'\0')
        for value in paths:
            if value and not os.fsdecode(value).startswith('evaluation/inprocess/results/'):
                pin(REPO/os.fsdecode(value))
        for module in tuple(sys.modules.values()):
            file = getattr(module, '__file__', None)
            if file and Path(file).resolve().is_relative_to(REPO):
                pin(file)
        build = Build(record, private, pin, binary, run)
        products = build.prepare()
        outcomes = json.loads((FIXTURE/'OUTCOMES.json').read_bytes())
        need(outcomes['schema_version'] == 1 and outcomes['header_bytes'] == 208 and
             outcomes['header_format'] == '<18QqQq5Q' and len(outcomes['header_fields']) == 26 and
             len(set(outcomes['header_fields'])) == 26 and
             [c['name'] for c in outcomes['commands']] == ['positive', 'write-fault'] and
             [c['exit'] for c in outcomes['commands']] == [0, 125] and
             [c['successful_operation'] for c in outcomes['commands']] == [True, False] and
             [c['argv'] for c in outcomes['commands']] == [['repeat-dword-owner-fixture']]*2 and
             [c['environment_delta'] for c in outcomes['commands']] == [{}, {'LI2_REPEAT_WRITE_FAULT': '1'}] and
             outcomes['limits']['native'] == PROFILES['native'] and
             outcomes['limits']['external_cpu_count'] == 1 and outcomes['limits']['core_bytes'] == 0 and
             outcomes['record_limit_bytes_exclusive'] == 16 << 20, 'closed owner outcome protocol')
        record['outcomes'] = fact(FIXTURE/'OUTCOMES.json')
        # The product translation unit includes the REP owner exactly once;
        # there is no private wrapper or archived binary dependency.
        pin(shutil.which('dirname', path=ENV['PATH']))
        text = (FIXTURE/'build.sh').read_text().replace(chr(92)+chr(10), ' ')
        command = next(line for line in text.splitlines() if line.startswith('"$cc_bin" '))
        words = shlex.split(command)
        options = words[1:words.index('-I$source_dir')]
        inputs = [PRODUCT/'step_owner.c', PRODUCT/'lifecycle_loader.c',
                  PRODUCT/'tests/generic/tf_controls.c', FIXTURE/'fixture.c', PRODUCT/'tests/generic/fixture.S']
        includes = ['-I'+str(p) for p in (FIXTURE, PRODUCT/'tests/generic', PRODUCT, PRODUCT.parent)]
        oracle_start = len(record['commands'])
        _, out, err = run('header-dependencies', [build.tools['cc'], *options, *includes, '-M', '-MT',
                                                 'li2_repeat_dependency', *inputs],
                          profile='metadata', env=build.environment)
        need(not err, 'dependency preprocessing stderr')
        rows = out.decode().replace(chr(92)+chr(10), ' ').splitlines()
        need(len(rows) == len(inputs) and all(r.startswith('li2_repeat_dependency: ') for r in rows),
             'exact five preprocessed dependency rules')
        dependencies = sorted({x for r in rows for x in shlex.split(r.split(':', 1)[1])})
        need(all(str(p) in dependencies for p in inputs), 'actual translation-unit dependency closure')
        need(all(str(p) in dependencies for p in (PRODUCT/'repeat_owner.h', PRODUCT/'repeat_owner.inc')),
             'actual product includes both REP owner files')
        record['headers'] = {str(pin(p)): fact(p) for p in dependencies}
        run('fixture-build', [build.tools['sh'], FIXTURE/'build.sh', products['archive'], private],
            profile='fixture_link', env=build.environment)
        binary(fixture)
        record['fixture'] = fact(fixture)
        record['elf'] = plain_executable(fixture)
        _, out, err = run('fixture-undefined', [build.tools['nm'], '-u', fixture],
                          profile='inspect', env=build.environment)
        need(out == err == b'', 'no fixture undefined symbols')
        _, out, err = run('fixture-sections', [build.tools['readelf'], '-S', '-W', fixture],
                          profile='inspect', env=build.environment)
        need(not err and b'.debug_info ' in out and b'.debug_abbrev ' in out and b'.debug_line ' in out,
             'retain actual executable DWARF')
        for case in outcomes['commands']:
            name = case['name']
            result = dict(name=name, accepted=False, actual_exit=None, operation_completed=None,
                          actual_failed_operation=False)
            record['cases'].append(result)
            need(case['argv'][0] == fixture.name, 'exact retained executable name')
            row, out, err = run(name, [fixture, *case['argv'][1:]], case['exit'], env=case['environment_delta'])
            result['actual_exit'] = row['exit']
            need(err == case['stderr'].encode(), 'exact stderr: '+name)
            # Early setup failures can retain the inherited generic layout.
            # Preserve those bytes and never substitute a successful REP record.
            path = private/(name+'.record')
            data = path.read_bytes()
            need(208 <= len(data) < outcomes['record_limit_bytes_exclusive'], 'complete bounded owner header')
            header = dict(zip(outcomes['header_fields'], struct.unpack_from(outcomes['header_format'], data)))
            result.update(header=header, record=fact(path))
            need(all(header[k] == v for k, v in case['header_equals'].items()), 'exact owner header: '+name)
            need(header['xcr0'] & 3 == 3 and 576 <= header['xsave_bytes'] <= 65536, 'qualified XSAVE extent')
            need(all(header[k] > 0 for k in ('selftest_bytes', 'case_bytes', 'event_bytes')) and
                 len(data) == 208+header['selftest_bytes']+6*header['case_bytes']+header['event_bytes'],
                 'complete selftest/six-case/unexpected extents')
            if case['successful_operation']:
                need(case['trace_total_min'] <= header['traces'] <= case['trace_total_max'] and
                     out == (case['stdout_prefix']+str(header['traces'])+case['stdout_suffix']).encode(),
                     'exact successful stdout/trace total')
                need(not any(data[-header['event_bytes']:]), 'no unexpected event in successful record')
                result['operation_completed'] = True
                record['totals'].update(positive_pairs=6, positive_selftest_pairs=1, repeat_traces=header['traces'],
                                        old_refusal_encodings=47, stosd_refusal_encodings=6)
            else:
                need(case['actual_failed_operation'] and header['completed'] == 0 and
                     header['unexpected_observed'] == header['expected_failure_verified'] == 1 and
                     any(data[-header['event_bytes']:]) and out == case['stdout'].encode(),
                     'actual failed operation and exact diagnostic stdout')
                result.update(operation_completed=False, actual_failed_operation=True)
                record['totals']['verified_failed_operations'] += 1
            result['accepted'] = True
        need([c['name'] for c in record['commands'][oracle_start:]] == ORACLE_COMMANDS,
             'all six exact oracle commands completed after the fresh product build')
        record['status'] = 'passed'
    except BaseException as exc:
        record['error'] = type(exc).__name__+': '+str(exc)
    finally:
        if build is not None:
            try:
                record['final_errors'].extend(build.finish())
                if record['status'] == 'passed':
                    need(record['build']['status'] == 'passed', 'build closure did not pass')
            except BaseException as exc:
                record['final_errors'].append('build closure: '+repr(exc))
        try:
            if fixture.is_file():
                record['fixture_after'] = fact(fixture)
                record.setdefault('fixture', record['fixture_after'])
                binary(fixture)
        except BaseException as exc:
            record['final_errors'].append('fixture retention: '+repr(exc))
        record['inputs_before'], record['binaries_before'] = pins, binaries
        for key, before in (('inputs_after', pins), ('binaries_after', binaries)):
            after = record[key] = {}
            for path, expected in before.items():
                try:
                    after[path] = fact(path)
                    need(after[path] == expected, 'final byte identity')
                except BaseException as exc:
                    record['final_errors'].append(path+': '+repr(exc))
        try:
            record['source_unchanged'] = source() == record['source']
            need(record['source_unchanged'], 'source changed')
        except BaseException as exc:
            record['final_errors'].append('source: '+repr(exc))
        record['cleanup_complete'] = bool(record['commands']) and all(
            c.get('reaped') and not c.get('error') and not c.get('timed_out') and
            not c.get('cleanup_errors') and all(d['closed'] for d in c.get('descriptors', []))
            for c in record['commands'])
        if record['final_errors'] or not record['cleanup_complete'] or not record.get('build', {}).get('configuration_unchanged'):
            record['status'] = 'failed'
            if record['error'] is None:
                record['error'] = 'FinalObservationError: input/source/artifact closure failed'
        receipt = private/'receipt.json'
        save(receipt, record)
        publish(public, record, receipt)
    print(json.dumps({'status': record['status'], 'totals': record['totals'],
                      'failure_type': (record['error'] or '').split(':')[0] or None}))
    return 0 if record['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
