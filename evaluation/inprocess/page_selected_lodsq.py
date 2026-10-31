#!/usr/bin/env python3
"""Canonical LODSQ: additive original-address native/TF full-state oracle."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import csv
import re
import os
from pathlib import Path
import platform
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
FIXTURE = REPO/'tools/page-entry/selected/tests/lodsq_native'
GENERIC = REPO/'tools/page-entry/selected/tests/generic'
PROFILES = dict(BUILD_PROFILES, fixture_link=[5, 512 << 20, 16 << 20, 15],
                native=[5, 512 << 20, 16 << 20, 15])


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def publish(path, record, receipt):
    build = record.get('build', {})
    public = {key: record.get(key) for key in (
        'schema_version', 'profile', 'status', 'scope', 'expected_revision', 'started_utc',
        'cpu', 'source', 'source_unchanged', 'hardware', 'totals', 'reproduce', 'bounds', 'elf')}
    public.update(environment=ENV, private_receipt=fact(receipt),
        command_count=len(record['commands']), commands_sha256=digest(record['commands']),
        cases_sha256=digest(record['cases']), inputs_sha256=digest(record.get('inputs_before', {})),
        binaries_sha256=digest(record.get('binaries_before', {})),
        tool_versions=build.get('numeric_versions', {}),
        tool_hashes={name: {k: value[k] for k in ('bytes', 'sha256')}
                     for name, value in build.get('tools', {}).items()},
        build_artifacts={name: {k: value[k] for k in ('bytes', 'sha256')}
                         for name, value in build.get('artifacts', {}).items()},
        fixture=record.get('fixture'),
        rust_classification=record.get('rust_classification'),
        build_status=build.get('status', 'not_started'),
        failure_type=(record.get('error') or '').split(':')[0] or None,
        final_error_count=len(record['final_errors']),
        native_commands=[{'name': c['name'], 'exit': c.get('exit'), 'expected_exit': c['expected_exit'],
                          'duration_ns': c.get('duration_ns'), 'reaped': c.get('reaped'),
                          'timed_out': c.get('timed_out'),
                          'cleanup_error_count': len(c.get('cleanup_errors', [])),
                          'captures': {n: {k: v[k] for k in ('bytes', 'sha256')}
                                       for n, v in c.get('captures', {}).items()}}
                         for c in record['commands'] if c['profile'] == 'native'],
        cases=[{'name': c['name'], 'accepted': c['accepted'], 'process_outcome': c['process_outcome'],
                'header': c.get('header'), 'record': c.get('record'), 'trailer': c.get('trailer')} for c in record['cases']],
        command_recipe={
            'selected_build': ['sh', 'tools/page-entry/selected/build.sh'],
            'fixture_build': ['sh', 'tools/page-entry/selected/tests/lodsq_native/build.sh',
                              '<retained decoder.a>', '<private run directory>', 'tools/page-entry/selected'],
            'native': ['lodsq-native', '<empty|load-fault|unowned-target|rsp-domain>'],
            'lodsq_native_environment': {'LI2_LODSQ_CASE': '<positive|none-df0|none-df1|split-df0|split-df1>'},
            'actual_commands': 'Complete ordered argv, environments and captures are retained privately and bound by commands_sha256.'})
    text = json.dumps(public, sort_keys=True, indent=2, allow_nan=False)+'\n'
    markers = (str(Path.home()), str(REPO), platform.node())
    need(not any(x and len(x) > 1 and x in text for x in markers), 'public private-location guard')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as output:
        output.write(text)
    with path.with_suffix('.csv').open('x', newline='') as output:
        fields = ['name', 'accepted', 'process_outcome', 'exit', 'expected_exit',
                  'duration_ns', 'pairs', 'completed', 'control', 'record_bytes', 'record_sha256']
        writer = csv.DictWriter(output, fieldnames=fields); writer.writeheader()
        commands = {c['name']: c for c in record['commands'] if c['profile'] == 'native'}
        for case in record['cases']:
            command = commands.get(case['name'], {}); header = case.get('header', {}); raw = case.get('record', {})
            writer.writerow(dict(name=case['name'], accepted=case['accepted'],
                process_outcome=case['process_outcome'], exit=command.get('exit'),
                expected_exit=command.get('expected_exit'), duration_ns=command.get('duration_ns'),
                pairs=header.get('pairs'), completed=header.get('completed'), control=header.get('control'),
                record_bytes=raw.get('bytes'), record_sha256=raw.get('sha256')))


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
    name = stamp+'-page-selected-lodsq-oracle-'+args.expect_revision[:12]
    private = REPO/'target/evaluation/inprocess'/name
    private.mkdir(parents=True, exist_ok=False)
    public = REPO/'evaluation/inprocess/results'/(name+'.json')
    record = {'schema_version': 1, 'profile': 'page-selected-lodsq-oracle-v1', 'status': 'failed',
        'scope': 'Finite canonical 48 AD LODSQ component: unchanged generic21 and three failed operations; eight additional native/TF pairs, both DF values, actual read-only data and guard endpoints, four page-ending and four crossing source fetches, and four real read-fault pairs. All original GPR/flags/full initialized FP/live XSAVE/stack/data/source/TLS/selectors and closure checks remain. Five Rust descriptive tests and actual C route/NONE-write queries are separate gates. Failed operations remain exit125; no loader completion, transparent-fault, copied-code, whole-owner or performance claim.',
        'expected_revision': args.expect_revision, 'started_utc': stamp, 'cpu': cpu,
        'source': None, 'source_unchanged': False, 'commands': [], 'cases': [],
        'error': None, 'final_errors': [], 'bounds': PROFILES,
        'totals': {'positive_pairs': 0, 'generic_pairs': 0, 'positive_selftest_pairs': 0,
                   'supplied_refusal_encodings': 0, 'verified_failed_operations': 0,
                   'additional_negative_command_selftests': 0, 'lodsq_pairs': 0, 'lodsq_verified_failed_operations': 0,
                   'lodsq_selftest_pairs': 0, 'executed_route_checks': 0, 'executed_footprint_checks': 0, 'rust_tests': 0},
        'reproduce': ['python3', 'evaluation/inprocess/page_selected_lodsq.py',
                      '--expect-revision', args.expect_revision]}
    pins, binaries = {}, {}
    fixture = private/'lodsq-native'
    build = None

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
        build = Build(record, private, pin, binary, run)
        products = build.prepare()
        # A host descriptive test binary uses unwind, unlike the production
        # abort-only static archive. Targetdir/jobs/incremental and all bounds
        # are the same existing build settings; production bytes stay pinned.
        test_env = dict(build.environment, RUSTFLAGS='-C relocation-model=pic -C force-unwind-tables=no')
        _, test_out, _ = run('lodsq-classification', [build.tools['cargo'], 'test', '--offline', '--locked',
            '--manifest-path', REPO/'tools/page-entry/selected/tests/lodsq/Cargo.toml',
            '--', '--test-threads=1'], profile='build', env=test_env)
        expected_tests = ['canonical_metadata_and_implicit_read_effects',
            'copied_register_region_span_and_link_none_stay_closed',
            'no_memory_write_does_not_claim_read_address_validity',
            'noncanonical_width_prefix_and_string_forms_refuse',
            'original_decode_argument_and_overflow_failures_stay_exact']
        actual_tests = re.findall(rb'^test ([a-z_]+) \.\.\. ok$', test_out, re.M)
        need(actual_tests == [n.encode() for n in expected_tests] and
             test_out.count(b'running 5 tests\n') == 1 and
             len(re.findall(rb'^test result: ok\. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;',
                            test_out, re.M)) == 1 and test_out.count(b'test result:') == 1,
             'all five exact actual-source Rust tests, no filtered or ignored case')
        record['rust_classification'] = dict(tests=expected_tests, passed=5, failed=0, ignored=0,
            filtered=0, component_only=True, native_credit=False)
        record['totals']['rust_tests'] = 5
        run('fixture-build', [build.tools['sh'], FIXTURE/'build.sh', products['archive'], private, REPO/'tools/page-entry/selected'],
            profile='fixture_link', env=build.environment)
        binary(fixture)
        record['fixture'] = fact(fixture)
        record['elf'] = plain_executable(fixture)
        _, out, err = run('fixture-undefined', [build.tools['nm'], '-u', fixture],
                          profile='inspect', env=build.environment)
        need(not out and not err, 'no undefined fixture symbols')
        outcomes = json.loads((FIXTURE/'OUTCOMES.json').read_bytes())
        need(fact(FIXTURE/'OUTCOMES.json') == dict(bytes=9939,
             sha256='66e3f6b7a62c9746a76786678d9c12325c570522ded51abff2b6573404b708e3'),
             'exact reviewed nine-command protocol')
        old_outcomes = json.loads((GENERIC/'OUTCOMES.json').read_bytes())
        need(outcomes['old_generic_protocol'] == fact(GENERIC/'OUTCOMES.json') and
             outcomes['commands'][:4] == old_outcomes['commands'],
             'all four original generic outcomes and assertions remain literal')
        names = outcomes['record_header_fields']
        need(names == old_outcomes['record_header_fields'] and len(names) == 17 and
             len(outcomes['commands']) == 9 and
             [c['name'] for c in outcomes['commands'][4:]] ==
             ['lodsq-positive', 'lodsq-none-df0', 'lodsq-none-df1', 'lodsq-split-df0', 'lodsq-split-df1'] and
             outcomes['bounds'] == dict(cpu_seconds=5, address_space_bytes=512 << 20,
                 file_size_bytes=16 << 20, wall_seconds=15, cpu_affinity_count=1),
             'complete original plus additive finite protocol under unchanged bounds')
        trailer_fields = outcomes['lodsq_trailer_fields']
        need(trailer_fields == ['magic', 'version', 'bytes', 'route_checks', 'footprint_checks',
                                'lodsq_pairs', 'native_faults', 'stepped_faults'],
             'exact bounded typed additive trailer')
        for case in outcomes['commands']:
            name = case['name']
            result = {'name': name, 'process_outcome': case['process_outcome'], 'accepted': False}
            record['cases'].append(result)
            _, out, err = run(name, [fixture, *case['argv'][1:]], case['exit'], env=case.get('environment_delta'))
            need(out == case['stdout'].encode() and err == case['stderr'].encode(), 'exact fixture output: '+name)
            data = (private/(name+'.record')).read_bytes()
            need(len(data) >= 136, 'retained complete header')
            header = dict(zip(names, struct.unpack_from('<17Q', data)))
            result.update(header=header, record=fact(private/(name+'.record')))
            need(all(header[key] == value for key, value in case['header_equals'].items()), 'exact header outcome: '+name)
            lodsq = name.startswith('lodsq-')
            old_extent = header['header_bytes']+22*header['sample_bytes']+40
            need(header['sample_bytes'] > 0 and len(data) == old_extent+(64 if lodsq else 0),
                 'complete original record slots plus exact separate LODSQ trailer')
            # Every omitted slot remains actual all-zero storage, never a
            # fabricated completed pair or a missing raw observation.
            first_unused = header['completed']
            need(not any(data[136+first_unused*header['sample_bytes']:136+21*header['sample_bytes']]),
                 'complete zero scan of all unused positive sample slots')
            if case['exit'] == 0:
                need(not any(data[136+21*header['sample_bytes']:136+22*header['sample_bytes']]),
                     'whole unused negative slot is zero')
            if lodsq:
                trailer = dict(zip(trailer_fields, struct.unpack_from('<8Q', data, old_extent)))
                need(trailer == case['trailer_equals'], 'exact actual query/fault/effect trailer: '+name)
                result['trailer'] = trailer
                record['totals']['executed_route_checks'] += trailer['route_checks']
                record['totals']['executed_footprint_checks'] += trailer['footprint_checks']
                record['totals']['lodsq_selftest_pairs'] += 1
                if name == 'lodsq-positive':
                    record['totals']['lodsq_pairs'] += 8
                else:
                    record['totals']['lodsq_verified_failed_operations'] += 1
            need(576 <= header['xsave_bytes'] <= 65536 and header['xcr0'] & 3 == 3, 'qualified XSAVE extent')
            result['accepted'] = True
            if name == 'positive':
                record['totals'].update(positive_pairs=21, generic_pairs=20, positive_selftest_pairs=1,
                                        supplied_refusal_encodings=47)
            elif not lodsq:
                record['totals']['verified_failed_operations'] += 1
                record['totals']['additional_negative_command_selftests'] += 1
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
        if record['final_errors']:
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
