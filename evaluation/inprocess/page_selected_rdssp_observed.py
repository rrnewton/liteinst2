#!/usr/bin/env python3
"""Canonical RDSSPQ with actual adjacent observations; strict query failures remain separate."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
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
FIXTURE = REPO/'tools/page-entry/selected/tests/rdssp_observed'
PROFILES = dict(BUILD_PROFILES, fixture_link=[5, 512 << 20, 16 << 20, 15],
                native=[5, 512 << 20, 16 << 20, 15])


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def catalogue():
    path = FIXTURE/'OUTCOMES.json'
    binding = fact(path)
    need(binding['sha256'] == '62a6024f6125118c2a5e7c6e56fa5c1ea630505a38173c833ef653b1b7783449', 'exact reviewed observed-SHSTK protocol and catalogue')
    protocol = json.loads(path.read_bytes())
    expected = [dict(group=g, reg=r, bytes=bytes([0xf3, 0x48 if r < 8 else 0x49,
                   0x0f, 0x1e, 0xc8+(r & 7)]).hex(), tail=tail, code=1053)
                for g in range(2) for r in range(g*8, g*8+8) for tail in (5, 4)]
    need(protocol['pairs'] == expected and len(expected) == 32 and
         expected[0]['bytes'] == 'f3480f1ec8' and
         {r['reg'] for r in expected} == set(range(16)),
         'all canonical r64 destinations, actual loader opcode and ending/crossing geometry')
    return dict(source=binding, counts=dict(new_pairs=32, page_ending_pairs=16,
                crossing_pairs=16, r64_destinations=16), rows_sha256=digest(expected))


def probe_instructions(path, symbols, symbol, production=False):
    """Bind the actual separately emitted helper and its two adjacent opcodes."""
    rows = [line.split() for line in symbols.decode('ascii').splitlines()
            if line.split()[-1:] == [symbol]]
    need(len(rows) == 1, 'one emitted observation helper')
    row = rows[0]
    need(len(row) == 8 and row[3] == 'FUNC' and row[6].isdigit() and
         (row[4:6] in (['LOCAL', 'DEFAULT'], ['GLOBAL', 'HIDDEN']) if production else
          row[4:6] == ['GLOBAL', 'DEFAULT']), 'defined observation text symbol')
    address, size = int(row[1], 16), int(row[2])
    data = path.read_bytes()
    need(data[:7] == b'\x7fELF\x02\x01\x01' and len(data) >= 64 and
         struct.unpack_from('<H', data, 18)[0] == 62, 'actual x86-64 helper ELF')
    phoff = struct.unpack_from('<Q', data, 32)[0]
    phsize, phnum = struct.unpack_from('<HH', data, 54)
    need(phsize == 56 and phnum > 0 and phoff+phsize*phnum <= len(data), 'helper program table')
    matches = []
    for i in range(phnum):
        kind, flags, offset, va, _, filesz, memsz, _ = struct.unpack_from('<II6Q', data, phoff+i*phsize)
        if kind == 1 and va <= address and address+size <= va+filesz:
            need(flags == 5 and filesz <= memsz and offset+filesz <= len(data), 'immutable RX helper bytes')
            start = offset+address-va
            matches.append(data[start:start+size])
    need(len(matches) == 1 and size >= 10, 'single complete helper extent')
    code = matches[0]
    pair = bytes.fromhex('f3480f1ec8f3480f1eca')
    need(code.count(pair) == 1, 'actual adjacent RAX/RDX RDSSPQ pair')
    return dict(symbol=symbol, symbol_bytes=size, code_sha256=hashlib.sha256(code).hexdigest(),
                pair_offset=code.index(pair), exact_pair=pair.hex())


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
        fixtures=record.get('fixtures'), catalogue=record.get('catalogue'),
        emitted_observations=record.get('emitted_observations'),
        build_status=build.get('status', 'not_started'),
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
        cases=[{'name': c['name'], 'accepted': c['accepted'], 'process_outcome': c['process_outcome'],
                'actual_exit': c.get('actual_exit'), 'operation_completed': c.get('operation_completed'),
                'verified_preopen_refusal': c.get('verified_preopen_refusal'),
                'query_evidence': c.get('query_evidence'),
                'header': c.get('header'), 'record': c.get('record')} for c in record['cases']],
        command_recipe={
            'selected_build': ['sh', 'tools/page-entry/selected/build.sh'],
            'fixture_build': ['sh', 'tools/page-entry/selected/tests/rdssp_observed/build.sh',
                              '<retained decoder.a>', '<private run directory>', 'tools/page-entry/selected'],
            'native': [['rdssp-observed-0'], ['rdssp-observed-1']]+[['rdssp-observed-0']]*5,
            'native_environment_controls': ['absent', 'absent', 'query-einval', 'query-enosys', 'status-shstk', 'status-wrss', 'observed-equal'],
            'control_variable': 'LI2_RDSSP_CONTROL',
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
    name = stamp+'-page-selected-rdssp-observed-'+args.expect_revision[:12]
    private = REPO/'target/evaluation/inprocess'/name
    private.mkdir(parents=True, exist_ok=False)
    public = REPO/'evaluation/inprocess/results'/(name+'.json')
    record = {'schema_version': 1, 'profile': 'page-selected-rdssp-observed-oracle-v1', 'status': 'failed',
        'scope': 'Distinct observed-SHSTK path: 32 canonical RDSSPQ original-PC native/TF no-op pairs plus two startup pairs. Every native and owner entry retains two adjacent actual RDSSPQ outputs and requires both distinct seeds unchanged before target execution. Actual kernel status queries remain diagnostic; their errors grant no authority. Four unchanged strict query-path negative commands retain failed125 operations. One distinct observed-owner command supplies equal outputs at real NX and must fail107 before opening; eight pure supplied observation-rejection checks per command remain separate. None claims enabled-CET execution. All old encoding refusals/full-state/literal-memory predicates remain required. Query-only ac1d238 positive remains failed. Existing generic and all other required suites remain separate. No RDSSPD, enabled-CET, IBT proof, loader completion, performance or full-B2 claim.',
        'expected_revision': args.expect_revision, 'started_utc': stamp, 'cpu': cpu,
        'source': None, 'source_unchanged': False, 'commands': [], 'cases': [],
        'error': None, 'final_errors': [], 'bounds': PROFILES,
        'totals': {'positive_pairs': 0, 'generic_pairs': 0, 'positive_selftest_pairs': 0,
                   'rdsspq_pairs': 0, 'actual_native_disabled_observations': 0, 'actual_owner_disabled_observations': 0,
                   'actual_native_diagnostic_queries': 0, 'actual_owner_diagnostic_queries': 0,
                   'supplied_observation_refusals': 0, 'executed_supplied_observation_refusals': 0,
                   'strict_query_refusal_commands': 0, 'supplied_owner_refusal_commands': 0,
                   'supplied_refusal_encodings': 0, 'old_refusal_encodings': 0, 'new_refusal_encodings': 0,
                   'new_page_ending_pairs': 0, 'new_crossing_pairs': 0,
                   'verified_preopen_refusal_commands': 0, 'nonissued_query_injections': 0,
                   'actual_native_failed_operations': 0, 'additional_negative_command_selftests': 0,
                   'executed_refusal_checks': 0},
        'reproduce': ['python3', 'evaluation/inprocess/page_selected_rdssp_observed.py',
                      '--expect-revision', args.expect_revision]}
    pins, binaries = {}, {}
    fixtures = {name: private/name for name in ('rdssp-observed-0', 'rdssp-observed-1')}
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
        _, out, err = run('production-probe-symbols', [build.tools['readelf'], '-Ws', products['bridge']],
                          profile='inspect', env=build.environment)
        need(not err, 'production observation symbol inspection stderr')
        record['emitted_observations'] = {'production': probe_instructions(products['bridge'], out,
            'li2_tf_observe_shstk', production=True)}
        run('fixture-build', [build.tools['sh'], FIXTURE/'build.sh', products['archive'], private, REPO/'tools/page-entry/selected'],
            profile='fixture_link', env=build.environment)
        support = private/'rdssp-observed-support'
        actual_owner = (REPO/'tools/page-entry/selected/step_owner.c').read_bytes()
        actual_tf = (REPO/'tools/page-entry/selected/tf_owner.inc').read_bytes()
        original_name = b'__attribute__((noinline)) int li2_tf_observe_shstk('
        supplied_name = b'__attribute__((noinline)) int li2_tf_actual_observe_shstk('
        need(actual_tf.count(original_name) == 1 and supplied_name not in actual_tf and
             (support/'step_owner.c').read_bytes() == actual_owner and
             (support/'tf_owner.inc').read_bytes() == actual_tf.replace(original_name, supplied_name),
             'definition-only test boundary; all actual owner calls and guards preserved')
        record['test_adapter'] = {name: fact(binary(support/name)) for name in ('step_owner.c', 'tf_owner.inc')}
        record['fixtures'], record['elf'] = {}, {}
        for fixture_name, fixture in fixtures.items():
            binary(fixture)
            record['fixtures'][fixture_name] = fact(fixture)
            record['elf'][fixture_name] = plain_executable(fixture)
            _, out, err = run(fixture_name+'-undefined', [build.tools['nm'], '-u', fixture],
                              profile='inspect', env=build.environment)
            need(not out and not err, 'no undefined fixture symbols')
            _, out, err = run(fixture_name+'-probe-symbols', [build.tools['readelf'], '-Ws', fixture],
                              profile='inspect', env=build.environment)
            need(not err, 'observation symbol inspection stderr')
            record.setdefault('emitted_observations', {})[fixture_name] = probe_instructions(fixture, out, 'li2_tf_actual_observe_shstk')
        record['catalogue'] = catalogue()
        outcomes = json.loads((FIXTURE/'OUTCOMES.json').read_bytes())
        names = outcomes['record_header_fields']
        need(len(names) == 17 and len(outcomes['commands']) == 7, 'complete finite RDSSPQ protocol')
        controls = ['query-einval', 'query-enosys', 'status-shstk', 'status-wrss', 'observed-equal']
        need(outcomes['schema_version'] == 1 and outcomes['record_header_format'] == '<17Q' and
             names == ['magic', 'version', 'header_bytes', 'sample_bytes', 'pairs', 'completed', 'control',
                       'xcr0', 'xsave_bytes', 'refusals', 'failed_refusal', 'decoder_result',
                       'expected_failure_verified', 'fixture_failure', 'owner_failure',
                       'owner_detail_abs', 'owner_detail_negative'] and
             [c['name'] for c in outcomes['commands']] == ['group0', 'group1']+controls and
             [c['exit'] for c in outcomes['commands']] == [0, 0, 125, 125, 125, 125, 125] and
             [c['argv'] for c in outcomes['commands']] == [['rdssp-observed-0'], ['rdssp-observed-1']]+[['rdssp-observed-0']]*5 and
             [c['environment_delta'] for c in outcomes['commands']] ==
             [{}, {}]+[{'LI2_RDSSP_CONTROL': n} for n in controls] and
             outcomes['bounds'] == dict(cpu_seconds=5, address_space_bytes=512 << 20,
                 file_size_bytes=16 << 20, wall_seconds=15, cpu_affinity_count=1),
             'exact RDSSPQ names, input environments, exits, header schema and bounds')
        seed_a, seed_b = 0x13579bdf2468ace1, 0xfedcba9876543210
        need(outcomes['query_trailer'] == dict(bytes=2080, header_format='<6Q',
             header_fields=['magic', 'version', 'bytes', 'actual_native_queries', 'injected_calls', 'injected_control'],
             magic=0x315053534452324c, query_count=21, query_format='<QQqQ',
             query_fields=['attempted', 'complete', 'result', 'features'], version=2,
             observation_count=21, observation_format='<8Q', observation_fields=[
                 'version', 'attempted', 'complete', 'reserved', 'seed_a', 'seed_b', 'value_a', 'value_b'],
             observation_offset=720, supplied_observation_refusals_offset=2064,
             supplied_observation_refusals=8, supplied_owner_observations_offset=2072, seeds=[seed_a, seed_b]), 'closed actual-query and observation trailer schema')
        for case in outcomes['commands']:
            name = case['name']
            result = {'name': name, 'process_outcome': case['process_outcome'], 'accepted': False,
                      'actual_exit': None, 'operation_completed': False,
                      'verified_preopen_refusal': False}
            record['cases'].append(result)
            row, out, err = run(name, [fixtures[case['argv'][0]], *case['argv'][1:]], case['exit'],
                                env=case['environment_delta'])
            result['actual_exit'] = row['exit']
            need(out == case['stdout'].encode() and err == case['stderr'].encode(), 'exact fixture output: '+name)
            data = (private/(name+'.record')).read_bytes()
            need(len(data) >= 136, 'retained complete header')
            header = dict(zip(names, struct.unpack_from('<17Q', data)))
            result.update(header=header, record=fact(private/(name+'.record')))
            need(all(header[key] == value for key, value in case['header_equals'].items()), 'exact header outcome: '+name)
            need(header['sample_bytes'] > 0 and len(data) == header['header_bytes']+22*header['sample_bytes']+40+2080,
                 'complete actual record extent')
            need(576 <= header['xsave_bytes'] <= 65536 and header['xcr0'] & 3 == 3, 'qualified XSAVE extent')
            # The C fixture's authenticated binary enforces full-state effects;
            # retain all complete samples for independent actual-layout replay.
            positive = name in ('group0', 'group1')
            used = 17 if positive else 1
            start = header['header_bytes']+used*header['sample_bytes']
            end = header['header_bytes']+21*header['sample_bytes']
            need(not any(data[start:end]), 'all unused original sample slots remain zero')
            trailer = data[-2080:]
            qheader = struct.unpack_from('<6Q', trailer)
            queries = [struct.unpack_from('<QQqQ', trailer, 48+i*32) for i in range(21)]
            observations = [struct.unpack_from('<8Q', trailer, 720+i*64) for i in range(21)]
            supplied, supplied_owner = struct.unpack_from('<2Q', trailer, 2064)
            observed_failure = name == 'observed-equal'
            control = 0 if positive else controls.index(name)+1
            need(qheader == (0x315053534452324c, 2, 2080, 16 if positive else 0,
                             0 if positive or observed_failure else 1,
                             0 if observed_failure else control), 'actual query counts and injection identity')
            for i, query in enumerate(queries):
                if positive and 1 <= i <= 16:
                    need(query[:2] == (1, 1) and -4095 <= query[2] <= 0 and
                         (query[2] != 0 or query[3] == 0), 'actual diagnostic query and no status contradiction')
                else:
                    need(query == (0, 0, 0, 0), 'unused native query slot is zero')
            expected_observations = [(1, 1, 1, 0, seed_a, seed_b, seed_a, seed_b)
                                     if positive and 1 <= i <= 16 else (0,)*8 for i in range(21)]
            need(observations == expected_observations, 'each actual adjacent observation preserved exact distinct seeds')
            need(supplied == 8 and supplied_owner == int(observed_failure),
                 'separate supplied predicate and real-owner refusal counts')
            result['query_evidence'] = dict(actual_native_diagnostic_queries=qheader[3],
                actual_owner_diagnostic_queries=16 if positive else int(observed_failure),
                native_query_results=[list(q) for q in queries[1:17]] if positive else [],
                actual_native_disabled_observations=16 if positive else 0,
                actual_owner_disabled_observations=16 if positive else 0,
                actual_observation_values=[seed_a, seed_b] if positive else None,
                supplied_observation_refusals=supplied, supplied_owner_observations=supplied_owner,
                nonissued_query_injections=qheader[4], injection_control=qheader[5],
                trailer_sha256=hashlib.sha256(trailer).hexdigest())
            record['totals']['supplied_observation_refusals'] = supplied
            record['totals']['executed_supplied_observation_refusals'] += supplied
            record['totals']['executed_refusal_checks'] += header['refusals']
            if positive:
                need(not any(data[end:end+header['sample_bytes']]), 'positive has no negative sample')
                result['operation_completed'] = True
                record['totals']['positive_pairs'] += used
                record['totals']['generic_pairs'] += used-1
                record['totals']['rdsspq_pairs'] += used-1
                record['totals']['positive_selftest_pairs'] += 1
                record['totals']['actual_native_disabled_observations'] += 16
                record['totals']['actual_owner_disabled_observations'] += 16
                record['totals']['actual_native_diagnostic_queries'] += 16
                record['totals']['actual_owner_diagnostic_queries'] += 16
                record['totals']['new_page_ending_pairs'] += 8
                record['totals']['new_crossing_pairs'] += 8
                record['totals'].update(supplied_refusal_encodings=63,
                    old_refusal_encodings=47, new_refusal_encodings=16)
            else:
                need(any(data[end:end+header['sample_bytes']]), 'retain actual failed-operation sample')
                # Both distinct source-bound failure comparators require real
                # NX, no opening/TRACE/continuation, unchanged state and held borrow.
                # Four query controls are strict/nonissued; the fifth issues its
                # actual diagnostic query but supplies equal observation outputs.
                # Every target operation stays failed with no completion credit.
                result['verified_preopen_refusal'] = True
                record['totals']['verified_preopen_refusal_commands'] += 1
                if observed_failure:
                    record['totals']['supplied_owner_refusal_commands'] += 1
                    record['totals']['actual_owner_diagnostic_queries'] += 1
                else:
                    record['totals']['nonissued_query_injections'] += 1
                    record['totals']['strict_query_refusal_commands'] += 1
                record['totals']['additional_negative_command_selftests'] += 1
            result['accepted'] = True
        need(record['totals'] == dict(positive_pairs=34, generic_pairs=32, rdsspq_pairs=32,
                 positive_selftest_pairs=2, actual_native_disabled_observations=32, actual_owner_disabled_observations=32,
                 actual_native_diagnostic_queries=32, actual_owner_diagnostic_queries=33,
                 supplied_observation_refusals=8, executed_supplied_observation_refusals=56,
                 strict_query_refusal_commands=4, supplied_owner_refusal_commands=1,
                 supplied_refusal_encodings=63, old_refusal_encodings=47, new_refusal_encodings=16,
                 new_page_ending_pairs=16, new_crossing_pairs=16,
                 verified_preopen_refusal_commands=5, nonissued_query_injections=4,
                 actual_native_failed_operations=0, additional_negative_command_selftests=5,
                 executed_refusal_checks=441) and
             len(record['cases']) == 7 and all(c['accepted'] for c in record['cases']),
             'complete two17-pair cohorts, four strict failures and one observed-owner failure')
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
        for fixture_name, fixture in fixtures.items():
            try:
                if fixture.is_file():
                    value = fact(fixture)
                    record.setdefault('fixtures_after', {})[fixture_name] = value
                    record.setdefault('fixtures', {}).setdefault(fixture_name, value)
                    binary(fixture)
            except BaseException as exc:
                record['final_errors'].append('fixture retention '+fixture_name+': '+repr(exc))
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
