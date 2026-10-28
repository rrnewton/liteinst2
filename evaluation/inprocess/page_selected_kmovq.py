#!/usr/bin/env python3
"""Exact KMOVQ RSI,K0 register oracle with complete native/TF state."""
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
FIXTURE = REPO/'tools/page-entry/selected/tests/kmovq'
PROFILES = dict(BUILD_PROFILES, fixture_link=[5, 512 << 20, 16 << 20, 15],
                native=[5, 512 << 20, 16 << 20, 15])


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def catalogue():
    path = FIXTURE/'cases.inc'
    binding = fact(path)
    need(binding['sha256'] == 'ab4393a8b6fb0df9b3339c42cdfa0e029f78cf5dd172a98c4b6c153dfa07e69d', 'exact reviewed KMOVQ catalogue')
    rows = []
    for line in path.read_text().splitlines():
        if not line.startswith('  {'):
            continue
        match = re.fullmatch(r'  \{"(kmv_rsi_k0_pattern([0-3])_tail([1-5]))",([0-3]),([1-5]),UINT64_C\(0x([0-9a-f]{16})\),UINT64_C\(0x([0-9a-f]{16})\)\},', line)
        need(match is not None and match[2] == match[4] and match[3] == match[5], 'literal input identity/geometry')
        rows.append(dict(name=match[1], pattern=int(match[2]), tail=int(match[3]), k0=int(match[6],16), initial_rsi=int(match[7],16)))
    patterns = [0, (1 << 64)-1, 0x8000000000000001, 0x0123456789abcdef]
    need([(r['pattern'], r['tail'], r['k0'], r['initial_rsi']) for r in rows] ==
         [(p,t,k,k ^ ((1 << 64)-1)) for p,k in enumerate(patterns) for t in (5,1,2,3,4)],
         'zero/all1/high-bit/mixed full-width K0 inputs and every fetch geometry')
    need(len({r['name'] for r in rows}) == 20 and all(r['initial_rsi'] != r['k0'] for r in rows),
         'unique pairs and stale destination disqualified')
    return dict(source=binding, counts=dict(new_pairs=20, page_ending_pairs=4, crossing_pairs=16), rows_sha256=digest(rows))

def observations(data, group, header):
    need(len(data) == 5176, 'complete actual CPUID/XSAVE trailer')
    head = struct.unpack_from('<8Q', data)
    magic, version, extent, actual_group, count, checked, xcr0, size = head
    need((magic, version, extent, actual_group, checked, xcr0, size) ==
         (0x3158564d4b56324c, 1, 5176, group, 21, header['xcr0'], header['xsave_bytes']),
         'exact trailer identity and observed input joins')
    tuples = [struct.unpack_from('<6Q', data, 64+48*i) for i in range(68)]
    basic, components = tuples[:4], tuples[4:]
    need([x[:2] for x in basic] == [(0, 0), (1, 0), (7, 0), (13, 0)] and
         all(all(v < 1 << 32 for v in q) for q in tuples), 'actual CPUID tuple identities and register width')
    need(basic[0][2] >= 13 and basic[1][4] & 0x1c000000 == 0x1c000000 and
         basic[2][3] & 0x40010000 == 0x40010000, 'actual XSAVE/OSXSAVE/AVX/AVX512F/BW prerequisites')
    supported = basic[3][2] | basic[3][5] << 32
    need(xcr0 & 0xe7 == 0xe7 and not xcr0 & ~supported and not xcr0 >> 63 and
         basic[3][3] == size <= basic[3][4], 'actual enabled standard XSAVE capacity')
    active = [i for i in range(2, 63) if xcr0 >> i & 1]
    need(count == 4+len(active), 'every enabled extended component queried exactly once')
    regions = []
    for i, q in enumerate(components):
        if i not in active:
            need(not any(q), 'unqueried component remains absent')
            continue
        leaf, index, n, offset, flags, reserved = q
        need((leaf, index) == (13, i) and n > 0 and 576 <= offset <= size and
             n <= size-offset and not flags & 1, 'user standard-layout tuple and bounds')
        need(all(offset >= end or start >= offset+n for start, end in regions), 'all enabled components disjoint')
        regions.append((offset, offset+n))
    need([components[i][2] for i in (2, 5, 6, 7)] == [256, 64, 512, 1024],
         'architectural YMM/opmask/ZMM_Hi256/Hi16_ZMM extents')
    ids = list(struct.unpack_from('<21Q', data, 3328))
    need(ids == [0]+list(range(7000+20*group, 7020+20*group)), 'actual retained pair identities')
    bvs = [list(struct.unpack_from('<10Q', data, 3496+80*i)) for i in range(21)]
    for row in bvs:
        need(all(v & 0xe7 == 0xe7 and not v & ~xcr0 for v in row), 'real non-init seed components present')
        need(len(set(row[:6])) == len(set(row[6:])) == 1,
             'exact kernel and live before/after XSTATE_BVs, separately observed without normalization')
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), checked=checked,
                query_count=count, cpuid_basic=[list(x) for x in basic],
                components=[dict(index=i, raw=list(components[i])) for i in active],
                kernel_xstate_bv=sorted({r[0] for r in bvs}), live_xstate_bv=sorted({r[6] for r in bvs}),
                xcr0=xcr0, xsave_bytes=size, all_bvs_sha256=digest(bvs), pair_ids_sha256=digest(ids))

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
                'verified_memory_fault': c.get('verified_memory_fault'),
                'header': c.get('header'), 'record': c.get('record'),
                'observations': c.get('observations')} for c in record['cases']],
        command_recipe={
            'selected_build': ['sh', 'tools/page-entry/selected/build.sh'],
            'fixture_build': ['sh', 'tools/page-entry/selected/tests/kmovq/build.sh',
                              '<retained decoder.a>', '<private run directory>', 'tools/page-entry/selected'],
            'native': [['kmovq-0']],
            'native_environment_controls': ['absent'],
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
    name = stamp+'-page-selected-kmovq-'+args.expect_revision[:12]
    private = REPO/'target/evaluation/inprocess'/name
    private.mkdir(parents=True, exist_ok=False)
    public = REPO/'evaluation/inprocess/results'/(name+'.json')
    record = {'schema_version': 1, 'profile': 'page-selected-kmovq-oracle-v1', 'status': 'failed',
        'scope': 'Exactc4e1fb93f0/Code1933 KMOVQ RSI,K0. One21-pair cohort:20 new plus startup, four full-width K0 patterns across all five fetch geometries. Complete64-bit RSI result, all32ZMM/all8K and every other register/flags/memory unchanged, actual kernel/live XSAVE and endpoints compared. All47 old+28 retained supplied refusals and5 explicit typed1933/NONE promotions. No memory operand or invented operand-fault claim; original fault suites remain required separately. No general VEX, enabled-CET, hardware masking, real-program completion, speedup or full-B2 claim.',
        'expected_revision': args.expect_revision, 'started_utc': stamp, 'cpu': cpu,
        'source': None, 'source_unchanged': False, 'commands': [], 'cases': [],
        'error': None, 'final_errors': [], 'bounds': PROFILES,
        'totals': {'positive_pairs': 0, 'generic_pairs': 0, 'positive_selftest_pairs': 0,
                   'supplied_refusal_encodings': 0, 'old_refusal_encodings': 0,
                   'new_refusal_encodings': 0, 'register_move_pairs': 0,
                   'new_page_ending_pairs': 0, 'new_crossing_pairs': 0,
                   'executed_refusal_checks': 0, 'promoted_encoding_checks': 0, 'promoted_footprint_queries': 0},
        'reproduce': ['python3', 'evaluation/inprocess/page_selected_kmovq.py',
                      '--expect-revision', args.expect_revision]}
    pins, binaries = {}, {}
    fixtures = {name: private/name for name in ('kmovq-0',)}
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
        run('fixture-build', [build.tools['sh'], FIXTURE/'build.sh', products['archive'], private, REPO/'tools/page-entry/selected'],
            profile='fixture_link', env=build.environment)
        record['fixtures'], record['elf'] = {}, {}
        for fixture_name, fixture in fixtures.items():
            binary(fixture)
            record['fixtures'][fixture_name] = fact(fixture)
            record['elf'][fixture_name] = plain_executable(fixture)
            _, out, err = run(fixture_name+'-undefined', [build.tools['nm'], '-u', fixture],
                              profile='inspect', env=build.environment)
            need(not out and not err, 'no undefined fixture symbols')
        record['catalogue'] = catalogue()
        outcomes = json.loads((FIXTURE/'OUTCOMES.json').read_bytes())
        names = outcomes['record_header_fields']
        need(len(names) == 17 and len(outcomes['commands']) == 1, 'complete finite register-move protocol')
        need(outcomes['schema_version'] == 1 and outcomes['record_header_format'] == '<17Q' and
             names == ['magic', 'version', 'header_bytes', 'sample_bytes', 'pairs', 'completed', 'control',
                       'xcr0', 'xsave_bytes', 'refusals', 'failed_refusal', 'decoder_result',
                       'expected_failure_verified', 'fixture_failure', 'owner_failure',
                       'owner_detail_abs', 'owner_detail_negative'] and
             [c['name'] for c in outcomes['commands']] ==
             ['group0'] and
             [c['exit'] for c in outcomes['commands']] == [0] and
             [c['argv'] for c in outcomes['commands']] == [['kmovq-0']] and
             [c['environment_delta'] for c in outcomes['commands']] == [{}] and
             outcomes['bounds'] == dict(cpu_seconds=5, address_space_bytes=512 << 20,
                 file_size_bytes=16 << 20, wall_seconds=15, cpu_affinity_count=1),
             'exact register-move names, environments, exits, header schema and bounds')
        need(fact(FIXTURE/'OUTCOMES.json')['sha256'] ==
             'f7787136f8710f7c16f557fb2edc05f67d80e4dd8ed00adf67f5cf926a5fba32',
             'exact reviewed one-command outcomes')
        for case in outcomes['commands']:
            name = case['name']
            result = {'name': name, 'process_outcome': case['process_outcome'], 'accepted': False,
                      'actual_exit': None, 'operation_completed': False,
                      'verified_memory_fault': False}
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
            need(header['sample_bytes'] > 0 and len(data) == header['header_bytes']+22*header['sample_bytes']+40+5176,
                 'complete actual record extent')
            need(576 <= header['xsave_bytes'] <= 65536 and header['xcr0'] & 3 == 3, 'qualified XSAVE extent')
            # The C fixture's authenticated binary enforces full-state effects;
            # retain all complete samples for independent actual-layout replay.
            need(name == 'group0' and header['completed'] == header['pairs'] == 21,
                 'every expected positive pair completed')
            end = header['header_bytes']+21*header['sample_bytes']
            need(not any(data[end:end+header['sample_bytes']]), 'negative sample remains zero; all21 positive slots occupied')
            result['observations'] = observations(data[-5176:], int(name[-1]), header)
            result['operation_completed'] = True
            record['totals']['positive_pairs'] += 21
            record['totals']['generic_pairs'] += 20
            record['totals']['register_move_pairs'] += 20
            record['totals']['positive_selftest_pairs'] += 1
            record['totals']['new_page_ending_pairs'] += 4
            record['totals']['new_crossing_pairs'] += 16
            record['totals']['executed_refusal_checks'] += header['refusals']
            record['totals'].update(supplied_refusal_encodings=75,
                old_refusal_encodings=47, new_refusal_encodings=28,
                promoted_encoding_checks=5, promoted_footprint_queries=5)
            result['accepted'] = True
        need(record['totals'] == dict(positive_pairs=21, generic_pairs=20, register_move_pairs=20,
                 positive_selftest_pairs=1, supplied_refusal_encodings=75, old_refusal_encodings=47,
                 new_refusal_encodings=28, new_page_ending_pairs=4, new_crossing_pairs=16,
                 executed_refusal_checks=75, promoted_encoding_checks=5, promoted_footprint_queries=5) and len(record['cases']) == 1 and
             all(c['accepted'] for c in record['cases']),
             'complete one21-pair register-move cohort; original fault suites remain separate')
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
