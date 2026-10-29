#!/usr/bin/env python3
"""Exact EVEX512 VMOVDQU64 memory-load oracle with complete native/TF state."""
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

# Original row16 now requires a mandatory supplied Code1847/RANGE64 record; native populations and every other check remain.
sys.dont_write_bytecode = True
from checks import source
from run import hardware
from page_selected import ENV, fact, need, save
from page_selected_components import plain_executable
from page_selected_generic_build import Build, PROFILES as BUILD_PROFILES
from page_selected_process import invoke
from page_selected_vmovdqu64_promotions import promotions as vm64_promotions
from page_selected_vmovdqu64_256_promotions import promotions as vm256_promotions
from page_selected_vmovdqu64_store_promotions import promotions as vdq_store_promotions

REPO = Path(__file__).resolve().parents[2]
FIXTURE = REPO/'tools/page-entry/selected/tests/vmovdqu64'
PROFILES = dict(BUILD_PROFILES, fixture_link=[5, 512 << 20, 16 << 20, 15],
                native=[5, 512 << 20, 16 << 20, 15])


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def catalogue():
    path = FIXTURE/'cases.inc'
    binding = fact(path)
    need(binding['sha256'] == '69016a1ff281b0123d674cee57b5023926aa898670ce4cbb5c240b3a3fd712d4', 'exact reviewed m512 catalogue')
    rows = []
    for line in path.read_text().splitlines():
        if not line.startswith('  {'):
            continue
        match = re.fullmatch(r'  \{"(vmovdqu64_zmm17_pattern([0-2])_offset(256|257)_tail([1-6]))",([0-2]),(256|257),([1-6])\},', line)
        need(match is not None and match.group(2, 3, 4) == match.group(5, 6, 7), 'literal operand pattern/address/geometry')
        rows.append(dict(name=match[1], pattern=int(match[2]), offset=int(match[3]), tail=int(match[4])))
    need([(r['pattern'], r['offset'], r['tail']) for r in rows] ==
         [(pattern, offset, tail) for offset in (256, 257) for pattern in range(3) for tail in (6, 1, 2, 3, 4, 5)],
         'three literal memory patterns, aligned/unaligned, end and every crossing split')
    need(len({r['name'] for r in rows}) == 36, 'unique finite pairs')
    return dict(source=binding, counts=dict(new_pairs=36, aligned=18, unaligned=18,
                page_ending_pairs=6, crossing_pairs=30), rows_sha256=digest(rows))


def observations(data, group, header, fault_kind=0):
    need(len(data) == 5000, 'complete actual CPUID/XSAVE trailer')
    head = struct.unpack_from('<8Q', data)
    magic, version, extent, actual_group, count, checked, xcr0, size = head
    need((magic, version, extent, actual_group, checked, xcr0, size) ==
         (0x315854344d56324c, 1, 5000, group, 1 if fault_kind else 19, header['xcr0'], header['xsave_bytes']),
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
    ids = list(struct.unpack_from('<19Q', data, 3328))
    need(ids == ([0]*19 if fault_kind else [0]+list(range(5000+18*group, 5018+18*group))),
         'actual retained completed pair identities')
    bvs = [list(struct.unpack_from('<10Q', data, 3480+80*i)) for i in range(19)]
    need(not fault_kind or not any(v for row in bvs[1:] for v in row), 'uncompleted pair BV fields remain absent')
    for row in bvs[:checked]:
        need(all(v & 0xe7 == 0xe7 and not v & ~xcr0 for v in row), 'real non-init seed components present')
        need(len(set(row[:6])) == len(set(row[6:])) == 1,
             'exact kernel and live before/after XSTATE_BVs, separately observed without normalization')
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), checked=checked,
                query_count=count, cpuid_basic=[list(x) for x in basic],
                components=[dict(index=i, raw=list(components[i])) for i in active],
                kernel_xstate_bv=sorted({r[0] for r in bvs[:checked]}), live_xstate_bv=sorted({r[6] for r in bvs[:checked]}),
                xcr0=xcr0, xsave_bytes=size, all_bvs_sha256=digest(bvs), pair_ids_sha256=digest(ids))


def fault_observations(data, kind, header):
    need(len(data) == 96, 'complete actual fault trailer')
    fields = ('kind', 'checked', 'operand', 'address', 'prefix_bytes', 'owner_trace',
              'native_before_bv', 'native_after_bv', 'owner_before_bv', 'owner_after_bv',
              'live_before_bv', 'live_after_bv')
    raw = struct.unpack('<12Q', data)
    if not kind:
        need(not any(raw), 'no invented fault observations on completed cohort')
        return None
    row = dict(zip(fields, raw))
    need(row['kind'] == kind and row['checked'] == 1 and row['owner_trace'] == 0 and
         row['address'] > 4096 and row['address'] % 4096 == 0 and
         row['prefix_bytes'] == (32 if kind == 2 else 0) and
         row['operand'] == row['address']-row['prefix_bytes'], 'actual fault operand/guard geometry')
    need(all(v & 0xe7 == 0xe7 and not v & ~header['xcr0'] for v in raw[6:]) and
         len(set(raw[6:10])) == len(set(raw[10:])) == 1,
         'fault native/owner kernel BVs and live BVs unchanged separately')
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), **row)

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
                'observations': c.get('observations'), 'fault_observations': c.get('fault_observations'),
                'vdq_store_promotions': c.get('vdq_store_promotions'), 'vm64_promotions': c.get('vm64_promotions'), 'vm256_promotions': c.get('vm256_promotions')} for c in record['cases']],
        command_recipe={
            'selected_build': ['sh', 'tools/page-entry/selected/build.sh'],
            'fixture_build': ['sh', 'tools/page-entry/selected/tests/vmovdqu64/build.sh',
                              '<retained decoder.a>', '<private run directory>', 'tools/page-entry/selected'],
            'native': [['vmovdqu64-0'], ['vmovdqu64-1'], ['vmovdqu64-0'], ['vmovdqu64-0']],
            'native_environment_controls': ['absent', 'absent', 'LI2_VM64_CONTROL=full-read-fault', 'LI2_VM64_CONTROL=cross-read-fault'],
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
    name = stamp+'-page-selected-vmovdqu64-'+args.expect_revision[:12]
    private = REPO/'target/evaluation/inprocess'/name
    private.mkdir(parents=True, exist_ok=False)
    public = REPO/'evaluation/inprocess/results'/(name+'.json')
    record = {'schema_version': 1, 'profile': 'page-selected-vmovdqu64-oracle-v1', 'status': 'failed',
        'scope': 'Exact unmasked 62e1fe486f0f/Code1605, ZMM17 from64 bytes at RDI. Two19-pair cohorts:36 new plus2 startup, aligned/unaligned and every fetch split; all32ZMM/all8opmask independently seeded, actual standard-layout CPUID records, complete unchanged native/TF/kernelFP/liveXSAVE/memory comparisons. Two real read-fault commands (full/cross-page operand) retain failed operation125, no TRACE/completion and unchanged state/memory. All47 old+24 remaining new supplied refusals and seven mandatory typed Code1605/NONE promotions remain. One retained row12 additionally requires exact Code1604/NONE with separate native coverage. No general EVEX, enabled-CET, hardware masking, loader completion, performance or full-B2 claim Original row16 additionally requires exact Code1847/FALLTHROUGH/SIMD and full RANGE64 in a separate352-byte trailer in every success/fault record; native Code1847 coverage is a separately mandatory cohort.',
        'expected_revision': args.expect_revision, 'started_utc': stamp, 'cpu': cpu,
        'source': None, 'source_unchanged': False, 'commands': [], 'cases': [],
        'error': None, 'final_errors': [], 'bounds': PROFILES,
        'totals': {'vdq_store_typed_promotions': 0, 'vdq_store_supplied_range_queries': 0, 'vm256_typed_promotions': 0, 'vm256_supplied_none_queries': 0, 'positive_pairs': 0, 'generic_pairs': 0, 'positive_selftest_pairs': 0,
                   'supplied_refusal_encodings': 0, 'old_refusal_encodings': 0,
                   'new_refusal_encodings': 0, 'load_pairs': 0,
                   'new_page_ending_pairs': 0, 'new_crossing_pairs': 0,
                   'executed_refusal_checks': 0, 'verified_memory_failures': 0, 'negative_selftest_pairs': 0},
        'reproduce': ['python3', 'evaluation/inprocess/page_selected_vmovdqu64.py',
                      '--expect-revision', args.expect_revision]}
    pins, binaries = {}, {}
    fixtures = {name: private/name for name in ('vmovdqu64-0', 'vmovdqu64-1')}
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
        need(len(names) == 17 and len(outcomes['commands']) == 4, 'complete finite load/fault protocol')
        need(outcomes['schema_version'] == 1 and outcomes['record_header_format'] == '<17Q' and
             names == ['magic', 'version', 'header_bytes', 'sample_bytes', 'pairs', 'completed', 'control',
                       'xcr0', 'xsave_bytes', 'refusals', 'failed_refusal', 'decoder_result',
                       'expected_failure_verified', 'fixture_failure', 'owner_failure',
                       'owner_detail_abs', 'owner_detail_negative'] and
             [c['name'] for c in outcomes['commands']] ==
             ['group0', 'group1', 'full-read-fault', 'cross-read-fault'] and
             [c['exit'] for c in outcomes['commands']] == [0, 0, 125, 125] and
             [c['argv'] for c in outcomes['commands']] == [['vmovdqu64-0'], ['vmovdqu64-1'], ['vmovdqu64-0'], ['vmovdqu64-0']] and
             [c['environment_delta'] for c in outcomes['commands']] ==
             [{}, {}, {'LI2_VM64_CONTROL':'full-read-fault'}, {'LI2_VM64_CONTROL':'cross-read-fault'}] and
             outcomes['bounds'] == dict(cpu_seconds=5, address_space_bytes=512 << 20,
                 file_size_bytes=16 << 20, wall_seconds=15, cpu_affinity_count=1),
             'exact load/fault names, environments, exits, header schema and bounds')
        need(fact(FIXTURE/'OUTCOMES.json')['sha256'] ==
             '542903d34e699e085756331cca2740d3c1c3e2aa9d70a33087e5a7aea69a919d',
             'exact reviewed four-command outcomes')
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
            need(352<len(data)<16<<20,'complete Code1847 trailer within unchanged full cap')
            result['vdq_store_promotions']=vdq_store_promotions(data[-352:]);data=data[:-352]
            record['totals']['vdq_store_typed_promotions']+=1
            record['totals']['vdq_store_supplied_range_queries']+=1
            need(352<len(data)<16<<20,'complete Code1604 promotion trailer within unchanged cap')
            result['vm256_promotions']=vm256_promotions(data[-352:]);data=data[:-352]
            record['totals']['vm256_typed_promotions']+=result['vm256_promotions']['typed_promotions']
            record['totals']['vm256_supplied_none_queries']+=result['vm256_promotions']['supplied_none_queries']
            need(2080<len(data)<16<<20,'complete seven Code1605 promotions within old cap')
            result['vm64_promotions']=vm64_promotions(data[-2080:]);data=data[:-2080]
            need(len(data) >= 136, 'retained complete header')
            header = dict(zip(names, struct.unpack_from('<17Q', data)))
            result.update(header=header, record=fact(private/(name+'.record')))
            need(all(header[key] == value for key, value in case['header_equals'].items()), 'exact header outcome: '+name)
            need(header['sample_bytes'] > 0 and len(data) == header['header_bytes']+22*header['sample_bytes']+40+5000+96,
                 'complete actual record extent')
            need(576 <= header['xsave_bytes'] <= 65536 and header['xcr0'] & 3 == 3, 'qualified XSAVE extent')
            # The C fixture's authenticated binary enforces full-state effects;
            # retain all complete samples for independent actual-layout replay.
            is_positive = name in ('group0', 'group1')
            kind = 0 if is_positive else 1 if name == 'full-read-fault' else 2
            group = int(name[-1]) if is_positive else 0
            need(header['pairs'] == 19 and header['completed'] == (19 if is_positive else 1),
                 'exact completed pair prefix; fault never counts as completion')
            if is_positive:
                end = header['header_bytes']+19*header['sample_bytes']
                need(not any(data[end:end+3*header['sample_bytes']]), 'two unused slots and negative sample remain zero')
                result['operation_completed'] = True
                record['totals']['positive_pairs'] += 19
                record['totals']['generic_pairs'] += 18
                record['totals']['load_pairs'] += 18
                record['totals']['positive_selftest_pairs'] += 1
                record['totals']['new_page_ending_pairs'] += 3
                record['totals']['new_crossing_pairs'] += 15
            else:
                end = header['header_bytes']+header['sample_bytes']
                need(not any(data[end:end+20*header['sample_bytes']]), 'unstarted positive slots remain zero')
                result['verified_memory_fault'] = True
                record['totals']['verified_memory_failures'] += 1
                record['totals']['negative_selftest_pairs'] += 1
            result['observations'] = observations(data[-5096:-96], group, header, kind)
            result['fault_observations'] = fault_observations(data[-96:], kind, header)
            record['totals']['executed_refusal_checks'] += header['refusals']
            record['totals'].update(supplied_refusal_encodings=71,
                old_refusal_encodings=47, new_refusal_encodings=24)
            result['accepted'] = True
        need(record['totals'] == dict(vdq_store_typed_promotions=4, vdq_store_supplied_range_queries=4, vm256_typed_promotions=4, vm256_supplied_none_queries=4, positive_pairs=38, generic_pairs=36, load_pairs=36,
                 positive_selftest_pairs=2, supplied_refusal_encodings=71, old_refusal_encodings=47,
                 new_refusal_encodings=24, new_page_ending_pairs=6, new_crossing_pairs=30,
                 executed_refusal_checks=284, verified_memory_failures=2, negative_selftest_pairs=2) and len(record['cases']) == 4 and
             all(c['accepted'] for c in record['cases']),
             'complete two19-pair load cohorts and two genuine failed-read controls')
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
