#!/usr/bin/env python3
"""Exact EVEX256 VPTESTMB register oracle with complete native/TF state."""
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
from page_selected_vptestnmb_promotions import promotions as vtn_promotions
from page_selected_vptestmb256_promotions import promotions as vtm256_promotions

REPO = Path(__file__).resolve().parents[2]
FIXTURE = REPO/'tools/page-entry/selected/tests/vptestmb256'
GROUP_COUNTS = (18,18,18,18,6)
PROFILES = dict(BUILD_PROFILES, fixture_link=[5, 512 << 20, 16 << 20, 15],
                native=[5, 512 << 20, 16 << 20, 15])


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def catalogue():
    path = FIXTURE/'cases.inc'
    binding = fact(path)
    need(fact(FIXTURE/'neighbors.inc')['sha256'] == '16d764ca7a058cbb452620a828e6cd245c2c97a5dafb9e6a165710484615f610',
         'exact additive 37-row unsupported-neighbor source')
    need(binding['sha256'] == 'd8ea4604d93cc0c1374751ffc42a373ebbc2c72cb52214965cb424433ef9c43b', 'exact reviewed AND-nonzero/mask catalogue')
    pattern = re.compile(r'  \{([0-9,]+),\{([0-9a-fx,]+)\},UINT64_C\(0x([0-9a-f]{16})\),UINT64_C\(0x([0-9a-f]{16})\),UINT64_C\(0x([0-9a-f]{16})\)\},')
    rows = []
    edge = [0,255,1,128,85,170,127,254]
    literals = [([edge[i%8] for i in range(64)], [edge[i%8] for i in range(64)]),
                ([1<<(i%8) for i in range(64)], [255^(1<<(i%8)) for i in range(64)]),
                ([(37*i+128)&255 for i in range(64)],
                 [((37*i+128)&255) if i%3==0 else ((255^((37*i+128)&255)) if i%3==1 else 1<<(i%8)) for i in range(64)])]
    for match in pattern.finditer(path.read_text()):
        p, tail, a, b, d, m = map(int, match[1].split(','))
        encoded = bytes(int(x,16) for x in match[2].split(','))
        initial, mask, expected = (int(match[i],16) for i in (3,4,5))
        need(p < 3 and 1 <= tail <= 6 and a < 32 and b < 32 and d < 8 and m < 8,
             'canonical case fields')
        actual_encoding = bytes([0x62,0x92|((1-(b>>4&1))<<6)|((1-(b>>3&1))<<5),
            5|((~a&15)<<3),0x20|((1-(a>>4&1))<<3)|m,0x26,0xc0|(d<<3)|(b&7)])
        need(encoded == actual_encoding and initial and (not m or m != d or mask == initial),
             'literal encoding and destination/writemask pre-state alias')
        lhs, rhs = literals[p]
        if a == b:
            rhs = lhs
        answer = sum(1<<i for i,(x,y) in enumerate(zip(lhs[:32],rhs[:32])) if (x&y)!=0 and (not m or mask>>i&1))
        need(answer == expected, 'independent per-byte AND-nonzero and zero-masking literal')
        rows.append(dict(pattern=p,tail=tail,src1=a,src2=b,destination=d,
                         writemask=m,initial=initial,mask_value=mask,expected=expected,encoding=encoded.hex()))
    need(len(rows) == 78 and {r['src1'] for r in rows} == {r['src2'] for r in rows} == set(range(32)) and
         {r['destination'] for r in rows} == {r['writemask'] for r in rows} == set(range(8)),
         'complete vector/K index coverage')
    need([(r['src1'],r['src2'],r['destination'],r['writemask']) for r in rows[:32]] ==
         [(i,(7*i+17)%32,i%8,i//4) for i in range(32)] and
         [r['encoding'] for r in rows[32:50]] == ['62b2752126c1']*18 and
         [r['encoding'] for r in rows[50:68]] == ['62b2752026c1']*18 and
         all([(r['pattern'],r['tail']) for r in group] == [(p,t) for p in range(3) for t in (6,1,2,3,4,5)]
             for group in (rows[32:50],rows[50:68])) and
         all(r['src1'] == r['src2'] and r['destination'] == r['writemask'] for r in rows[68:72]) and
         [(r['pattern'],r['tail'],r['src1'],r['src2'],r['destination'],r['writemask'],r['encoding']) for r in rows[72:]] ==
         [(0,t,20,20,1,0,'62b25d2026cc') for t in range(1,7)],
         'index coverage, observed masked/promoted unmasked geometries and source/mask aliases')
    return dict(source=binding,counts=dict(new_pairs=78,page_ending_pairs=12,crossing_pairs=66),
                rows_sha256=digest(rows), groups=[dict(ending=sum(r['tail']==6 for r in rows[g*18:(g+1)*18]),
                    crossing=sum(r['tail']<6 for r in rows[g*18:(g+1)*18])) for g in range(5)])

def observations(data, group, header):
    need(len(data) == 5000, 'complete actual CPUID/XSAVE trailer')
    head = struct.unpack_from('<8Q', data)
    magic, version, extent, actual_group, count, checked, xcr0, size = head
    need((magic, version, extent, actual_group, checked, xcr0, size) ==
         (0x3158324d5456324c, 1, 5000, group, GROUP_COUNTS[group]+1, header['xcr0'], header['xsave_bytes']),
         'exact trailer identity and observed input joins')
    tuples = [struct.unpack_from('<6Q', data, 64+48*i) for i in range(68)]
    basic, components = tuples[:4], tuples[4:]
    need([x[:2] for x in basic] == [(0, 0), (1, 0), (7, 0), (13, 0)] and
         all(all(v < 1 << 32 for v in q) for q in tuples), 'actual CPUID tuple identities and register width')
    need(basic[0][2] >= 13 and basic[1][4] & 0x1c000000 == 0x1c000000 and
         basic[2][3] & 0xc0010000 == 0xc0010000, 'actual XSAVE/OSXSAVE/AVX/AVX512F/BW/VL prerequisites')
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
    need(ids == [0]+list(range(19000+18*group,19000+18*group+GROUP_COUNTS[group]))+[0]*(18-GROUP_COUNTS[group]), 'actual retained pair identities')
    bvs = [list(struct.unpack_from('<10Q', data, 3480+80*i)) for i in range(19)]
    need(not any(v for row in bvs[checked:] for v in row), 'all unused full BV rows remain zero')
    for row in bvs[:checked]:
        need(all(v & 0xe7 == 0xe7 and not v & ~xcr0 for v in row), 'real non-init seed components present')
        need(len(set(row[:6])) == len(set(row[6:])) == 1,
             'exact kernel and live before/after XSTATE_BVs, separately observed without normalization')
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), checked=checked,
                query_count=count, cpuid_basic=[list(x) for x in basic],
                components=[dict(index=i, raw=list(components[i])) for i in active],
                kernel_xstate_bv=sorted({r[0] for r in bvs[:checked]}), live_xstate_bv=sorted({r[6] for r in bvs[:checked]}),
                xcr0=xcr0, xsave_bytes=size, all_bvs_sha256=digest(bvs), pair_ids_sha256=digest(ids))

def queries(data, group):
    need(len(data) == 9024, 'complete actual-before footprint trailer')
    need(struct.unpack_from('<8Q',data) == (0x3151324d5456324c,1,9024,group,2*GROUP_COUNTS[group],134,0,0),
         'exact query header and unsupported encoding count')
    rows=[]
    for index in range(GROUP_COUNTS[group]):
        pair=[]
        for lane in range(2):
            at=64+224*(2*index+lane)
            attempted,result,identity,actual_lane=struct.unpack_from('<4Q',data,at)
            before=struct.unpack_from('<18Q',data,at+32)
            pc,next_pc,first,end,abi,policy,code,length=struct.unpack_from('<4Q4I',data,at+176)
            need((attempted,result,identity,actual_lane,first,end,abi,policy,code,length) ==
                 (1,0,19000+18*group+index,lane,0,0,1,1,2784,6) and pc and next_pc==pc+6,
                 'actual retained query is exact NONE at the original PC')
            pair.append(dict(before=list(before),pc=pc,next_pc=next_pc))
        need(pair[0] == pair[1], 'native/TF query inputs and instruction identity exact')
        rows.append(pair)
    need(not any(data[64+224*2*GROUP_COUNTS[group]:]), 'every unused actual-before row remains zero')
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),actual_before_queries=2*GROUP_COUNTS[group],
                unsupported_encoding_queries=134,rows_sha256=digest(rows),memory_write_ranges=0)


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
                'vtn_promotions': c.get('vtn_promotions'), 'vtm256_promotions': c.get('vtm256_promotions'), 'observations': c.get('observations'), 'footprint': c.get('footprint')} for c in record['cases']],
        command_recipe={
            'selected_build': ['sh', 'tools/page-entry/selected/build.sh'],
            'fixture_build': ['sh', 'tools/page-entry/selected/tests/vptestmb256/build.sh',
                              '<retained decoder.a>', '<private run directory>', 'tools/page-entry/selected', '<group0..4>'],
            'native': [['vptestmb256-'+str(g)] for g in range(5)],
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
    name = stamp+'-page-selected-vptestmb256-'+args.expect_revision[:12]
    private = REPO/'target/evaluation/inprocess'/name
    private.mkdir(parents=True, exist_ok=False)
    public = REPO/'evaluation/inprocess/results'/(name+'.json')
    record = {'schema_version': 1, 'profile': 'page-selected-vptestmb256-oracle-v1', 'status': 'failed',
        'scope': 'Required cohort: canonical EVEX256.W0 register-only VPTESTMB Code2784;78 selected+5startup native/TF pairs in five bounded processes, all32 vector and8K roles, old writemask aliases/zeroing, exact observed62b25d2026cc at all six fetch tails. Full original C architectural/kernelFP/liveXSAVE/GPR/flags/memory/source comparisons, independent per-byte catalogue model,156 actual-before NONE queries. All181 supplied refusals and original2785/11Code2791/oneCode2784 typed/NONE controls per process. Actual accepted counts are in totals/cases. No operand-memory/fault, application completion, performance or full-B2/B3 claim.',
        'expected_revision': args.expect_revision, 'started_utc': stamp, 'cpu': cpu,
        'source': None, 'source_unchanged': False, 'commands': [], 'cases': [],
        'error': None, 'final_errors': [], 'bounds': PROFILES,
        'totals': {'positive_pairs': 0, 'generic_pairs': 0, 'positive_selftest_pairs': 0,
                   'supplied_refusal_encodings': 0, 'old_refusal_encodings': 0,
                   'new_refusal_encodings': 0, 'mask_pairs': 0,
                   'new_page_ending_pairs': 0, 'new_crossing_pairs': 0,
                   'executed_refusal_checks': 0, 'footprint_queries': 0, 'footprint_refusals': 0, 'promoted_encoding_checks': 0, 'promoted_footprint_queries': 0, 'vtn_typed_promotions': 0, 'vtn_supplied_none_queries': 0, 'vtm256_typed_promotions': 0, 'vtm256_supplied_none_queries': 0},
        'reproduce': ['python3', 'evaluation/inprocess/page_selected_vptestmb256.py',
                      '--expect-revision', args.expect_revision]}
    pins, binaries = {}, {}
    fixtures = {name: private/name for name in ['vptestmb256-'+str(g) for g in range(5)]}
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
        for fixture_group in range(5):
            run('fixture-build-'+str(fixture_group), [build.tools['sh'], FIXTURE/'build.sh', products['archive'], private,
                REPO/'tools/page-entry/selected', str(fixture_group)], profile='fixture_link', env=build.environment)
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
        need(len(names) == 17 and len(outcomes['commands']) == 5, 'complete finite mask-test protocol')
        need(outcomes['schema_version'] == 1 and outcomes['record_header_format'] == '<17Q' and
             names == ['magic', 'version', 'header_bytes', 'sample_bytes', 'pairs', 'completed', 'control',
                       'xcr0', 'xsave_bytes', 'refusals', 'failed_refusal', 'decoder_result',
                       'expected_failure_verified', 'fixture_failure', 'owner_failure',
                       'owner_detail_abs', 'owner_detail_negative'] and
             [c['name'] for c in outcomes['commands']] ==
             ['group'+str(g) for g in range(5)] and
             [c['exit'] for c in outcomes['commands']] == [0]*5 and
             [c['argv'] for c in outcomes['commands']] == [['vptestmb256-'+str(g)] for g in range(5)] and
             [c['environment_delta'] for c in outcomes['commands']] == [{}]*5 and
             outcomes['bounds'] == dict(cpu_seconds=5, address_space_bytes=512 << 20,
                 file_size_bytes=16 << 20, wall_seconds=15, cpu_affinity_count=1),
             'exact mask-test names, environments, exits, header schema and bounds')
        need(fact(FIXTURE/'OUTCOMES.json')['sha256'] ==
             '01f9c38412e74fc81f2b67076291bd142bcc8003379c342fe0cbbca9726fc887',
             'exact reviewed five-command outcomes')
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
            need(352<len(data)<16<<20,'complete Code2784 promotion within original cap')
            result['vtm256_promotions']=vtm256_promotions(data[-352:]);data=data[:-352]
            need(3232<len(data)<16<<20,'complete typed Code2791 promotions within unchanged cap')
            result['vtn_promotions']=vtn_promotions(data[-3232:], 'vptestmb');data=data[:-3232]
            need(len(data) >= 136, 'retained complete header')
            header = dict(zip(names, struct.unpack_from('<17Q', data)))
            result.update(header=header, record=fact(private/(name+'.record')))
            need(all(header[key] == value for key, value in case['header_equals'].items()), 'exact header outcome: '+name)
            need(header['sample_bytes'] > 0 and len(data) == header['header_bytes']+22*header['sample_bytes']+40+5000+9024,
                 'complete actual record extent')
            need(576 <= header['xsave_bytes'] <= 65536 and header['xcr0'] & 3 == 3, 'qualified XSAVE extent')
            # The C fixture's authenticated binary enforces full-state effects;
            # retain all complete samples for independent actual-layout replay.
            need(name in ['group'+str(g) for g in range(5)] and header['completed'] == header['pairs'] == GROUP_COUNTS[int(name[-1])]+1,
                 'every expected positive pair completed')
            end = header['header_bytes']+(GROUP_COUNTS[int(name[-1])]+1)*header['sample_bytes']
            need(not any(data[end:header['header_bytes']+22*header['sample_bytes']]), 'every unused positive slot and original negative sample remain zero; exact per-group pairs required')
            result['observations'] = observations(data[-14024:-9024], int(name[-1]), header)
            result['footprint'] = queries(data[-9024:], int(name[-1]))
            result['operation_completed'] = True
            record['totals']['positive_pairs'] += GROUP_COUNTS[int(name[-1])]+1
            record['totals']['generic_pairs'] += GROUP_COUNTS[int(name[-1])]
            record['totals']['mask_pairs'] += GROUP_COUNTS[int(name[-1])]
            record['totals']['positive_selftest_pairs'] += 1
            record['totals']['new_page_ending_pairs'] += record['catalogue']['groups'][int(name[-1])]['ending']
            record['totals']['new_crossing_pairs'] += record['catalogue']['groups'][int(name[-1])]['crossing']
            record['totals']['executed_refusal_checks'] += header['refusals']
            record['totals']['footprint_queries'] += 2*GROUP_COUNTS[int(name[-1])]
            record['totals']['footprint_refusals'] += 134
            record['totals']['promoted_encoding_checks'] += 1
            record['totals']['promoted_footprint_queries'] += 1
            record['totals'].update(supplied_refusal_encodings=181,
                old_refusal_encodings=109, new_refusal_encodings=72)
            record['totals']['vtn_typed_promotions'] += 11
            record['totals']['vtn_supplied_none_queries'] += 11
            record['totals']['vtm256_typed_promotions'] += result['vtm256_promotions']['typed_promotions']
            record['totals']['vtm256_supplied_none_queries'] += result['vtm256_promotions']['supplied_none_queries']
            result['accepted'] = True
        need(record['totals'] == dict(positive_pairs=83, generic_pairs=78, mask_pairs=78,
                 positive_selftest_pairs=5, supplied_refusal_encodings=181, old_refusal_encodings=109,
                 new_refusal_encodings=72, new_page_ending_pairs=12, new_crossing_pairs=66,
                 executed_refusal_checks=905, footprint_queries=156, footprint_refusals=670,
                 promoted_encoding_checks=5, promoted_footprint_queries=5, vtn_typed_promotions=55, vtn_supplied_none_queries=55, vtm256_typed_promotions=5, vtm256_supplied_none_queries=5) and len(record['cases']) == 5 and
             all(c['accepted'] for c in record['cases']),
             'complete fixed78 selected+5startup mask-test pairs; original memory fault suites remain separate')
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
