#!/usr/bin/env python3
"""Canonical RIP-relative BND JMP under actual MPX-disabled XCR0 custody."""
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
FIXTURE = REPO/'tools/page-entry/selected/tests/bnd_jmp'
PROFILES = dict(BUILD_PROFILES, fixture_link=[5, 512 << 20, 16 << 20, 15],
                native=[5, 512 << 20, 16 << 20, 15])


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def catalogue():
    path = FIXTURE/'OUTCOMES.json'
    binding = fact(path)
    need(binding['sha256'] == '6b1c8d721440abef9cee280648aa88b7488a7f3d040408eb2bec1d0a3750309b', 'exact reviewed BND JMP protocol')
    protocol = json.loads(path.read_bytes())
    rows = []
    for i in range(14):
        tail, negative = 7-i%7, i >= 7
        displacement = (-3*4096 if negative else 3*4096)+57+tail
        rows.append(dict(id=2000+i, tail=tail, negative_displacement=negative,
                         displacement=displacement, code=765,
                         bytes=(bytes.fromhex('f2ff25')+displacement.to_bytes(4, 'little', signed=True)).hex()))
    need(protocol['pairs'] == rows and len({r['bytes'] for r in rows}) == 14 and
         sum(r['tail'] == 7 for r in rows) == 2 and
         sum(r['negative_displacement'] for r in rows) == 7,
         'both signed displacements and every seven-byte ending/crossing geometry')
    return dict(source=binding, rows_sha256=digest(rows), counts=dict(new_pairs=14,
                page_ending_pairs=2, crossing_pairs=12, negative_displacements=7,
                positive_displacements=7, old_refusals=47, new_refusals=16))

def probe_instructions(path, symbols, symbol, production=False):
    """Bind the actual separately emitted helper and its actual ECX=0 XGETBV instruction."""
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
    need(len(matches) == 1 and size >= 5, 'single complete helper extent')
    code = matches[0]
    pair = bytes.fromhex('0f01d0')
    need(code.count(pair) == 1 and
         (bytes.fromhex('31c9')+pair in code or bytes.fromhex('b900000000')+pair in code),
         'one actual ECX-zero XGETBV observation')
    return dict(symbol=symbol, symbol_bytes=size, code_sha256=hashlib.sha256(code).hexdigest(),
                pair_offset=code.index(pair), exact_pair=pair.hex())


def publish(path, record, receipt):
    # Small numeric/hash projection. Complete command rows, raw state records,
    # actual ELF/DWARF, tool pins and cleanup outcomes remain private and bound.
    build = record.get('build', {})
    public = {key: record.get(key) for key in (
        'schema_version', 'profile', 'status', 'scope', 'expected_revision', 'started_utc',
        'cpu', 'source', 'source_unchanged', 'hardware', 'totals', 'reproduce', 'bounds')}
    public.update(environment=ENV, private_receipt=fact(receipt),
        command_count=len(record['commands']), commands_sha256=digest(record['commands']),
        case_count=len(record['cases']), cases_sha256=digest(record['cases']),
        inputs_sha256=digest(record.get('inputs_before', {})),
        binaries_sha256=digest(record.get('binaries_before', {})),
        elf_sha256=digest(record.get('elf', {})),
        catalogue=record.get('catalogue'),
        emitted_observations=record.get('emitted_observations'),
        native_commands=[dict(name=c['name'], actual_exit=c.get('exit'),
            expected_exit=c.get('expected_exit'), timed_out=c.get('timed_out'), reaped=c.get('reaped'),
            cleanup_error_count=len(c.get('cleanup_errors', [])),
            environment_delta={k:v for k,v in c['environment'].items() if ENV.get(k) != v},
            captures={n:{k:v[k] for k in ('bytes','sha256')} for n,v in c.get('captures', {}).items()})
            for c in record['commands'] if c['profile']=='native'],
        cases=record['cases'],
        tool_versions=build.get('numeric_versions', {}),
        tool_hashes={name: {k: value[k] for k in ('bytes', 'sha256')}
                     for name, value in build.get('tools', {}).items()},
        build_artifacts_sha256=digest(build.get('artifacts', {})),
        build_status=build.get('status', 'not_started'),
        failure_type=(record.get('error') or '').split(':')[0] or None,
        final_error_count=len(record['final_errors']))
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
    name = stamp+'-page-selected-bnd-jmp-'+args.expect_revision[:12]
    private = REPO/'target/evaluation/inprocess'/name
    private.mkdir(parents=True, exist_ok=False)
    public = REPO/'evaluation/inprocess/results'/(name+'.json')
    record = {'schema_version': 1, 'profile': 'page-selected-bnd-jmp-oracle-v1', 'status': 'failed',
        'scope': 'Canonical F2 FF25 disp32 original-PC indirect JMP only: fourteen native/TF branches plus one startup pair, both displacement signs and all seven fetch geometries. Each native/owner entry requires a fresh actual XGETBV0 observation with both MPX bits clear. Exact actual target, all GPRs/flags/full initialized FP/live XSAVE/whole stack/data supplement unchanged common comparisons. One genuine pointer-read fault remains failed125 with no branch completion. Three separately labeled supplied-XCR0 controls remain pre-open failures125, not enabled-MPX hardware evidence. Old47 and new16 encoding refusals stay required. Existing no-CET/singleton/signal/OSXSAVE custody applies; no target-body execution, transparent faults, arbitrary BND prefixes, enabled-MPX, loader completion or performance claim.',
        'expected_revision': args.expect_revision, 'started_utc': stamp, 'cpu': cpu,
        'source': None, 'source_unchanged': False, 'commands': [], 'cases': [],
        'error': None, 'final_errors': [], 'bounds': PROFILES,
        'totals': {'positive_pairs': 0, 'bnd_jmp_pairs': 0, 'positive_selftest_pairs': 0, 'new_page_ending_pairs': 0, 'new_crossing_pairs': 0, 'positive_displacement_pairs': 0, 'negative_displacement_pairs': 0, 'supplied_refusal_encodings': 0, 'old_refusal_encodings': 0, 'new_refusal_encodings': 0, 'executed_refusal_checks': 0, 'actual_native_xcr0_observations': 0, 'actual_owner_xcr0_observations': 0, 'supplied_owner_xcr0_observations': 0, 'verified_preopen_refusals': 0, 'actual_native_failed_operations': 0, 'actual_stepped_failed_operations': 0, 'additional_negative_command_selftests': 0},
        'reproduce': ['python3', 'evaluation/inprocess/page_selected_bnd_jmp.py',
                      '--expect-revision', args.expect_revision]}
    pins, binaries = {}, {}
    fixtures = {name: private/name for name in ('bnd-jmp',)}
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
            'li2_tf_observe_xcr0', production=True)}
        run('fixture-build', [build.tools['sh'], FIXTURE/'build.sh', products['archive'], private, REPO/'tools/page-entry/selected'],
            profile='fixture_link', env=build.environment)
        support = private/'bnd-jmp-support'
        actual_owner = (REPO/'tools/page-entry/selected/step_owner.c').read_bytes()
        actual_tf = (REPO/'tools/page-entry/selected/tf_owner.inc').read_bytes()
        original = b'__attribute__((noinline)) uint64_t li2_tf_observe_xcr0('
        replacement = b'__attribute__((noinline)) uint64_t li2_tf_actual_observe_xcr0('
        need(actual_tf.count(original) == 1 and replacement not in actual_tf and
             (support/'step_owner.c').read_bytes() == actual_owner and
             (support/'tf_owner.inc').read_bytes() == actual_tf.replace(original, replacement),
             'definition-only supplied-observation adapter; all owner guards stay exact')
        record['test_adapter'] = {n: fact(binary(support/n)) for n in ('step_owner.c', 'tf_owner.inc')}
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
            need(not err, 'fixture observation symbol inspection stderr')
            record['emitted_observations'][fixture_name] = probe_instructions(fixture, out,
                'li2_tf_actual_observe_xcr0')
        record['catalogue'] = catalogue()
        outcomes = json.loads((FIXTURE/'OUTCOMES.json').read_bytes())
        names = outcomes['record_header_fields']
        controls = ['load-fault', 'supplied-bndregs', 'supplied-bndcsr', 'supplied-both']
        need(outcomes['schema_version'] == 1 and outcomes['record_header_format'] == '<17Q' and
             names == ['magic', 'version', 'header_bytes', 'sample_bytes', 'pairs', 'completed', 'control',
                       'xcr0', 'xsave_bytes', 'refusals', 'failed_refusal', 'decoder_result',
                       'expected_failure_verified', 'fixture_failure', 'owner_failure',
                       'owner_detail_abs', 'owner_detail_negative'] and
             [c['name'] for c in outcomes['commands']] == ['positive']+controls and
             [c['exit'] for c in outcomes['commands']] == [0,125,125,125,125] and
             [c['argv'] for c in outcomes['commands']] == [['bnd-jmp']]*5 and
             [c['environment_delta'] for c in outcomes['commands']] ==
             [{}]+[{'LI2_BND_JMP_CONTROL': n} for n in controls] and
             outcomes['bounds'] == dict(cpu_seconds=5, address_space_bytes=512 << 20,
                 file_size_bytes=16 << 20, wall_seconds=15, cpu_affinity_count=1),
             'exact five outcomes, real/supplied failure distinction, header and unchanged bounds')
        need(outcomes['query_trailer'] == dict(bytes=576, header_format='<6Q',
             header_fields=['magic','version','bytes','native_queries','injected_control','injected_calls'],
             magic=0x31444e424a324c, version=1, observation_format='<3Q',
             observation_fields=['attempted','complete','xcr0'], observation_count=22,negative_slot=21),
             'closed complete query trailer')
        for index, case in enumerate(outcomes['commands']):
            name = case['name']
            result = {'name': name, 'process_outcome': case['process_outcome'], 'accepted': False,
                      'actual_exit': None, 'operation_completed': False,
                      'verified_preopen_refusal': False}
            record['cases'].append(result)
            row, out, err = run(name, [fixtures['bnd-jmp']], case['exit'], env=case['environment_delta'])
            result['actual_exit'] = row['exit']
            need(out == case['stdout'].encode() and err == case['stderr'].encode(), 'exact fixture output: '+name)
            data = (private/(name+'.record')).read_bytes()
            need(len(data) >= 136, 'retained complete header')
            header = dict(zip(names, struct.unpack_from('<17Q', data)))
            result.update(header=header, record=fact(private/(name+'.record')))
            need(all(header[key] == value for key, value in case['header_equals'].items()), 'exact header outcome: '+name)
            need(header['sample_bytes'] > 0 and len(data) == header['header_bytes']+22*header['sample_bytes']+40+576,
                 'complete actual record extent')
            need(576 <= header['xsave_bytes'] <= 65536 and header['xcr0'] & 3 == 3 and
                 header['xcr0'] & 24 == 0, 'qualified XSAVE and actual MPX-disabled fixture profile')
            used = 15 if index == 0 else 1
            end = header['header_bytes']+21*header['sample_bytes']
            need(not any(data[header['header_bytes']+used*header['sample_bytes']:end]),
                 'all unused original sample slots remain zero')
            need((not any(data[end:end+header['sample_bytes']])) if index == 0 else
                 any(data[end:end+header['sample_bytes']]), 'exact positive/failed sample custody')
            trailer = data[-576:]
            qheader = struct.unpack_from('<6Q', trailer)
            queries = [struct.unpack_from('<3Q', trailer,48+i*24) for i in range(22)]
            count = 14 if index == 0 else 1 if index == 1 else 0
            need(qheader == (0x31444e424a324c,1,576,count,index if index>=2 else 0,int(index>=2)),
                 'actual query count and separately labeled injection prefix')
            expected = [(1,1,header['xcr0']) if (index == 0 and 1 <= i <= 14) or
                        (index == 1 and i == 21) else (0,0,0) for i in range(22)]
            need(queries == expected, 'every actual XCR0 observation and every unused slot')
            result['query_evidence'] = dict(actual_native=count,actual_owner=count,
                actual_xcr0=header['xcr0'] if count else None,supplied_owner=int(index>=2),
                supplied_value=[8,16,24][index-2] if index>=2 else None,
                trailer_sha256=hashlib.sha256(trailer).hexdigest())
            total = record['totals']
            total['executed_refusal_checks'] += header['refusals']
            total['actual_native_xcr0_observations'] += count
            total['actual_owner_xcr0_observations'] += count
            total.update(supplied_refusal_encodings=63,old_refusal_encodings=47,new_refusal_encodings=16)
            if index == 0:
                result['operation_completed'] = True
                total.update(positive_pairs=15,bnd_jmp_pairs=14,positive_selftest_pairs=1,
                    new_page_ending_pairs=2,new_crossing_pairs=12,positive_displacement_pairs=7,
                    negative_displacement_pairs=7)
            else:
                total['additional_negative_command_selftests'] += 1
                if index == 1:
                    total['actual_native_failed_operations'] += 1
                    total['actual_stepped_failed_operations'] += 1
                else:
                    result['verified_preopen_refusal'] = True
                    total['supplied_owner_xcr0_observations'] += 1
                    total['verified_preopen_refusals'] += 1
            result['accepted'] = True
        need(record['totals'] == dict(positive_pairs=15,bnd_jmp_pairs=14,positive_selftest_pairs=1,
                 new_page_ending_pairs=2,new_crossing_pairs=12,positive_displacement_pairs=7,
                 negative_displacement_pairs=7,supplied_refusal_encodings=63,old_refusal_encodings=47,
                 new_refusal_encodings=16,executed_refusal_checks=315,actual_native_xcr0_observations=15,
                 actual_owner_xcr0_observations=15,supplied_owner_xcr0_observations=3,verified_preopen_refusals=3,
                 actual_native_failed_operations=1,actual_stepped_failed_operations=1,
                 additional_negative_command_selftests=4) and
             len(record['cases']) == 5 and all(c['accepted'] for c in record['cases']),
             'complete finite branch, real pointer fault and supplied pre-open cohorts')
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
