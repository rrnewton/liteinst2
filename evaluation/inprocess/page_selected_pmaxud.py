#!/usr/bin/env python3
"""Finite closed PMAXUD full-state oracle, guarded #PF and unaligned #GP controls."""
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
from page_selected import ENV, fact, need, save, elf
from page_selected_components import plain_executable
from page_selected_generic_build import Build, PROFILES as BUILD_PROFILES
from page_selected_process import invoke

REPO = Path(__file__).resolve().parents[2]
FIXTURE = REPO/'tools/page-entry/selected/tests/pmaxud'
PROFILES = dict(BUILD_PROFILES, fixture_link=[5, 512 << 20, 16 << 20, 15],
                native=[5, 512 << 20, 16 << 20, 15])


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def catalogue():
    path = FIXTURE/'cases.inc'
    binding = fact(path)
    need(binding['sha256'] == '9c8b5c35130db7b7854f85d243c7eb6a1f256dcc46f3256814f96509cd5f6ca3',
         'exact reviewed literal PMAXUD catalogue')
    encodings = {(0, 1, 0): '660f383fc1', (12, 9, 0): '66450f383fe1',
                 (7, 7, 0): '660f383fff', (0, 0, 1): '660f383f06',
                 (12, 0, 1): '66440f383f26'}
    rows, signed_discriminators = [], 0
    for line in path.read_text().splitlines():
        if not line.startswith('    {'):
            continue
        match = re.fullmatch(r'    \{"([^"]+)",([0-9,]+),\{([^}]*)\},\{([^}]*)\},\{([^}]*)\},\{([^}]*)\},0\},', line)
        need(match is not None, 'closed literal PMAXUD row')
        numbers = [int(n) for n in match[2].split(',')]
        need(len(numbers) == 7, 'exact PMAXUD row fields')
        length, code, destination, source_register, memory, movemask, tail = numbers
        blobs = [bytes(int(n, 16) for n in match[k].split(',')) for k in (3, 4, 5, 6)]
        need(len(blobs[0]) == length and all(len(b) == 16 for b in blobs[1:]) and
             1 <= tail <= length <= 6 and movemask == 0 and code == 2993 and
             (destination, source_register, memory) in encodings,
             'closed PMAXUD row operands')
        a, b, expected = [struct.unpack('<4I', value) for value in blobs[1:]]
        signed = lambda v: v if v < 1 << 31 else v-(1 << 32)
        signed_result = tuple(x if signed(x) >= signed(y) else y for x, y in zip(a, b))
        signed_discriminators += expected != signed_result
        need(blobs[0].hex() == encodings[destination, source_register, memory] and
             expected == tuple(max(x, y) for x, y in zip(a, b)) and
             (destination != source_register or memory or a == b),
             'exact five encodings and independent unsigned32 lane maxima')
        rows.append(dict(name=match[1], length=length, code=code, destination=destination,
                         source_register=source_register, memory=memory, tail=tail,
                         bytes=blobs[0].hex(), a=list(a), b=list(b), expected=list(expected)))
    counts = dict(new_pairs=len(rows), register_vector_pairs=sum(not r['memory'] for r in rows),
                  aligned_memory_vector_pairs=sum(r['memory'] for r in rows),
                  page_ending_pairs=sum(r['tail'] == r['length'] for r in rows),
                  crossing_pairs=sum(r['tail'] < r['length'] for r in rows))
    need(counts == dict(new_pairs=18, register_vector_pairs=12, aligned_memory_vector_pairs=6,
                       page_ending_pairs=4, crossing_pairs=14) and
         {r['bytes'] for r in rows} == set(encodings.values()) and signed_discriminators == 17 and
         rows[0]['bytes'] == '660f383fc1', 'complete PMAXUD literal cohort')
    tails = {'660f383fc1': [5, 4, 3, 2, 1], '66450f383fe1': [6, 5, 4, 3, 2, 1],
             '660f383f06': [5, 3, 1], '66440f383f26': [6, 4, 2], '660f383fff': [4]}
    need(all([r['tail'] for r in rows if r['bytes'] == raw] == values for raw, values in tails.items()),
         'exact source endings and crossing splits')
    return dict(source=binding, counts=counts, signed_max_discriminators=signed_discriminators,
                rows_sha256=digest(rows))


def executable_layout(path, symbols):
    """Record sizes are bound to objects in the retained executable, not its output."""
    names = {'result', 'samples', 'negative_sample', 'refused_last'}
    found = {}
    _, _, segments = elf(path)
    for line in symbols.decode('ascii').splitlines():
        fields = line.split()
        if len(fields) != 4 or fields[3] not in names:
            continue
        address, size, kind, name = fields
        need(name not in found and re.fullmatch('[0-9a-fA-F]+', address) and
             re.fullmatch('[0-9a-fA-F]+', size) and kind in ('b', 'B'),
             'unique actual fixture BSS symbol')
        address, size = int(address, 16), int(size, 16)
        need(size > 0 and sum(p[0] == 1 and p[1] == 6 and
             p[3] <= address < address+size <= p[3]+p[6] for p in segments) == 1,
             'whole record object within one writable NX load segment')
        found[name] = dict(address=address, bytes=size)
    need(set(found) == names, 'all actual retained record objects')
    spans = sorted((v['address'], v['address']+v['bytes']) for v in found.values())
    need(all(a[1] <= b[0] for a, b in zip(spans, spans[1:])), 'disjoint record objects')
    size = {k: v['bytes'] for k, v in found.items()}
    need(size['result'] == 136 and size['refused_last'] == 40 and
         size['samples'] == 21*size['negative_sample'] and
         0 < sum(size.values()) < 16 << 20, 'exact finite executable record extents')
    return dict(symbols=found, header_bytes=size['result'], sample_bytes=size['negative_sample'],
                total_bytes=sum(size.values()), classification_bytes=size['refused_last'])


def publish(path, record, receipt):
    # Raw state and ordered command/capture rows stay private. This projection
    # gives counts and failed-operation identities, without timing credit.
    build = record.get('build', {})
    public = {key: record.get(key) for key in (
        'schema_version', 'profile', 'status', 'scope', 'expected_revision', 'started_utc',
        'cpu', 'source', 'source_unchanged', 'hardware', 'totals', 'reproduce', 'bounds')}
    public.update(environment=ENV, private_receipt=fact(receipt),
        command_count=len(record['commands']), commands_sha256=digest(record['commands']),
        cases_sha256=digest(record['cases']), inputs_sha256=digest(record.get('inputs_before', {})),
        binaries_sha256=digest(record.get('binaries_before', {})),
        elf_sha256=digest(record.get('elf', {})), layout_sha256=digest(record.get('layouts', {})),
        tool_versions=build.get('numeric_versions', {}),
        tool_hashes={name: {k: value[k] for k in ('bytes', 'sha256')}
                     for name, value in build.get('tools', {}).items()},
        build_artifacts_sha256=digest(build.get('artifacts', {})),
        fixtures=record.get('fixtures'), catalogue=record.get('catalogue'),
        build_status=build.get('status', 'not_started'),
        failure_type=(record.get('error') or '').split(':')[0] or None,
        final_error_count=len(record['final_errors']),
        cases=[{key: c.get(key) for key in ('name', 'accepted', 'process_outcome', 'actual_exit',
               'operation_completed', 'verified_memory_fault', 'fault_vector', 'header', 'record')}
               for c in record['cases']],
        command_recipe={
            'selected_build': ['sh', 'tools/page-entry/selected/build.sh'],
            'fixture_build': ['sh', 'tools/page-entry/selected/tests/pmaxud/build.sh',
                              '<retained decoder.a>', '<private run directory>', 'tools/page-entry/selected'],
            'native': [['pmaxud-0']]*3,
            'native_environment_controls': ['absent', 'load-fault', 'unaligned'],
            'control_variable': 'LI2_PMAXUD_CONTROL',
            'actual_commands': 'Complete ordered argv, environments and captures remain private and bound by commands_sha256.'})
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
    name = stamp+'-page-selected-pmaxud-'+args.expect_revision[:12]
    private = REPO/'target/evaluation/inprocess'/name
    private.mkdir(parents=True, exist_ok=False)
    public = REPO/'evaluation/inprocess/results'/(name+'.json')
    record = {'schema_version': 1, 'profile': 'page-selected-pmaxud-oracle-v1', 'status': 'failed',
        'scope': 'Closed legacy SSE4.1 PMAXUD: 18 literal native/TF pairs plus one startup pair, five exact encodings, and98 supplied refusals (74 old plus24 new) in each of three processes. Guarded aligned #PF and accessible unaligned #GP remain failed operations. The source-bound C comparator enforces complete state and memory effects; full private records and retained ELF/DWARF support independent replay. Other old suites remain separately required. No every-encoding, real-program completion, performance or full-B2 claim.',
        'expected_revision': args.expect_revision, 'started_utc': stamp, 'cpu': cpu,
        'source': None, 'source_unchanged': False, 'commands': [], 'cases': [],
        'error': None, 'final_errors': [], 'bounds': PROFILES,
        'totals': {'positive_pairs': 0, 'generic_pairs': 0, 'positive_selftest_pairs': 0,
                   'supplied_refusal_encodings': 0, 'old_refusal_encodings': 0,
                   'new_refusal_encodings': 0, 'pmaxud_pairs': 0,
                   'register_vector_pairs': 0, 'aligned_memory_vector_pairs': 0, 'movemask_pairs': 0,
                   'new_page_ending_pairs': 0, 'new_crossing_pairs': 0,
                   'verified_memory_fault_commands': 0, 'actual_native_failed_operations': 0,
                   'actual_stepped_failed_operations': 0, 'additional_negative_command_selftests': 0,
                   'executed_refusal_checks': 0},
        'reproduce': ['python3', 'evaluation/inprocess/page_selected_pmaxud.py',
                      '--expect-revision', args.expect_revision]}
    pins, binaries = {}, {}
    fixtures = {name: private/name for name in ('pmaxud-0',)}
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
        record['fixtures'], record['elf'], record['layouts'] = {}, {}, {}
        for fixture_name, fixture in fixtures.items():
            binary(fixture)
            record['fixtures'][fixture_name] = fact(fixture)
            record['elf'][fixture_name] = plain_executable(fixture)
            _, out, err = run(fixture_name+'-undefined', [build.tools['nm'], '-u', fixture],
                              profile='inspect', env=build.environment)
            need(not out and not err, 'no undefined fixture symbols')
            _, out, err = run(fixture_name+'-record-symbols', [build.tools['nm'], '-S', '--defined-only', fixture],
                              profile='inspect', env=build.environment)
            need(not err, 'record object inspection stderr')
            record['layouts'][fixture_name] = executable_layout(fixture, out)
        record['catalogue'] = catalogue()
        outcomes = json.loads((FIXTURE/'OUTCOMES.json').read_bytes())
        names = outcomes['record_header_fields']
        need(len(names) == 17 and len(outcomes['commands']) == 3, 'complete finite PMAXUD protocol')
        need(outcomes['schema_version'] == 1 and outcomes['record_header_format'] == '<17Q' and
             names == ['magic', 'version', 'header_bytes', 'sample_bytes', 'pairs', 'completed', 'control',
                       'xcr0', 'xsave_bytes', 'refusals', 'failed_refusal', 'decoder_result',
                       'expected_failure_verified', 'fixture_failure', 'owner_failure',
                       'owner_detail_abs', 'owner_detail_negative'] and
             [c['name'] for c in outcomes['commands']] ==
             ['positive', 'load-fault', 'unaligned'] and
             [c['exit'] for c in outcomes['commands']] == [0, 125, 125] and
             [c['argv'] for c in outcomes['commands']] == [['pmaxud-0']]*3 and
             [c['environment_delta'] for c in outcomes['commands']] ==
             [{}, {'LI2_PMAXUD_CONTROL': 'load-fault'}, {'LI2_PMAXUD_CONTROL': 'unaligned'}] and
             outcomes['bounds'] == dict(cpu_seconds=5, address_space_bytes=512 << 20,
                 file_size_bytes=16 << 20, wall_seconds=15, cpu_affinity_count=1),
             'exact PMAXUD names, input environments, exits, header schema and bounds')
        need(fact(FIXTURE/'OUTCOMES.json')['sha256'] ==
             '1c70522c84531b50755f5094c9cb519eb9976dfe1dcead19d9f2a05375ec9273',
             'exact reviewed three-command outcomes')
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
            layout = record['layouts'][case['argv'][0]]
            need(header['sample_bytes'] > 0 and len(data) == header['header_bytes']+22*header['sample_bytes']+40,
                 'complete actual record extent')
            need(header['sample_bytes'] == layout['sample_bytes'] and
                 header['header_bytes'] == layout['header_bytes'] and len(data) == layout['total_bytes'],
                 'record extents match actual retained executable objects')
            need(576 <= header['xsave_bytes'] <= 65536 and header['xcr0'] & 3 == 3, 'qualified XSAVE extent')
            # The C fixture's authenticated binary enforces full-state effects;
            # retain all complete samples for independent actual-layout replay.
            positive = name == 'positive'
            used = 19 if positive else 1
            start = header['header_bytes']+used*header['sample_bytes']
            end = header['header_bytes']+21*header['sample_bytes']
            need(not any(data[start:end]), 'all unused original sample slots remain zero')
            record['totals']['executed_refusal_checks'] += header['refusals']
            if positive:
                need(not any(data[end:end+header['sample_bytes']]), 'positive has no negative sample')
                result['operation_completed'] = True
                record['totals']['positive_pairs'] += 19
                record['totals']['generic_pairs'] += 18
                record['totals']['pmaxud_pairs'] += 18
                record['totals']['positive_selftest_pairs'] += 1
                record['totals']['register_vector_pairs'] += 12
                record['totals']['aligned_memory_vector_pairs'] += 6
                record['totals']['movemask_pairs'] += 0
                record['totals']['new_page_ending_pairs'] += 4
                record['totals']['new_crossing_pairs'] += 14
                record['totals'].update(supplied_refusal_encodings=98,
                    old_refusal_encodings=74, new_refusal_encodings=24)
            else:
                need(any(data[end:end+header['sample_bytes']]), 'retain actual failed-operation sample')
                # Authenticated C requires the specific actual native/stepped
                # #PF or #GP, unchanged state, revoke/sync and retained failed
                # borrow before emitting this outcome. No successful continuation.
                result['fault_vector'] = 14 if name == 'load-fault' else 13
                result['verified_memory_fault'] = True
                record['totals']['verified_memory_fault_commands'] += 1
                record['totals']['actual_native_failed_operations'] += 1
                record['totals']['actual_stepped_failed_operations'] += 1
                record['totals']['additional_negative_command_selftests'] += 1
            result['accepted'] = True
        need(record['totals'] == dict(positive_pairs=19, generic_pairs=18, pmaxud_pairs=18,
                 positive_selftest_pairs=1, supplied_refusal_encodings=98, old_refusal_encodings=74,
                 new_refusal_encodings=24, register_vector_pairs=12, aligned_memory_vector_pairs=6,
                 movemask_pairs=0, new_page_ending_pairs=4, new_crossing_pairs=14,
                 verified_memory_fault_commands=2, actual_native_failed_operations=2,
                 actual_stepped_failed_operations=2, additional_negative_command_selftests=2,
                 executed_refusal_checks=294) and
             len(record['cases']) == 3 and all(c['accepted'] for c in record['cases']),
             'complete nineteen-pair cohort and both actual failed-memory commands')
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
