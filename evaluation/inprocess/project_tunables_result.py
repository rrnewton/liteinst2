#!/usr/bin/env python3
"""Project one closed PF/focal/component receipt to compact JSON and CSV.

  python3 -B project_tunables_result.py --receipt PATH --receipt-sha256 SHA \
      --output FRESH_DIRECTORY
Run from the repository root. This stdlib-only script hashes every recorded
command capture and joins case fields to those commands. Component output reuses
the collector's authenticated summary. No reader, subject, control or evaluator
is executed. Recorded failure and partial populations remain literal; a projected
receipt grants no new qualification or performance credit. Fresh reproduction
uses the named tracked collector and fresh same-source prerequisites, not this
projection. Full private receipts/captures remain necessary for offline replay.
"""
import argparse
from collections import Counter
import csv
import hashlib
import io
import json
from pathlib import Path
import platform
import re
import sys

ROOT = Path.cwd().resolve()
# script, recorded successful status, planned commands, component names
PROFILES = {
    'bounded-fused-owner-v1': ('bounded_fused_owner.py', 'observed_unqualified', 105, ()),
    'persistent-loop-owner-v1': ('persistent_loop_owner.py', 'observed_focal_unqualified', 126, ()),
    'experimental-bounded-fused-component-v1': ('bounded_fusion_component/run.py', 'components_passed', 44,
                                               ('bounded_fusion_plan',)),
    'experimental-loop-components-v1': ('loop_components/run.py', 'components_passed', 60,
        ('scalar_span_metadata', 'scalar_read', 'loop_envelope', 'bounded_fusion_plan', 'loop_plan')),
}
HARDWARE = ('architecture', 'vendor_id', 'model name', 'cpu family', 'model', 'stepping',
            'microcode', 'kernel_version', 'kernel_release_sha256', 'probe_cpu', 'affinity_cpu_count')
CLOSURE = ('source_unchanged', 'inputs_unchanged', 'cleanup_complete')
PF_POSITIVE = ('observed_native_bounded_fused', 'observed_generated_bounded_fused_maintained',
               'observed_generated_bounded_fused_differential')
PF_FAULT = ('observed_native_write_fault', 'observed_pf_store_fault',
            'observed_native_write_fault', 'observed_pf_guard_rejection')
# Exact `link-` labels emitted by both component collectors' LINK_NAMES loops.
COMPONENT_LINK_COMMANDS = {'link-'+name for name in (
    'crt1.o Scrt1.o crti.o crtn.o crtbegin.o crtbeginS.o crtend.o crtendS.o '
    'libgcc.a libgcc_eh.a libgcc_s.so libgcc_s.so.1 libc.so libc_nonshared.a '
    'libc.so.6 libdl.a libpthread.a libm.so libm.so.6 libmvec.so.1').split()}


def need(ok, message):
    if not ok: raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def fact(path):
    path = Path(path)
    need(path.is_file() and not path.is_symlink(), 'whole regular input')
    h = hashlib.sha256(); size = 0
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            h.update(chunk); size += len(chunk)
    return dict(bytes=size, sha256=h.hexdigest())


def decode(raw):
    def unique(items):
        result = dict(items); need(len(result) == len(items), 'unique JSON keys'); return result
    return json.loads(raw, object_pairs_hook=unique)


def public_text(value):
    """Refuse private text; never silently rewrite a recorded failure."""
    need(value is None or type(value) is str, 'literal optional recorded text')
    if value is not None:
        tokens = (str(ROOT), str(Path.home()), platform.node(), '/home/', '/tmp/',
                  '/usr/local/', 'fbcode', 'devbig', 'ssh://', 'http://', 'https://')
        need(all(not x or x not in value for x in tokens), 'private path/host/URL in projection')
    return value


def numeric(value):
    """The existing small pair results contain only numeric/boolean values."""
    need(type(value) is dict and all(type(k) is str and type(v) in (int, bool)
                                   for k, v in value.items()), 'literal numeric pair result')
    return value


def controls(value):
    names = value if type(value) is list else value['refusals']
    need(type(names) is list and all(type(n) is str and n for n in names) and
         len(names) == len(set(names)), 'actual unique named controls')
    if type(value) is dict and 'count' in value:
        need(value['count'] == len(names), 'recorded control count equals named population')
    return dict(count=len(names), names_sha256=digest(names))


def recipe(script, revision, cpu, component):
    argv = ['python3', '-B', 'evaluation/inprocess/'+script, '--expect-revision', revision,
            '--cpu', str(cpu)]
    if component:
        argv += ['--archive', '<FRESH_SAME_SOURCE_DECODER_ARCHIVE>', '--archive-sha256', '<FRESH_SHA256>']
    else:
        names = ('direct', 'block', 'fused-component') if script == 'bounded_fused_owner.py' else (
            'direct', 'block', 'fused', 'loop-component', 'loop-native')
        for name in names:
            argv += ['--'+name+'-receipt', '<FRESH_'+name.upper().replace('-', '_')+'_RECEIPT>',
                     '--'+name+'-receipt-sha256', '<FRESH_SHA256>']
    return argv + ['--output', 'target/evaluation/inprocess/<FRESH_ATTEMPT>']


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--receipt', type=Path, required=True)
    ap.add_argument('--receipt-sha256', required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{64}', args.receipt_sha256),
         'assertions and explicit whole receipt SHA256')
    need(not args.output.exists(), 'fresh projection output; original results stay intact')
    path = args.receipt.resolve(strict=True); receipt_fact = fact(path)
    need(receipt_fact['sha256'] == args.receipt_sha256, 'exact supplied closed receipt')
    r = decode(path.read_bytes()); profile = r['profile']
    need(r['schema'] == 1 and profile in PROFILES, 'one of the four existing receipt profiles')
    script, accepted_status, planned, component_names = PROFILES[profile]
    need(r['status'] in ('failed', accepted_status), 'literal closed status, never running/partial relabeling')
    revision, cpu = r['revision'], r['cpu']
    need(re.fullmatch('[0-9a-f]{40}', revision) and type(cpu) is int and cpu >= 0,
         'actual revision and CPU')
    need(all(type(r[k]) is bool for k in CLOSURE), 'actual closure flags')
    accepted = r['status'] == accepted_status
    if accepted:
        need(all(r[k] for k in CLOSURE) and r['error'] is None and r['final_errors'] == [],
             'recorded successful cohort retains complete closure')
    source = r['source']
    need(source is None or set(source) == {'revision', 'tree', 'source_manifest_sha256',
         'tracked_clean', 'head_sources_match'}, 'bounded actual source identity')
    if source is not None: need(source['revision'] == revision, 'same recorded source revision')
    hardware = {k: r['hardware'][k] for k in HARDWARE}
    hardware.update(isa_flags_count=len(r['hardware']['isa_flags']),
                    isa_flags_sha256=digest(r['hardware']['isa_flags']))
    commands = r['commands']
    need(type(commands) is list and len(commands) <= planned and
         len({c['name'] for c in commands}) == len(commands), 'unique bounded actual command rows')
    if accepted: need(len(commands) == planned, 'all planned commands recorded')
    captures, rows, command_errors = [], {}, []
    for command in commands:
        name = command['name']
        need(re.fullmatch('[a-zA-Z0-9_-]+', name) or
             (component_names and name in COMPONENT_LINK_COMMANDS), 'actual command label')
        kind = ('component' if name in {n+'-component' for n in component_names} else 'build') if component_names else command['profile']
        need(command['bounds'] == r['bounds'][kind], 'unchanged recorded profile bounds')
        if accepted:
            need(command.get('reaped') is True and command.get('timed_out') is False and
                 command.get('error') is None and command.get('cleanup_errors') == [] and
                 type(command.get('descriptors')) is list and all(d['closed'] is True for d in command['descriptors']) and
                 type(command.get('exit')) is int and command['exit'] == command['expected_exit'],
                 'each recorded successful command keeps its actual exit and cleanup')
        observed = {}
        for stream, entry in sorted(command.get('captures', {}).items()):
            need(stream in ('stdout', 'stderr', 'record') and Path(entry['file']).name == entry['file'],
                 'actual local command capture')
            value = fact(path.parent/entry['file'])
            need(value == {k: entry[k] for k in ('bytes', 'sha256')}, 'whole actual capture bytes')
            observed[stream] = value; captures.append(dict(command=name, stream=stream, **value))
        rows[name] = (command, observed)
        if command.get('error') or command.get('cleanup_errors'):
            command_errors.append(dict(command=name, error=public_text(command.get('error')),
                cleanup_errors=[public_text(e) for e in command.get('cleanup_errors', [])]))
    subjects = []; components = {}; summary_fact = None
    if component_names:
        summary_path = path.with_name('summary.json'); summary_fact = fact(summary_path)
        summary = decode(summary_path.read_bytes())
        need(summary['receipt'] == dict(receipt_fact, mode=format(path.stat().st_mode & 0o777, '04o')) and
             all(summary[k] == r[k] for k in ('profile', 'status', 'source', 'cpu', 'bounds', *CLOSURE)) and
             summary['hardware'] == dict((k, v) for k, v in r['hardware'].items() if k != 'isa_flags') |
                dict(isa_flags_count=hardware['isa_flags_count'], isa_flags_sha256=hardware['isa_flags_sha256']),
             'collector-produced component summary matches whole receipt and metadata')
        need(set(r['components']) <= set(component_names) and set(summary['components']) == set(r['components']),
             'only recorded original component slots')
        for name, item in r['components'].items():
            small = summary['components'][name]
            need(all(small[k] == item[k] for k in ('status', 'result', 'binary', 'recipe')),
                 'whole actual component result and source recipe')
            if accepted: need(item['status'] == 'passed', 'each component actually passed')
            components[name] = {k: small[k] for k in ('status', 'result', 'binary', 'recipe')}
        if accepted: need(set(components) == set(component_names), 'complete component population')
        need(r['archive_builds'] == 0 and r['archive_source_provenance_verified'] is False and
             r['generated_execution'] == r['native_execution'] == 0 and r['owner_credit'] is False and
             r['qualification_credit'] is r['performance_credit'] is False,
             'component-only supplied-archive scope remains exact')
    else:
        if profile == 'bounded-fused-owner-v1':
            cases = r['cases'] + r['fault_cases']
            expected = [(lane, 0, 0, state) for lane, state in zip(('native', 'maintained', 'differential'), PF_POSITIVE)] + [
                (lane, mode, 0, state) for (lane, mode), state in zip(
                    (('native', 1), ('maintained', 1), ('native', 2), ('maintained', 2)), PF_FAULT)]
        else:
            cases = r['cases']
            expected = [(lane, mode, placement, 'observed_required_read_fault' if mode >= 5 else 'observed_focal_completion')
                        for lane in ('maintained', 'differential') for mode in range(7) for placement in range(4)]
        need(len(cases) == len(expected), 'all original planned subject slots, including unreached ones')
        for case, (lane, mode, placement, success) in zip(cases, expected):
            need(case.get('build_lane', case['lane']) == lane and case['mode'] == mode and
                 case.get('placement', 0) == placement and case['control'] == 0 and
                 case['status'] in ('unexecuted', 'failed', success), 'literal subject identity/status')
            if accepted: need(case['status'] == success, 'every original subject accepted by its collector')
            command, observed = rows.get(case['label'], ({}, {}))
            need(case.get('exit') == command.get('exit') and case.get('whole_process_ns') == command.get('duration_ns') and
                 case['launched'] == (type(command.get('pid')) is int), 'actual case/command process join')
            if 'captures' in case: need(case['captures'] == observed, 'actual case/command whole captures')
            control_values = {k: controls(v) for k, v in case.items() if k.endswith('_controls')}
            pair = case.get('pair'); pair = None if pair is None else numeric(pair)
            subjects.append(dict(label=case['label'], lane=lane, mode=mode, placement=placement,
                status=case['status'], launched=case['launched'], expected_exit=case['expected_exit'], exit=case.get('exit'),
                validation_duration_ns=case.get('whole_process_ns'), timed_out=case.get('timed_out'),
                error=public_text(case.get('error')), errors=[public_text(e) for e in case.get('errors', [])],
                captures=observed, recorded_pair=pair, recorded_controls=control_values,
                complete_case_accepted=case['status'] == success))
    value = dict(schema=1, profile=profile+'-projection', status=r['status'], revision=revision, cpu=cpu,
        source=source, hardware=hardware, receipt=receipt_fact, component_summary=summary_fact,
        bounds=r['bounds'], closure={k: r[k] for k in CLOSURE},
        error=public_text(r['error']), final_errors=[public_text(e) for e in r['final_errors']],
        commands=dict(planned=planned, recorded=len(commands), sha256=digest(commands),
            exit_counts=dict(Counter(str(c.get('exit')) for c in commands)), errors=command_errors),
        captures=dict(count=len(captures), bytes=sum(c['bytes'] for c in captures), sha256=digest(captures)),
        archive=r.get('archive'), components=components, subjects=subjects,
        recorded_cohort_accepted=accepted, projection_only=True, qualification_credit=False,
        performance_credit=False, whole_profile_qualified=False,
        scope='Literal closed finite results only. Partial results on failed cases are not accepted equivalence; durations are validation cost.',
        reproduce=dict(precondition='Clean exact revision; same reserved CPU and fresh same-source prerequisites. Preserve all original gates.',
            argv=recipe(script, revision, cpu, bool(component_names)), original_argv_observed=False,
            note='Fresh invocation recipe reconstructed from the tracked collector API; original collector argv was not retained in this receipt.'))
    if component_names:
        value.update(archive_builds=0, archive_source_provenance_verified=False, native_execution=0,
                     generated_execution=0, owner_credit=False)
    table = io.StringIO(); writer = csv.writer(table, lineterminator='\n')
    writer.writerow(('revision', 'cpu', 'cohort_status', 'kind', 'name', 'status', 'exit',
                     'validation_duration_ns', 'recorded_values_json', 'qualification_credit', 'performance_credit'))
    for name, item in components.items():
        command = rows.get(name+'-component', ({}, {}))[0]
        writer.writerow((revision, cpu, r['status'], 'component', name, item['status'], command.get('exit'),
            command.get('duration_ns'), canonical(item['result']).decode(), False, False))
    for case in subjects:
        writer.writerow((revision, cpu, r['status'], 'subject', case['label'], case['status'], case['exit'],
            case['validation_duration_ns'], canonical(dict(pair=case['recorded_pair'], controls=case['recorded_controls'])).decode(), False, False))
    csv_bytes = table.getvalue().encode(); value['csv'] = dict(file='result.csv', bytes=len(csv_bytes),
                                                             sha256=hashlib.sha256(csv_bytes).hexdigest())
    encoded = json.dumps(value, sort_keys=True, indent=2, allow_nan=False).encode()+b'\n'
    public_text((encoded+csv_bytes).decode())
    need(fact(path) == receipt_fact and (summary_fact is None or fact(path.with_name('summary.json')) == summary_fact),
         'original receipt and component summary unchanged')
    args.output.mkdir(parents=True)
    for name, data in (('result.json', encoded), ('result.csv', csv_bytes)):
        with (args.output/name).open('xb') as stream: stream.write(data)
    print(json.dumps({name: fact(args.output/name) for name in ('result.json', 'result.csv')}, sort_keys=True))


if __name__ == '__main__': main()
