#!/usr/bin/env python3
"""Two fresh causal subjects; the three prior positive subjects stay historical."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
ROOT = Path.cwd().resolve()
sys.path[:0] = [str(ROOT/'evaluation/inprocess'), str(ROOT/'tools/page-entry')]
from checks import source
from run import hardware
from page_selected import ENV, fact, need, save
from page_selected_process import invoke
from page_selected_effect_ls import program_invoke
from persistent_dynamic import BOUNDS, imported_sources
from persistent_loop_native_build import FIXTURE, preparation
from persistent_loop_effects_native import summary
from direct_frontier_loop_helpers import prepare_inputs
import loop_ro_native_positive as positive
from loop_ro_oracle_build import build_control
import loop_ro_oracle_reports as reports

MODES = ('byte', 'history')
SCHEDULE = (('historical-decoder-recipe', 'metadata'),) + tuple(
    (mode+'-'+name, profile) for mode in MODES for name, profile in (
        ('build', 'release_build'), ('headers', 'metadata'), ('undefined', 'inspect'),
        ('symbols', 'inspect'), ('carrier', 'program'))
) + tuple(('subject-'+mode+'-0-0', 'program') for mode in MODES)
H = lambda data: hashlib.sha256(data).hexdigest()
# These six literal test-only insertion spans reconstruct the entire actual
# production donor at the successful prior experiment; no arbitrary inverse.
HOOKS = {'tools/page-entry/selected/loop_ro_certificate.h': [{'new': '#include "loop_history_certificate.h"\n#ifdef LI2_LOOP_RO_TEST\n#include "loop_ro_oracle.h"\n#endif\n', 'old': '#include "loop_history_certificate.h"\n'}], 'tools/page-entry/selected/loop_ro_certificate.inc': [{'new': '    int error=lhc_initialize();if(error)return error;\n#ifdef LI2_LOOP_RO_TEST\n    error=lro_initialize();if(error)return error;\n#endif\n', 'old': '    int error=lhc_initialize();if(error)return error;\n'}, {'new': '    lhc_report(status,code);\n#ifdef LI2_LOOP_RO_TEST\n    lro_report(status,code);\n#endif\n', 'old': '    lhc_report(status,code);\n'}], 'tools/page-entry/selected/sealed_byte_certificate.inc': [{'new': 'static int pe_bytes(void) {\n#ifdef LI2_LOOP_RO_TEST\n    lro_byte_hook();\n#endif\n', 'old': 'static int pe_bytes(void) {\n'}], 'tools/page-entry/selected/loop_history_certificate.inc': [{'new': '    if(!lhc_match(c,i)) { (void)lhc_add(&lhc.counts.errors,1);return 0; }\n#ifdef LI2_LOOP_RO_TEST\n    lro_history_hook(c,i);\n#endif\n', 'old': '    if(!lhc_match(c,i)) { (void)lhc_add(&lhc.counts.errors,1);return 0; }\n'}], 'tools/page-entry/selected/persistent_group_controller.inc': [{'new': '#include "persistent_active_domain.inc"\n#ifdef LI2_LOOP_RO_TEST\n#include "loop_ro_oracle.inc"\n#endif\n', 'old': '#include "persistent_active_domain.inc"\n'}]}


def source_input(relative, data, expected):
    """Authenticate a whole compiler input, with only the complete hook inverse.

    Hook presence/uniqueness is checked even when the retained build already
    compiled these current default-off insertions. No partial inverse is used.
    """
    inverse = data
    if relative in HOOKS:
        for span in reversed(HOOKS[relative]):
            before, after = span['old'].encode(), span['new'].encode()
            need(inverse.count(after) == 1, 'one exact conditional test-hook span')
            inverse = inverse.replace(after, before)
    current = dict(bytes=len(data), sha256=H(data))
    historical = dict(bytes=len(inverse), sha256=H(inverse))
    need(expected == current or (relative in HOOKS and expected == historical),
         'whole current production compiler input or exact complete test-hook inverse')
    return 'current' if expected == current else 'hook_inverse'


def reference(path, expected, r, pin, binary, complete, reader, image, seed):
    path = pin(path)
    need(path.name == 'receipt.json' and path.parent.parent == ROOT/'target/evaluation/inprocess'
         and fact(path)['sha256'] == expected, 'explicit whole prior positive receipt')
    n = json.loads(path.read_bytes()); directory = path.parent
    need(n['profile'] == 'loop-ro-native-positive-v1' and n['status'] == 'observed_positive_application_pairs'
         and n['revision'] == n['source']['revision'] and re.fullmatch('[0-9a-f]{40}', n['revision'])
         and n['source']['tracked_clean'] is True and n['source']['head_sources_match'] is True
         and n['cpu'] == r['cpu'] and n['hardware'] == r['hardware'] and n['bounds'] == BOUNDS
         and n['error'] is None and n['final_errors'] == []
         and all(n[k] is True for k in ('source_unchanged', 'inputs_unchanged', 'cleanup_complete'))
         and all(n[k] is False for k in ('owner_credit', 'qualification_credit', 'performance_credit'))
         and n['causal_suites'] == 'pending_unexecuted',
         'closed original positive outcome with historical revision and identical hardware/CPU')
    need(tuple((x['name'], x['profile']) for x in n['commands']) == positive.SCHEDULE
         and len(n['commands']) == 14 and [c['status'] for c in n['cases']] ==
         ['observed_fresh_native_reference', 'observed_positive_application_pair', 'observed_positive_application_pair']
         and n['retained_inputs'] == r['retained_inputs'],
         'all original positive commands/cases and exact reused setup authority')
    # Authenticate every original closed row/capture identity, but decode only
    # the native reference used by these fresh causal subjects.
    for command in n['commands']:
        complete(command)
        need(command['expected_exit'] == 0, 'all original positive commands expected zero')
        record = binary(directory/(command['name']+'.json'))
        need(json.loads(record.read_bytes()) == command, 'whole original closed positive command row')
        for value in command['captures'].values():
            capture = binary(directory/value['file'])
            need(capture.parent == directory and fact(capture) == {k: value[k] for k in ('bytes', 'sha256')},
                 'whole original bounded positive capture')
    # Every actual prior input is whole-equal to current bytes or the complete
    # six-insertion inverse. Both branches require unique current hook spans.
    # Generated prior headers remain retained, never current binding authority.
    seen = set()
    for mode in ('release', 'differential'):
        build = n['builds'][mode]
        need(build['status'] == 'compiled_diagnostic_only', 'actual prior production recipe completed')
        for name, value in build['headers'].items():
            lexical = Path(name); data = pin(lexical).read_bytes(); relative = None
            try: relative = str(lexical.relative_to(ROOT))
            except ValueError: pass
            source_input(relative, data, value)
            if relative in HOOKS: seen.add(relative)
        for value in build['binding']['sources']:
            path = pin(ROOT/'tools/page-entry/selected'/value['path']); data = path.read_bytes()
            relative = str(path.relative_to(ROOT))
            source_input(relative, data, {k: value[k] for k in ('bytes', 'sha256')})
    need(seen == set(HOOKS), 'every test-hook donor was in actual prior compiled closure')
    command = next(x for x in n['commands'] if x['name'] == 'subject-native-0-0')
    out = pin(directory/command['captures']['stdout']['file']).read_bytes()
    native = reader.read(out, 0, 0, 0, command['exit'], image, command['pid'], r['cpu'], seed)
    need(summary(native, 0, 0) == n['cases'][0]['native'] and native['native_frames'] == 107
         and native['native_instructions'] == 106 and native['native_reference_complete'] is True
         and native['application_complete'] is True, 'whole actual prior fresh native reference reconstructed')
    r['prior_positive'] = dict(receipt=fact(path), revision=n['revision'], source=n['source'],
        cpu=n['cpu'], native_capture={k: command['captures']['stdout'][k] for k in ('bytes', 'sha256')},
        native_frames=107, native_instructions=106, prior_subjects=3, current_subjects_replayed=0,
        current_production_sources_equal_except_exact_test_hooks=True,
        scope='Prior successful native/release/DIFF evidence; no positive subject rerun or current qualification.')
    return native


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    ap.add_argument('--native-receipt', type=Path, required=True)
    ap.add_argument('--native-receipt-sha256', required=True)
    ap.add_argument('--positive-receipt', type=Path, required=True)
    ap.add_argument('--positive-receipt-sha256', required=True)
    ap.add_argument('--current-build-receipt', type=Path)
    ap.add_argument('--current-build-sha256')
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args(); affinity = os.sched_getaffinity(0)
    need(sys.version_info[:2] == (3, 12) and not sys.flags.optimize and len(affinity) == 1
         and re.fullmatch('[0-9a-f]{40}', a.expect_revision)
         and all(re.fullmatch('[0-9a-f]{64}', v) for v in
             (a.native_receipt_sha256, a.positive_receipt_sha256)),
         'Python3.12/assertions, reserved singleton and whole explicit identities')
    need((a.current_build_receipt is None) == (a.current_build_sha256 is None),
         'explicit current build receipt and whole hash are supplied together')
    cpu = next(iter(affinity)); private = a.output.absolute()
    need(private.parent == ROOT/'target/evaluation/inprocess' and not private.exists(), 'fresh direct output child')
    private.mkdir(); pins, artifacts, aliases = {}, {}, {}
    r = dict(schema=1, profile='loop-ro-native-causal-v1', status='failed', revision=a.expect_revision,
        cpu=cpu, hardware=hardware(cpu), source=None, argv=[sys.executable, '-B', *sys.argv],
        bounds=dict(BOUNDS), commands=[], builds={}, namespace_aliases={}, presence={},
        error=None, final_errors=[], source_unchanged=False, inputs_unchanged=False, cleanup_complete=False,
        owner_credit=False, qualification_credit=False, performance_credit=False,
        cases=[dict(label='subject-'+mode+'-0-0', lane=1, mode=0, placement=0, control=0,
            suite=mode, cpu=cpu, expected_exit=125, status='unexecuted', launched=False) for mode in MODES])

    def pin(path):
        lexical = Path(os.path.abspath(path)); p = lexical.resolve(strict=True); value = fact(p)
        need(str(p) not in pins or pins[str(p)] == value, 'stable whole input')
        need(str(lexical) not in aliases or aliases[str(lexical)] == str(p), 'stable input alias')
        pins[str(p)] = value; aliases[str(lexical)] = str(p); return p

    def binary(path):
        p = pin(path); value = dict(fact(p), mode=p.stat().st_mode & 0o777)
        need(str(p) not in artifacts or artifacts[str(p)] == value, 'stable whole artifact bytes/mode')
        artifacts[str(p)] = value; return p

    def closure():
        need(source() == r['source'] and os.sched_getaffinity(0) == {cpu}, 'same clean source and reserved CPU')
        need(all(fact(p) == v for p, v in pins.items()), 'whole input closure')
        need(all(dict(fact(p), mode=Path(p).stat().st_mode & 0o777) == v for p, v in artifacts.items()),
             'whole artifact closure')
        need(all(str(Path(p).resolve(strict=True)) == v for p, v in aliases.items()), 'input alias closure')
        need(all(os.path.lexists(p) == v for p, v in r['presence'].items()), 'loader configuration presence')
        need(all(Path(p).is_symlink() and os.readlink(p) == v for p, v in r['namespace_aliases'].items()),
             'namespace alias closure')

    def complete(row):
        need(type(row['exit']) is int and row['exit'] == row['expected_exit']
             and row['timed_out'] is False and row['error'] is None and row['reaped'] is True
             and row['cleanup_errors'] == [] and type(row['descriptors']) is list
             and all(d.get('closed') is True for d in row['descriptors'])
             and row['bounds'] == BOUNDS[row['profile']] and row['capture_limit'] == 16 << 20,
             'exact original bounded outcome and process/descriptor closure')

    def run(name, argv, profile='metadata', expected=0, env=None, record=False):
        closure(); subject = name.startswith('subject-')
        need(len(r['commands']) < len(SCHEDULE) and (name, profile) == SCHEDULE[len(r['commands'])]
             and expected == (125 if subject else 0) and record is subject,
             'fixed13 schedule, exact required refusal exits and only subject record descriptors')
        row = dict(name=name, argv=list(map(str, argv)), environment=dict(ENV if env is None else env),
            profile=profile, bounds=BOUNDS[profile], capture_limit=16 << 20, expected_exit=expected)
        r['commands'].append(row)
        try:
            out, err = (program_invoke if record else invoke)(row, private, cpu, record=record)
            complete(row); return row, out, err
        finally:
            for value in row.get('captures', {}).values():
                try: need(fact(binary(private/value['file'])) == {k: value[k] for k in ('bytes', 'sha256')},
                          'whole fresh bounded capture')
                except BaseException as error: r['final_errors'].append(repr(error))
            path = private/(name+'.json')
            if path.exists():
                try: need(json.loads(binary(path).read_bytes()) == row, 'whole fresh command row')
                except BaseException as error: r['final_errors'].append(repr(error))
            save(private/'receipt.json', r)
            print(json.dumps(dict(command=name, exit=row.get('exit'), duration_ns=row.get('duration_ns'))), flush=True)

    try:
        r['source'] = source(); need(r['source']['revision'] == a.expect_revision, 'exact clean current source')
        pin(__file__); imported_sources(pin)
        current = None
        if a.current_build_receipt is not None:
            from loop_ro_current_archive import current_archive
            current = current_archive(a.current_build_receipt, a.current_build_sha256, ROOT, pin, binary, aliases)
        builder, archive, original, reader, image, seed, app = positive.retained_support(
            a.native_receipt, a.native_receipt_sha256, r, pin, binary, aliases, complete, run, current_build=current)
        native = reference(a.positive_receipt, a.positive_receipt_sha256, r, pin, binary, complete, reader, image, seed)
        launch = pin(FIXTURE/'launch.py'); subjects = {}
        for mode in MODES:
            directory = private/(mode+'-build'); directory.mkdir(); state = r['builds'][mode] = {}
            def lane_run(name, argv, profile='metadata', expected=0, env=None, record=False):
                return run(mode+'-'+name, argv, profile, expected, env, record)
            bridge = build_control(builder, archive, original, directory, pin, binary, aliases, lane_run, state, mode)
            subjects[mode] = prepare_inputs(original, bridge, builder, directory, pin, binary, lane_run, state, app)
        imported_sources(pin)
        for case in r['cases']:
            mode, label = case['suite'], case['label']; case.update(status='failed', launched=True)
            directory = private/label; directory.mkdir()
            _, roots, objects, description, _, _, carrier = subjects[mode]
            try:
                row, out, err = run(label, [builder.tools['python'], '-B', launch, '--root', ROOT,
                    '--role', 'gated', '--case', 0, '--placement', 0, '--control', 0, '--original', original,
                    '--library-root', original.parent, '--preparation', directory/'preparation.json',
                    '--carrier', carrier, '--namespace', directory/'namespace', '--record-fd', '{record_fd}'],
                    profile='program', expected=125, record=True)
                preparation(case, row, directory, original, roots, objects, description, carrier, private, binary, r)
                need(row['captures']['record']['bytes'] == 0, 'distinct test terminal, no old owner-schema bytes')
                prefix = reader.prefix(out, 1, 0, 0, image, row['pid'], cpu, seed)
                keys = ('hardware', 'facts', 'seed', 'machine', 'source', 'data', 'stack', 'base',
                        'page', 'entry', 'predecessor', 'endpoint')
                need(all(reader.identical(prefix[key], native[key]) for key in keys),
                     'whole actual initial application state equals the independently decoded prior native')
                result = reports.check(err, mode)
                case.update(status='observed_causal_controls', prefix_sha256=H(out),
                    initial_state_fields=list(keys), results=result,
                    application_completed=False, final_application_state_observed=False)
            except Exception as error: case['error'] = type(error).__name__+': '+str(error)
        need(len(r['commands']) == 13 and all(c['status'] == 'observed_causal_controls' for c in r['cases']),
             'both complete real causal suites and all13 original bounded commands mandatory')
        r['status'] = 'observed_causal_controls'
    except BaseException as error: r['error'] = type(error).__name__+': '+str(error)
    finally:
        for case in r['cases']:
            rows = [x for x in r['commands'] if x['name'] == case['label']]
            if rows:
                row = rows[0]; case.update(exit=row.get('exit'), timed_out=row.get('timed_out'),
                    duration_ns_validation_only=row.get('duration_ns'),
                    captures={k: {j: v[j] for j in ('bytes', 'sha256')} for k, v in row.get('captures', {}).items()})
        try:
            imported_sources(pin); closure(); r['source_unchanged'] = r['inputs_unchanged'] = True
            for row in r['commands']:
                need(json.loads(binary(private/(row['name']+'.json')).read_bytes()) == row, 'final whole command row')
                for value in row.get('captures', {}).values():
                    need(fact(binary(private/value['file'])) == {k: value[k] for k in ('bytes', 'sha256')},
                         'final whole capture')
        except BaseException as error: r['final_errors'].append(type(error).__name__+': '+str(error))
        r['cleanup_complete'] = bool(r['commands']) and all(x.get('reaped') is True and x.get('cleanup_errors') == []
            and type(x.get('descriptors')) is list and all(d.get('closed') is True for d in x['descriptors'])
            for x in r['commands'])
        if r['error'] or r['final_errors'] or not r['cleanup_complete']: r['status'] = 'failed'
        r.update(inputs=pins, artifacts=artifacts, aliases=aliases); save(private/'receipt.json', r)
        public = {k: r[k] for k in ('schema', 'profile', 'status', 'revision', 'cpu', 'bounds',
            'source_unchanged', 'inputs_unchanged', 'cleanup_complete', 'owner_credit',
            'qualification_credit', 'performance_credit')}
        public.update(receipt=fact(private/'receipt.json'), hardware=r['hardware'],
            prior_positive={k: v for k, v in r.get('prior_positive', {}).items() if k != 'source'},
            commands=[{k: x.get(k) for k in ('name', 'expected_exit', 'exit', 'timed_out', 'duration_ns')}
                      for x in r['commands']],
            cases=[{k: c[k] for k in ('label', 'suite', 'status', 'launched', 'exit', 'timed_out',
                'duration_ns_validation_only', 'captures', 'prefix_sha256') if k in c} |
                dict(control_count=len(c.get('results', {}).get('controls', [])),
                     restored_baselines=c.get('results', {}).get('oracle', {}).get('restorations'),
                     result_sha256=H(json.dumps(c.get('results', {}), sort_keys=True,
                         separators=(',', ':')).encode())) for c in r['cases']],
            scope='Two additive actual causal subjects with required125 only after every control/restoration. '
                  'Prior three positive subjects retain their own revision. No final application, warm-code, '
                  'interior owner, qualification or performance credit.')
        text = json.dumps(public, sort_keys=True, indent=2)+'\n'
        need(len(text.encode()) < 24 << 10 and '/home/' not in text and str(ROOT) not in text,
             'bounded public observation without host paths or raw logs')
        save(private/'summary.json', public)
    print(json.dumps(dict(status=r['status'], receipt=str((private/'receipt.json').relative_to(ROOT)))), flush=True)
    return 0 if r['status'] == 'observed_causal_controls' else 1


if __name__ == '__main__':
    raise SystemExit(main())
