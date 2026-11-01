#!/usr/bin/env python3
"""Fresh PF fault diagnostic using the unchanged four-case semantic cohort.

No positive or differential result, whole-profile qualification or performance
credit. Original native/maintained fault gates and all controls are mandatory.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import sys

sys.dont_write_bytecode = True
from checks import source
from run import hardware
from page_selected import ENV, fact, need, save
from page_selected_generic_build import Build
from page_selected_process import invoke
from page_selected_effect_ls import program_invoke
from page_selected_oneshot_build import before_default
from persistent_dynamic import BOUNDS, H, imported_sources, raw_emission, seed_prerequisite
from persistent_fused_build import build_bridge
from bounded_fused_owner_build import compile_subject
from bounded_fused_owner_helpers import BASE_COMMAND_SCHEDULE, observed_layout, reader_support
from bounded_fused_fault import cohort as fault_cohort, ORDER as FAULT_ORDER, COMMAND_SCHEDULE as FAULT_SCHEDULE
from direct_frontier_loop_helpers import prepare_inputs

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT/'tools/page-entry/selected/tests/persistent_fused_app'
PROBE_FIXTURE = {
    'machine.S': dict(bytes=8665, sha256='d4e31fda500864543a31f9908783bfce06d0a377233f99a05dea562516cb179d'),
    'read.py': dict(bytes=42398, sha256='b2a4eff201df78f5ca15db7c1fa2e1955090475dd43ed3838fb4fcd51462cc5a'),
}
# Keep the unchanged native policy/seed and maintained capture build path.
# Positive/differential populations belong to the separate full PF evaluator.
BUILD_SCHEDULE = tuple(row for row in BASE_COMMAND_SCHEDULE
    if not row[0].startswith(('differential-', 'subject-')))
SCHEDULE = BUILD_SCHEDULE + FAULT_SCHEDULE
EXPECTED = {name: (125 if name in ('subject-maintained-1-0', 'subject-maintained-2-0') else 0)
            for name, _ in SCHEDULE}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    ap.add_argument('--expect-decoder-sha256', required=True)
    ap.add_argument('--cpu', type=int, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    need(re.fullmatch('[0-9a-f]{40}', args.expect_revision) and
         re.fullmatch('[0-9a-f]{64}', args.expect_decoder_sha256), 'explicit exact source and decoder identities')
    need(not sys.flags.optimize and sorted(os.sched_getaffinity(0)) == [args.cpu], 'assertions and one externally reserved CPU')
    need(len(BASE_COMMAND_SCHEDULE) == 101 and len(BUILD_SCHEDULE) == 74 and len(SCHEDULE) == 78 and
         FAULT_ORDER == (('native', 1), ('maintained', 1), ('native', 2), ('maintained', 2)) and
         FAULT_SCHEDULE == tuple(('subject-'+lane+'-'+str(mode)+'-0', 'program') for lane, mode in FAULT_ORDER),
         'exact diagnostic build subset and complete unchanged four-fault schedule')
    os.chdir(ROOT)
    private = args.output.absolute()
    need(private.parent == ROOT/'target/evaluation/inprocess' and not private.exists(), 'fresh direct-child diagnostic output')
    private.mkdir(parents=True, exist_ok=False)
    r = dict(schema=1, profile='bounded-fused-fault-smoke-v1', status='failed',
        revision=args.expect_revision, expected_decoder_sha256=args.expect_decoder_sha256,
        cpu=args.cpu, hardware=hardware(args.cpu), source=None, source_unchanged=False,
        inputs_unchanged=False, cleanup_complete=False, commands=[], bounds=dict(BOUNDS),
        error=None, final_errors=[], namespace_aliases={}, lanes={}, terminal_reports={},
        qualification_credit=False, whole_profile_qualified=False, performance_credit=False,
        positive_cohort_completed=False, differential_cohort_completed=False,
        scope='Fresh native/maintained mode1/2 fault diagnostic only; unchanged fault state/pair/terminal controls, no positive or full-profile result.',
        fault_cases=[dict(label='subject-'+lane+'-'+str(mode)+'-0', lane=lane, mode=mode, control=0,
                    expected_exit=0 if lane=='native' else 125, status='unexecuted', launched=False)
                    for lane, mode in FAULT_ORDER],
        seed_prerequisite=dict(planned=1, status='unexecuted', launched=False, expected_exit=0,
            bounds=BOUNDS['seed'], owner_subjects=0, completed_applications=0, performance_credit=False))
    pins, artifacts, aliases, presence = {}, {}, {}, {}

    def pin(path):
        alias = Path(os.path.abspath(path)); p = alias.resolve(strict=True); value = fact(p)
        need(str(alias) not in aliases or aliases[str(alias)] == str(p), 'stable input alias')
        need(str(p) not in pins or pins[str(p)] == value, 'stable input bytes')
        pins[str(p)] = value; aliases[str(alias)] = str(p)
        return p

    def binary(path):
        p = Path(path).resolve(strict=True)
        value = dict(fact(p), mode=p.stat().st_mode & 0o777)
        need(str(p) not in artifacts or artifacts[str(p)] == value, 'stable artifact')
        artifacts[str(p)] = value
        return p

    def closure():
        need(all(fact(p) == v for p, v in pins.items()), 'input bytes unchanged')
        need(all(dict(fact(p), mode=Path(p).stat().st_mode & 0o777) == v
                 for p, v in artifacts.items()), 'artifact bytes and modes unchanged')
        need(all(str(Path(p).resolve(strict=True)) == v for p, v in aliases.items()), 'input aliases unchanged')
        need(all(os.path.lexists(p) == v for p, v in presence.items()), 'loader configuration presence')
        need(all(Path(p).is_symlink() and os.readlink(p) == v
                 for p, v in r['namespace_aliases'].items()), 'sealed namespace aliases unchanged')

    def run(name, argv, profile='metadata', expected=0, env=None, record=False):
        closure()
        need(sorted(os.sched_getaffinity(0)) == [args.cpu], 'same reserved CPU before every command')
        need(len(r['commands']) < len(SCHEDULE) and (name, profile) == SCHEDULE[len(r['commands'])] and
             type(expected) is int and expected == EXPECTED[name],
             'fixed fault diagnostic order, original bounds and exact original0/125 outcomes')
        row = dict(name=name, argv=list(map(str, argv)), environment=dict(ENV if env is None else env),
            profile=profile, bounds=BOUNDS[profile], capture_limit=16 << 20, expected_exit=expected)
        r['commands'].append(row)
        try:
            out, err = (program_invoke if name.startswith('subject-') else invoke)(row, private, args.cpu, record=record)
            need(row['exit'] == expected and not row['timed_out'], 'actual original expected command outcome: '+name)
            return row, out, err
        finally:
            for item in row.get('captures', {}).values():
                try:
                    need(fact(binary(private/item['file'])) == {k: item[k] for k in ('bytes', 'sha256')}, 'whole actual capture bytes')
                except BaseException as error:
                    r['final_errors'].append('capture '+name+': '+repr(error))
            try:
                p = private/(name+'.json')
                if p.exists():
                    need(json.loads(binary(p).read_bytes()) == row, 'retained actual command row')
            except BaseException as error:
                r['final_errors'].append('command record '+name+': '+repr(error))

    def build_run(name, argv, profile='metadata', env=None, expected=0):
        before_default(name, argv, builder, pin, aliases, run, r)
        return run(name, argv, profile=profile, expected=expected, env=env)

    builder = Build(r, private, pin, binary, build_run, ('region.rs',),
                    scalar_span=True, linked_epoch=True, mov_guard=True)
    try:
        r['source'] = source()
        need(r['source']['revision'] == args.expect_revision, 'exact clean tracked source')
        r['probe_fixture'] = {name:fact(pin(FIXTURE/name)) for name in PROBE_FIXTURE}
        need(r['probe_fixture'] == PROBE_FIXTURE, 'exact reviewed generic-TF NOP probe fixture and ELF reader')
        imported_sources(pin)
        git = pin(shutil.which('git', path=ENV['PATH']))
        _, names, err = run('tracked-input-list', [git, '-C', ROOT, 'ls-files', '-z', 'tools/page-entry', 'evaluation/inprocess'])
        need(names and not err, 'complete nonempty tracked input list from the repository')
        for raw in names.split(b'\0'):
            if raw and not os.fsdecode(raw).startswith('evaluation/inprocess/results/'):
                pin(ROOT/os.fsdecode(raw))
        for name in ('/etc/ld.so.cache', '/etc/ld.so.preload'):
            presence[name] = os.path.lexists(name)
            if presence[name]: pin(name)
        need(not presence['/etc/ld.so.preload'], 'no global preload')
        products = builder.prepare()
        need(fact(products['archive'])['sha256'] == args.expect_decoder_sha256, 'fresh source-authenticated decoder has the explicit expected identity')
        original = compile_subject(builder, private, pin, binary, aliases, run, r)
        reader, owner_reader, native_policy = reader_support(builder, private, pin, binary, run, r)
        app_layout = reader.elf(original.read_bytes(), native_policy)
        r['application_layout'] = {k:v for k,v in app_layout.items() if k not in ('source', 'sources')}
        r['application_layout']['source_pairs'] = [dict(bytes=len(value), sha256=H(value))
            for value in app_layout['source_pairs']]
        seed_reference = seed_prerequisite(builder, private, pin, binary, run, r)
        subjects = {}
        for lane in ('maintained',):
            directory = private/(lane+'-build'); directory.mkdir(); holder = r['lanes'][lane] = {}
            def lane_run(name, argv, profile='metadata', expected=0, env=None, record=False):
                return run(lane+'-'+name, argv, profile=profile, expected=expected, env=env, record=record)
            bridge = build_bridge(builder, products, directory, pin, binary, aliases, lane_run,
                                  holder, original, capture=True, differential=lane == 'differential')
            raw_emission(builder, bridge, pin, lane_run, holder)
            layout = observed_layout(builder, bridge, directory, pin, binary, lane_run, holder)
            inputs = prepare_inputs(original, bridge, builder, directory, pin, binary, lane_run, holder, r['application_build'])
            need(holder['release_build']['status']=='passed'and
                 holder['release_build']['profile']=='persistent-fused-'+('differential'if lane=='differential'else'capture')+'-v1'and
                 holder['release_build']['active_domain']['differential']==(lane=='differential')and
                 holder['release_build']['active_domain']['native_probe']is True and
                 holder['release_build']['persistent_binding']['native_probe']is True and
                 holder['release_build']['active_domain']['parse_memo']is True and
                 holder['release_build']['persistent_binding']['parse_memo']is True and
                 holder['release_build']['active_domain']['subentry']is True and
                 holder['release_build']['persistent_binding']['subentry']is True and
                 holder['release_build']['active_domain']['cross_pair']is True and
                 holder['release_build']['persistent_binding']['cross_pair']is True and
                 holder['release_build']['active_domain']['direct_frontier']is True and
                 holder['release_build']['persistent_binding']['direct_frontier']is True and
                 holder['release_build']['persistent_binding']['bounded_fused']is True and
                 holder['release_build']['persistent_binding']['policy_version']==11 and
                 holder['release_build']['pf_refusals']==holder['release_build']['persistent_binding']['pf_refusals']==dict(version=1,reason=256,shared_reasons=18,abi2=False) and
                 holder['release_build']['bounded_fused']==dict(version=1,policy_version=11,heads_max=128,shared_boundaries=8,active_members_max=2,call_ret=False) and
                 holder['release_build']['direct_frontier']['policy_version']==11 and
                 holder['release_build']['direct_frontier']['partition']=='direction-fused' and
                 holder['release_build']['direct_frontier']['all_arms_directory']is False,
                 'separate exact maintained/differential actual builds')
            need(holder['subject_artifacts']['original'] == fact(original), 'one unchanged fresh original application')
            subjects[lane] = (bridge, layout, *inputs)
        imported_sources(pin)
        fault_cohort(builder, private, pin, binary, run, r, original,
                     (app_layout, seed_reference, subjects))
        need(tuple((c['name'], c['profile']) for c in r['commands']) == SCHEDULE,
             'complete fixed78-command diagnostic schedule')
        need(r['seed_prerequisite']['status'] == 'passed', 'actual unchanged seed prerequisite')
        r['status'] = 'observed_fault_diagnostic_only'
    except BaseException as error:
        r['error'] = type(error).__name__+': '+str(error)
    finally:
        r['final_errors'].extend(builder.finish())
        try:
            imported_sources(pin)
            closure()
            need(source() == r['source'], 'exact source unchanged')
            need(sorted(os.sched_getaffinity(0)) == [args.cpu], 'same reserved CPU at closure')
            r['source_unchanged'] = r['inputs_unchanged'] = True
        except BaseException as error:
            r['final_errors'].append(type(error).__name__+': '+str(error))
        r['cleanup_complete'] = all(c.get('reaped') and not c.get('cleanup_errors') and
            all(d['closed'] for d in c.get('descriptors', [])) for c in r['commands'])
        if r['error'] or r['final_errors'] or not r['source_unchanged'] or not r['cleanup_complete']:
            r['status'] = 'failed'
        r.update(inputs=pins, artifacts=artifacts, aliases=aliases, presence=presence)
        save(private/'receipt.json', r)
    print(json.dumps(dict(status=r['status'], receipt=str((private/'receipt.json').relative_to(ROOT)))))
    return int(r['status'] != 'observed_fault_diagnostic_only')


if __name__ == '__main__':
    raise SystemExit(main())
