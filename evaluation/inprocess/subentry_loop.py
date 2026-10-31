#!/usr/bin/env python3
"""One retained graph: cold root then guarded internal entry, with full-state pairs."""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from checks import source
from run import hardware
from page_selected import ENV, fact, need, save
from page_selected_generic_build import Build
from persistent_dynamic import BOUNDS
from subentry_loop_helpers import cohort
from subentry_loop_build import compile_subject
from page_selected_effect_ls import program_invoke
import persistent_active_domain as component
from page_selected_process import invoke
from page_selected_oneshot_build import before_default

ROOT = Path(__file__).resolve().parents[2]
SELECTED = ROOT/'tools/page-entry/selected'
PROFILES = dict(BOUNDS)
def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    args = ap.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0)) == 1, 'assertions and one reserved CPU')
    os.chdir(ROOT)
    cpu = next(iter(os.sched_getaffinity(0)))
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    name = stamp+'-subentry-loop-'+args.expect_revision[:12]
    private = ROOT/'target/evaluation/inprocess'/name
    private.mkdir(parents=True, exist_ok=False)
    public = ROOT/'evaluation/inprocess/results'/(name+'.json')
    receipt = private/'receipt.json'
    r = dict(schema=1, status='failed', revision=args.expect_revision, source=None,
             source_unchanged=False, cleanup_complete=False, commands=[], cases=[dict(label='subject-'+lane+'-0-0',lane=lane,mode=0,control=0,expected_exit=0,status='unexecuted',launched=False) for lane in ('native','maintained','differential')],
             error=None, final_errors=[], hardware=hardware(cpu), bounds=PROFILES,
             scope='cold root and guarded member1 subentry after complete drain; no whole-program or performance credit')
    r.update(cpu=cpu, namespace_aliases={}, terminal_reports={}, lanes={},
        maps_parse_component=dict(status='unexecuted',launched=False,expected_exit=0,bounds=PROFILES['finite'],
            emitted_instruction_execution=0,hardware_subjects=0,performance_credit=False),
        native_probe_component=dict(status='unexecuted',launched=False,expected_exit=0,bounds=PROFILES['finite'],
            emitted_instruction_execution=0,hardware_subjects=0,performance_credit=False),
        component_oracles=[dict(name=n,status='unexecuted',launched=False,expected_exit=0,bounds=PROFILES['finite'],
            emitted_instruction_execution=0,hardware_subjects=0,performance_credit=False)for n in component.COMPONENT_ORDER],
        seed_prerequisite=dict(planned=1,status='unexecuted',launched=False,expected_exit=0,bounds=PROFILES['seed'],
            owner_subjects=0,completed_applications=0,performance_credit=False))
    pins, artifacts, aliases, presence = {}, {}, {}, {}

    def pin(path):
        alias=Path(os.path.abspath(path));p=alias.resolve(strict=True);value=fact(p)
        need(str(alias) not in aliases or aliases[str(alias)]==str(p),'stable input alias')
        need(str(p) not in pins or pins[str(p)]==value,'stable input bytes')
        pins[str(p)]=value;aliases[str(alias)]=str(p)
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
        need(all(os.path.lexists(p)==v for p,v in presence.items()),'loader configuration presence')
        need(all(Path(p).is_symlink() and os.readlink(p)==v for p,v in r['namespace_aliases'].items()),'sealed namespace aliases unchanged')

    def run(name, argv, profile='metadata', expected=0, env=None, record=False):
        closure()
        need(not any(c['name'] == name for c in r['commands']), 'unique command/capture name')
        row = dict(name=name, argv=list(map(str, argv)), environment=dict(ENV if env is None else env),
                   profile=profile, bounds=PROFILES[profile], capture_limit=16 << 20, expected_exit=expected)
        r['commands'].append(row)
        try:
            out, err = (program_invoke if name.startswith('subject-') else invoke)(row, private, cpu, record=record)
            need(expected is None or row['exit'] == expected, 'actual command exit: ' + name)
            return row, out, err
        finally:
            for item in row.get('captures', {}).values():
                try:
                    p = private / item['file']
                    need(fact(binary(p)) == {k: item[k] for k in ('bytes', 'sha256')}, 'actual capture bytes')
                except BaseException as error:
                    r['final_errors'].append('capture ' + name + ': ' + repr(error))
            try:
                p = private / (name + '.json')
                if p.exists():
                    need(json.loads(binary(p).read_bytes()) == row, 'retained actual command row')
            except BaseException as error:
                r['final_errors'].append('command record ' + name + ': ' + repr(error))

    def build_run(name, argv, profile='metadata', env=None, expected=0):
        before_default(name, argv, builder, pin, aliases, run, r)
        return run(name, argv, profile=profile, expected=expected, env=env)

    builder = Build(r, private, pin, binary, build_run, ('region.rs',),
                    scalar_span=True, linked_epoch=True, mov_guard=True)


    try:
        r['source'] = source()
        need(r['source']['revision'] == args.expect_revision, 'exact clean revision')
        # Freeze all tracked implementation and reader inputs before imports or launch.
        _,names,err=run('tracked-input-list',['git','ls-files','-z','tools/page-entry','evaluation/inprocess'])
        need(not err, 'complete tracked input list')
        for raw in names.split(b'\0'):
            if raw:
                name=os.fsdecode(raw)
                if not name.startswith('evaluation/inprocess/results/'):pin(ROOT/name)
        for name in ('/etc/ld.so.cache','/etc/ld.so.preload'):
            presence[name]=os.path.lexists(name)
            if presence[name]:pin(name)
        need(not presence['/etc/ld.so.preload'],'no global preload')
        products=builder.prepare()
        original=compile_subject(builder,private,pin,binary,aliases,run,r)
        cohort(builder,products,private,pin,binary,aliases,run,r,original)
        r['status'] = 'passed'
    except BaseException as exc:
        r['error'] = type(exc).__name__+': '+str(exc)
    finally:
        r['final_errors'].extend(builder.finish())
        try:
            closure()
            need(source() == r['source'], 'exact source unchanged')
            r['source_unchanged'] = True
        except BaseException as exc:
            r['final_errors'].append(type(exc).__name__+': '+str(exc))
        r['cleanup_complete'] = all(c.get('reaped') and not c.get('cleanup_errors') and
            all(d['closed'] for d in c.get('descriptors', [])) for c in r['commands'])
        if r['error'] or r['final_errors'] or not r['source_unchanged'] or not r['cleanup_complete']:
            r['status'] = 'failed'
        r['inputs'] = pins
        r['artifacts'] = artifacts
        save(receipt, r)
        summary = {k: r[k] for k in ('schema', 'status', 'revision', 'source', 'source_unchanged',
            'cleanup_complete', 'hardware', 'bounds', 'scope')}
        summary['cases']=[{k:c[k] for k in ('lane','mode','status','expected_exit','exit','whole_process_ns',
            'timed_out','launched','captures','pair','owner_summary','error_type') if k in c} for c in r['cases']]
        for compact,actual in zip(summary['cases'],r['cases'],strict=True):
            compact['controls']={name:dict(count=len(actual[name]['refusals']),
                sha256=hashlib.sha256(json.dumps(actual[name],sort_keys=True,separators=(',',':')).encode()).hexdigest())
                for name in ('application_controls','owner_reader_controls','pair_controls',
                             'terminal_controls','repeat_tls_controls','native_probe_controls','subentry_controls') if name in actual}
        summary['subentry_component']={k:r.get('subentry_component',{}).get(k)
            for k in ('status','counts','exit','duration_ns','native_operations','qualification_credit')}
        summary['empty_namespace_component']={k:r.get('empty_namespace_component',{}).get(k)
            for k in ('status','counts','exit','duration_ns','native_operations','qualification_credit')}
        summary['copy_oracle']={k:r.get('application_build',{}).get('copy_oracle',{}).get(k)
            for k in ('status','counts','body','exit','duration_ns')}
        summary['closure']=dict(inputs=len(pins),artifacts=len(artifacts),commands=len(r['commands']),
            captures=sum(len(c.get('captures',{})) for c in r['commands']),final_error_count=len(r['final_errors']))
        summary.update(receipt=fact(receipt), application=r.get('application_build',{}).get('artifact'),
            reproduce=['cpuset-alloc','run','--cores','1','--','python3','-B',
                       'evaluation/inprocess/subentry_loop.py','--expect-revision',args.expect_revision],
            tool_versions=builder.record.get('numeric_versions'), error_type=r['error'].split(':', 1)[0] if r['error'] else None,
            commands=[{k: c.get(k) for k in ('name', 'exit', 'duration_ns', 'timed_out', 'reaped')}
                      for c in r['commands']])
        payload = (json.dumps(summary, sort_keys=True)+'\n').encode()
        need(len(payload) <= 32768 and b'/home/' not in payload, 'compact public receipt without host paths')
        public.write_bytes(payload)
        with public.with_suffix('.csv').open('w', newline='') as f:
            w = csv.writer(f, lineterminator='\n')
            w.writerow(('revision', 'command', 'exit', 'duration_ns', 'status'))
            for c in r['commands']:
                w.writerow((args.expect_revision, c['name'], c.get('exit'), c.get('duration_ns'), r['status']))
    print(json.dumps(dict(status=r['status'], receipt=str(public.relative_to(ROOT)))))
    return int(r['status'] != 'passed')


if __name__ == '__main__':
    raise SystemExit(main())
