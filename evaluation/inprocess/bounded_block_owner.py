#!/usr/bin/env python3
"""Finite version10 bounded-block owner proof; old native41/392/522 remain separate."""
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
from bounded_block_owner_helpers import cohort,COMMAND_SCHEDULE
from bounded_block_owner_build import compile_subject
from direct_frontier_program import direct_prerequisite
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
    ap.add_argument('--direct-receipt',type=Path,required=True)
    ap.add_argument('--direct-receipt-sha256',required=True)
    ap.add_argument('--cpu',type=int,required=True)
    ap.add_argument('--output',type=Path,required=True)
    args = ap.parse_args()
    need(not sys.flags.optimize and sorted(os.sched_getaffinity(0)) == [args.cpu], 'assertions and one reserved CPU')
    os.chdir(ROOT)
    cpu = next(iter(os.sched_getaffinity(0)))
    private=args.output.absolute()
    need(private.parent==ROOT/'target/evaluation/inprocess'and not private.exists(),'fresh direct-child finite output')
    private.mkdir(parents=True,exist_ok=False)
    receipt = private/'receipt.json'
    r = dict(schema=1, status='failed', revision=args.expect_revision, source=None,
             source_unchanged=False, inputs_unchanged=False, cleanup_complete=False, commands=[], cases=[dict(label='subject-'+lane+'-0-0',lane=lane,mode=0,control=0,expected_exit=0,status='unexecuted',launched=False) for lane in ('native','maintained','differential')],
             error=None, final_errors=[], hardware=hardware(cpu), bounds=PROFILES,
             profile='bounded-block-owner-v1',whole_profile_qualified=False,
             required_qualification='original392/522 and native41 remain separate; PB20 finite source/CPU/archive/state evidence only',
             scope='native20/12 full frames, two cold all-arm-directory completions, warm A/B lifetime and real unsupported-store cancellation; no whole-program or performance credit')
    r.update(cpu=cpu,namespace_aliases={},terminal_reports={},lanes={},
        seed_prerequisite=dict(planned=1,status='unexecuted',launched=False,expected_exit=0,bounds=PROFILES['seed'],owner_subjects=0,completed_applications=0,performance_credit=False))
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
        need(len(r['commands'])<len(COMMAND_SCHEDULE)and (name,profile)==COMMAND_SCHEDULE[len(r['commands'])], 'exact fixed finite command order and bound profile')
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
        # Freeze all tracked implementation and reader inputs before any child launch.
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
        need(fact(pin(args.direct_receipt))['sha256']==args.direct_receipt_sha256,'exact explicit prior native41 receipt identity')
        r['direct_prerequisite']=direct_prerequisite(args.direct_receipt,r,pin,binary,products['archive'])
        original=compile_subject(builder,private,pin,binary,aliases,run,r)
        cohort(builder,products,private,pin,binary,aliases,run,r,original)
        need(tuple((c['name'],c['profile'])for c in r['commands'])==COMMAND_SCHEDULE,'complete fixed101-command finite schedule')
        r['status'] = 'observed_unqualified'
    except BaseException as exc:
        r['error'] = type(exc).__name__+': '+str(exc)
    finally:
        r['final_errors'].extend(builder.finish())
        try:
            closure()
            need(source() == r['source'], 'exact source unchanged')
            need(sorted(os.sched_getaffinity(0))==[args.cpu],'same reserved finite CPU at closure')
            r['source_unchanged'] = True
            r['inputs_unchanged'] = True
        except BaseException as exc:
            r['final_errors'].append(type(exc).__name__+': '+str(exc))
        r['cleanup_complete'] = all(c.get('reaped') and not c.get('cleanup_errors') and
            all(d['closed'] for d in c.get('descriptors', [])) for c in r['commands'])
        if r['error'] or r['final_errors'] or not r['source_unchanged'] or not r['cleanup_complete']:
            r['status'] = 'failed'
        r['inputs'] = pins
        r['artifacts'] = artifacts
        r['aliases'] = aliases
        r['presence'] = presence
        save(receipt, r)
    print(json.dumps(dict(status=r['status'], receipt=str(receipt.relative_to(ROOT)))))
    return int(r['status'] != 'observed_unqualified')


if __name__ == '__main__':
    raise SystemExit(main())
