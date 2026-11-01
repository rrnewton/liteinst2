#!/usr/bin/env python3
"""Fresh policy14 focal owner: 56 gated subjects, full native pairs, no lifecycle credit."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import sys
sys.dont_write_bytecode=True
from checks import source
from run import hardware
from page_selected import ENV,fact,need,save
from page_selected_process import invoke
from page_selected_effect_ls import program_invoke
from persistent_dynamic import BOUNDS,imported_sources
from persistent_loop_archive import Build
from persistent_loop_build_default import before_loop_default
from persistent_loop_native_prerequisite import authenticate
from persistent_loop_owner_helpers import PROFILE,ORDER,SCHEDULE,cohort
from persistent_loop_owner_prerequisite import legacy

ROOT=Path(__file__).resolve().parents[2]


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision',required=True);ap.add_argument('--cpu',type=int,required=True)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--direct-receipt',type=Path,required=True)
    ap.add_argument('--direct-receipt-sha256',required=True)
    for name in('block','fused','loop-component','loop-native'):
        ap.add_argument('--'+name+'-receipt',type=Path,required=True)
        ap.add_argument('--'+name+'-receipt-sha256',required=True)
    args=ap.parse_args()
    need(re.fullmatch('[0-9a-f]{40}',args.expect_revision)and not sys.flags.optimize and
         sorted(os.sched_getaffinity(0))==[args.cpu],'exact source, assertions and externally reserved singleton CPU')
    need(len(SCHEDULE)==126 and len({n for n,_ in SCHEDULE})==126 and len(ORDER)==56,
         'entire fixed archive/build and seven-by-four two-lane schedule')
    os.chdir(ROOT);private=args.output.absolute()
    need(private.parent==ROOT/'target/evaluation/inprocess'and not private.exists(),'fresh direct-child focal output')
    private.mkdir(parents=True,exist_ok=False)
    r=dict(schema=1,profile=PROFILE,status='failed',revision=args.expect_revision,cpu=args.cpu,hardware=hardware(args.cpu),
        source=None,source_unchanged=False,inputs_unchanged=False,cleanup_complete=False,commands=[],bounds=dict(BOUNDS),
        error=None,final_errors=[],namespace_aliases={},lanes={},focal_only=True,whole_profile_qualified=False,
        cold_warm_validated=False,mixed_policy_validated=False,replacement_validated=False,held_cancellation_validated=False,
        qualification_credit=False,performance_credit=False,
        prerequisite_inputs={n:dict(path=str(getattr(args,n+'_receipt').absolute()),
            sha256=getattr(args,n+'_receipt_sha256',None))for n in('direct','block','fused','loop_component','loop_native')},
        cases=[dict(label='subject-'+lane+'-'+str(case)+'-'+str(place),build_lane=lane,lane=1,mode=case,
            placement=place,control=0,cpu=args.cpu,expected_exit=125 if case>=5 else 0,status='unexecuted',launched=False)
            for lane,case,place in ORDER])
    pins,artifacts,aliases,presence={},{},{},{}
    def pin(path):
        lexical=Path(os.path.abspath(path));p=lexical.resolve(strict=True);value=fact(p)
        need(str(lexical)not in aliases or aliases[str(lexical)]==str(p),'stable input alias')
        need(str(p)not in pins or pins[str(p)]==value,'stable whole input bytes')
        aliases[str(lexical)]=str(p);pins[str(p)]=value;return p
    def binary(path):
        p=Path(path).resolve(strict=True);value=dict(fact(p),mode=p.stat().st_mode&0o777)
        need(str(p)not in artifacts or artifacts[str(p)]==value,'stable whole artifact bytes and mode')
        artifacts[str(p)]=value;return p
    def closure():
        need(all(fact(p)==v for p,v in pins.items()),'whole inputs unchanged')
        need(all(dict(fact(p),mode=Path(p).stat().st_mode&0o777)==v for p,v in artifacts.items()),'whole artifacts unchanged')
        need(all(str(Path(p).resolve(strict=True))==v for p,v in aliases.items()),'whole aliases unchanged')
        need(all(os.path.lexists(p)==v for p,v in presence.items()),'loader configuration presence unchanged')
        need(all(Path(p).is_symlink()and os.readlink(p)==v for p,v in r['namespace_aliases'].items()),'sealed namespace aliases unchanged')
    def run(name,argv,profile='metadata',expected=0,env=None,record=False):
        closure();need(sorted(os.sched_getaffinity(0))==[args.cpu],'same reserved CPU before every child')
        need(len(r['commands'])<len(SCHEDULE)and(name,profile)==SCHEDULE[len(r['commands'])],
             'source-owned complete fixed command schedule')
        subject=next((c for c in r['cases']if c['label']==name),None)
        need(expected==(subject['expected_exit']if subject else 0)and record is bool(subject),
             'actual source-derived exit and record expectation, no skipped negative')
        row=dict(name=name,argv=list(map(str,argv)),environment=dict(ENV if env is None else env),
            profile=profile,bounds=BOUNDS[profile],capture_limit=16<<20,expected_exit=expected);r['commands'].append(row)
        try:
            out,err=(program_invoke if subject else invoke)(row,private,args.cpu,record=record)
            need(type(row['exit'])is int and row['exit']==expected and not row['timed_out'],'actual bounded child '+name)
            return row,out,err
        finally:
            for capture in row.get('captures',{}).values():
                try:need(fact(binary(private/capture['file']))=={k:capture[k]for k in('bytes','sha256')},'whole actual capture')
                except BaseException as error:r['final_errors'].append('capture '+name+': '+repr(error))
            try:
                path=private/(name+'.json')
                if path.exists():need(json.loads(binary(path).read_bytes())==row,'whole retained actual command row')
            except BaseException as error:r['final_errors'].append('command '+name+': '+repr(error))
    def build_run(name,argv,profile='metadata',env=None,expected=0):
        before_loop_default(name,argv,builder,pin,aliases,run,r)
        return run(name,argv,profile=profile,expected=expected,env=env)
    builder=Build(r,private,pin,binary,build_run,('region.rs',),scalar_span=True,linked_epoch=True,mov_guard=True)
    try:
        r['source']=source();need(r['source']['revision']==args.expect_revision,'exact clean tracked source')
        imported_sources(pin);git=pin(shutil.which('git',path=ENV['PATH']))
        _,names,err=run('tracked-input-list',[git,'-C',ROOT,'ls-files','-z','tools/page-entry','evaluation/inprocess'])
        need(names and not err,'actual complete tracked source roster')
        for name in names.split(b'\0'):
            if name and not os.fsdecode(name).startswith('evaluation/inprocess/results/'):pin(ROOT/os.fsdecode(name))
        for name in('/etc/ld.so.cache','/etc/ld.so.preload'):
            presence[name]=os.path.lexists(name)
            if presence[name]:pin(name)
        need(not presence['/etc/ld.so.preload'],'no global preload')
        products=builder.prepare();r['archive']=fact(products['archive'])
        legacy(args,r,pin,binary,products['archive'])
        r['prerequisite_stage']='loop_native'
        proof,cases,support=authenticate(args.loop_native_receipt,args.loop_native_receipt_sha256,r,pin,binary,products['archive'])
        r['loop_native_prerequisite']=proof;r['prerequisite_stage']=None
        cohort(builder,products,private,pin,binary,aliases,run,r,cases,support)
        need(tuple((c['name'],c['profile'])for c in r['commands'])==SCHEDULE,'entire126 commands actually completed')
        r['status']='observed_focal_unqualified'
    except BaseException as error:r['error']=type(error).__name__+': '+str(error)
    finally:
        r['final_errors'].extend(builder.finish())
        try:
            imported_sources(pin);closure();need(source()==r['source'],'whole tracked source unchanged')
            need(sorted(os.sched_getaffinity(0))==[args.cpu],'same reserved CPU at closure')
            r['source_unchanged']=r['inputs_unchanged']=True
        except BaseException as error:r['final_errors'].append(type(error).__name__+': '+str(error))
        r['cleanup_complete']=all(c.get('reaped')is True and c.get('cleanup_errors')==[]and
            type(c.get('descriptors'))is list and all(d.get('closed')is True for d in c['descriptors'])for c in r['commands'])
        if r['error']or r['final_errors']or not r['source_unchanged']or not r['cleanup_complete']:r['status']='failed'
        r.update(inputs=pins,artifacts=artifacts,aliases=aliases,presence=presence)
        save(private/'receipt.json',r)
    print(json.dumps(dict(status=r['status'],receipt=str((private/'receipt.json').relative_to(ROOT)),
        focal_only=True,qualification_credit=False,performance_credit=False)))
    return int(r['status']!='observed_focal_unqualified')


if __name__=='__main__':raise SystemExit(main())
