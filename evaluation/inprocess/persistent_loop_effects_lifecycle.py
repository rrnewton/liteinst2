#!/usr/bin/env python3
"""Fresh complete mixed-policy lifecycle: four native references and eight actual owner comparisons."""
import argparse
import csv
import io
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
from page_selected_process import invoke
from page_selected_effect_ls import program_invoke
from persistent_dynamic import BOUNDS, digest, imported_sources, seed_prerequisite
from persistent_loop_effects_archive import Build
from persistent_loop_effects_build_default import before_loop_effects_default
from persistent_loop_lifecycle_native_build import (FIXTURE, compile_subject, reader_support,
    observed_layout, native_namespace, native_preparation)

from persistent_loop_effects_lifecycle_helpers import (ROOT,PROFILE,NATIVE_ORDER,ORDER,SCHEDULE,LANES,
    native_summary,application_controls,providers,builds,gated,case_argv)


def public_result(r,receipt,argv):
    rows=[]
    for group in ('native_cases','cases'):
        for c in r[group]:
            rows.append(dict(lane=c.get('build_lane','native'),case=c['mode'],placement=c['placement'],
                status=c['status'],expected_exit=0,exit=c.get('exit'),
                elapsed_ns_validation_only=c.get('whole_process_ns'),native=c.get('native'),
                owner=c.get('owner_summary'),pair=c.get('pair')))
    value=dict(schema=1,profile=PROFILE,status=r['status'],revision=r['revision'],cpu=r['cpu'],
        source_sha256=digest(r['source']),hardware=r['hardware'],receipt=fact(receipt),
        reproducible_argv=argv,commands=len(r['commands']),bounds=r['bounds'],
        source_unchanged=r['source_unchanged'],inputs_unchanged=r['inputs_unchanged'],
        cleanup_complete=r['cleanup_complete'],coverage=r.get('coverage',{}),cases=rows,
        control_populations=r.get('control_populations'),elf_controls=r.get('elf_control_count'),
        qualification_credit=False,performance_credit=False,whole_profile_qualified=False,
        scope='finite lifecycle/full-state observations only; all elapsed values are validation cost')
    text=json.dumps(value,sort_keys=True,indent=2)+'\n'
    need('/home/'not in text and str(ROOT)not in text and len(text.encode())<32<<10,
         'bounded public lifecycle projection without host paths or raw logs')
    out=io.StringIO();writer=csv.writer(out,lineterminator='\n')
    writer.writerow(('lane','case','placement','status','exit','elapsed_ns_validation_only',
        'native_instructions','native_frames','generated_entries','generated_completed','ordinary_store_replays'))
    for c in rows:
        n=c['native']or{};o=c['owner']or{}
        writer.writerow((c['lane'],c['case'],c['placement'],c['status'],c['exit'],c['elapsed_ns_validation_only'],
            n.get('native_instructions'),n.get('native_frames'),o.get('generated_entries'),
            o.get('generated_completed'),o.get('ordinary_store_replays')))
    return text,out.getvalue()


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision',required=True);ap.add_argument('--cpu',type=int,required=True)
    ap.add_argument('--output',type=Path,required=True)
    for n in('direct','block','fused','loop-component','effects-component'):
        ap.add_argument('--'+n+'-receipt',type=Path,required=True)
        ap.add_argument('--'+n+'-receipt-sha256',required=True)
    args=ap.parse_args()
    need(re.fullmatch('[0-9a-f]{40}',args.expect_revision) and not sys.flags.optimize and
         sorted(os.sched_getaffinity(0)) == [args.cpu], 'exact revision, assertions and one externally reserved CPU')
    need(len(SCHEDULE)==116 and len({n for n,_ in SCHEDULE})==116 and len(NATIVE_ORDER)==4 and len(ORDER)==8,
         'complete fixed lifecycle build schedule and all four native/eight gated subjects')
    os.chdir(ROOT);private=args.output.absolute()
    need(private.parent==ROOT/'target/evaluation/inprocess' and not private.exists(),'fresh direct-child lifecycle output')
    private.mkdir(parents=True,exist_ok=False)
    r=dict(schema=1,profile=PROFILE,status='failed',revision=args.expect_revision,cpu=args.cpu,
        hardware=hardware(args.cpu),source=None,source_unchanged=False,inputs_unchanged=False,
        cleanup_complete=False,commands=[],bounds=dict(BOUNDS),error=None,final_errors=[],
        whole_profile_qualified=False,qualification_credit=False,performance_credit=False,namespace_aliases={},lanes={},coverage={},
        prerequisite_inputs={n:dict(path=str(getattr(args,n+'_receipt').absolute()),sha256=getattr(args,n+'_receipt_sha256'))
            for n in('direct','block','fused','loop_component','effects_component')},
        seed_prerequisite=dict(planned=1,status='unexecuted',launched=False,expected_exit=0,bounds=BOUNDS['seed'],
            completed_applications=0,owner_subjects=0,performance_credit=False),
        native_cases=[dict(label='subject-native-'+str(c)+'-'+str(p),lane=0,mode=c,placement=p,control=0,cpu=args.cpu,
                    expected_exit=0,status='unexecuted',launched=False)for c,p in NATIVE_ORDER],
        cases=[dict(label='subject-'+l+'-'+str(c)+'-'+str(p),build_lane=l,lane=1,mode=c,placement=p,control=0,cpu=args.cpu,
                    expected_exit=0,status='unexecuted',launched=False)for l,c,p in ORDER])
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
        need(all(Path(p).is_symlink()and os.readlink(p)==v for p,v in r['namespace_aliases'].items()),
             'whole actual sealed dependency aliases unchanged')
    def run(name,argv,profile='metadata',expected=0,env=None,record=False):
        closure();need(sorted(os.sched_getaffinity(0))==[args.cpu],'same reserved CPU before every child')
        subject=next((c for c in r['cases']if c['label']==name),None)
        need(type(expected)is int and expected==0 and record is bool(subject)and len(r['commands'])<len(SCHEDULE)and
             (name,profile)==SCHEDULE[len(r['commands'])],'fixed complete lifecycle schedule and original expected-zero bounds')
        row=dict(name=name,argv=list(map(str,argv)),environment=dict(ENV if env is None else env),
            profile=profile,bounds=BOUNDS[profile],capture_limit=16<<20,expected_exit=0);r['commands'].append(row)
        try:
            out,err=(program_invoke if name.startswith('subject-')else invoke)(row,private,args.cpu,record=record)
            need(row['exit']==0 and not row['timed_out'],'actual expected-zero child '+name)
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
        before_loop_effects_default(name,argv,builder,pin,aliases,run,r)
        return run(name,argv,profile=profile,expected=expected,env=env)
    builder=Build(r,private,pin,binary,build_run,('region.rs',),scalar_span=True,linked_epoch=True,mov_guard=True)
    try:
        r['source']=source();need(r['source']['revision']==args.expect_revision,'exact clean tracked source')
        imported_sources(pin);git=pin(shutil.which('git',path=ENV['PATH']))
        _,names,err=run('tracked-input-list',[git,'-C',ROOT,'ls-files','-z','tools/page-entry','evaluation/inprocess'])
        need(names and not err,'actual nonempty tracked source roster from repository')
        for name in names.split(b'\0'):
            if name and not os.fsdecode(name).startswith('evaluation/inprocess/results/'):pin(ROOT/os.fsdecode(name))
        for name in('/etc/ld.so.cache','/etc/ld.so.preload'):
            presence[name]=os.path.lexists(name)
            if presence[name]:pin(name)
        need(not presence['/etc/ld.so.preload'],'no global preload')
        products=builder.prepare();r['archive']=fact(products['archive'])
        # Imports of mandatory prospective providers occur inside this retained attempt.
        from persistent_loop_effects_owner_prerequisite import legacy
        from loop_effects13_component import prerequisite as effects_component_prerequisite
        legacy(args,r,pin,binary,products['archive'])
        r['prerequisite_stage']='effects_component'
        r['effects_component_prerequisite']=effects_component_prerequisite(args.effects_component_receipt,
            args.effects_component_receipt_sha256,r,pin,binary,products['archive'])
        r['prerequisite_stage']=None
        original=compile_subject(builder,private,pin,binary,aliases,run,r)
        reader,controls,native_policy=reader_support(builder,private,pin,binary,run,r)
        layout=observed_layout(builder,original,private,pin,binary,run,r)
        owner_reader,reports,counts=providers(pin,controls);r['control_populations']=counts
        image=reader.elf(original.read_bytes(),native_policy,layout,r['application_build']['headers'])
        r['elf_controls']=controls.elf_controls(reader,original.read_bytes(),native_policy,layout,r['application_build']['headers'])
        need(r['elf_controls']['status']=='passed' and r['elf_controls']['count']==counts['elf'],'all actual ELF/source controls')
        r['elf_control_count']=counts['elf']
        native_namespace(original,r['application_build'],pin,r)
        seed=seed_prerequisite(builder,private,pin,binary,run,r)
        seed_row=r['commands'][-1];need(seed_row['name']=='seed-prerequisite','actual separate seed row')
        seed=(*seed,(private/seed_row['captures']['stdout']['file']).read_bytes())
        launcher=pin(FIXTURE/'launch.py');imported_sources(pin);natives={}
        for case in r['native_cases']:
            mode,placement,label=case['mode'],case['placement'],case['label'];case['status']='failed'
            directory=private/label;directory.mkdir();errors=[]
            try:
                row,out,err=run(label,case_argv(builder,original,case,directory,[original.parent],None,pin),profile='program')
                need(not err,'whole native reference stderr is empty')
                native_preparation(directory/'preparation.json',row,original,mode,placement,args.cpu,binary)
                parsed=reader.read(out,0,mode,placement,row['exit'],image,row['pid'],args.cpu,seed)
                case['native']=native_summary(parsed,mode,placement);natives[mode,placement]=parsed
                case['controls']=controls.controls(reader,out,0,mode,placement,row['exit'],image,row['pid'],args.cpu,seed)
                metadata=controls.metadata_controls(reader,image)
                application_controls(case['controls'],metadata,counts['native'][mode],parsed['raw_sha256'],counts['metadata'],lane=0)
                case['control_counts']=dict(native=counts['native'][mode],layout=counts['metadata'])
            except Exception as error:errors.append(type(error).__name__+': '+str(error))
            last=r['commands'][-1]if r['commands']else{}
            if last.get('name')==label:
                case.update(exit=last.get('exit'),whole_process_ns=last.get('duration_ns'),timed_out=last.get('timed_out'),
                    launched=type(last.get('pid'))is int,
                    captures={k:{j:v[j]for j in('bytes','sha256')}for k,v in last.get('captures',{}).items()})
            if errors:case['errors']=errors
            else:case['status']='observed_native_reference'
            need(last.get('name')==label and last.get('reaped')is True and last.get('cleanup_errors')==[] and
                 type(last.get('descriptors'))is list and all(d.get('closed')is True for d in last['descriptors']),
                 'complete current-subject cleanup before advancing, including failed expected-zero subjects')
        need(all(c['status']=='observed_native_reference'for c in r['native_cases'])and len(natives)==4,
             'all four actual native references and controls before any gated build')
        support=dict(reader=reader,controls=controls,image=image,seed_reference=seed,layout=layout,
            native_policy=native_policy,original=original,headers=r['application_build']['headers'],application_build=r['application_build'])
        subjects=builds(builder,products,private,pin,binary,aliases,run,r,support)
        gated(builder,private,pin,binary,run,r,support,natives,subjects,owner_reader,reports,counts)
        need(tuple((c['name'],c['profile'])for c in r['commands'])==SCHEDULE,'all116 exact commands completed')
        r['status']='observed_lifecycle_unqualified'
    except BaseException as error:r['error']=type(error).__name__+': '+str(error)
    finally:
        r['final_errors'].extend(builder.finish())
        try:
            imported_sources(pin);closure();need(source()==r['source'],'whole source unchanged')
            need(sorted(os.sched_getaffinity(0))==[args.cpu],'same reserved CPU at closure')
            r['source_unchanged']=r['inputs_unchanged']=True
        except BaseException as error:r['final_errors'].append(type(error).__name__+': '+str(error))
        r['cleanup_complete']=all(c.get('reaped')is True and c.get('cleanup_errors')==[] and
            type(c.get('descriptors'))is list and all(d.get('closed')is True for d in c['descriptors'])for c in r['commands'])
        if r['error']or r['final_errors']or not r['source_unchanged']or not r['cleanup_complete']:r['status']='failed'
        r.update(inputs=pins,artifacts=artifacts,aliases=aliases,presence=presence)
        save(private/'receipt.json',r)
    argv=['python3','evaluation/inprocess/persistent_loop_effects_lifecycle.py','--expect-revision',args.expect_revision,
          '--cpu',str(args.cpu),'--output',str(private.relative_to(ROOT))]
    for n in('direct','block','fused','loop_component','effects_component'):
        path=getattr(args,n+'_receipt').absolute()
        need(path.is_relative_to(ROOT),'portable repository-relative prerequisite')
        argv+=['--'+n.replace('_','-')+'-receipt',str(path.relative_to(ROOT)),
               '--'+n.replace('_','-')+'-receipt-sha256',getattr(args,n+'_receipt_sha256')]
    text,csv_text=public_result(r,private/'receipt.json',argv)
    (private/'public.json').write_text(text);(private/'public.csv').write_text(csv_text)
    print(json.dumps(dict(status=r['status'],receipt=str((private/'receipt.json').relative_to(ROOT)))))
    return int(r['status']!='observed_lifecycle_unqualified')


if __name__=='__main__':raise SystemExit(main())
