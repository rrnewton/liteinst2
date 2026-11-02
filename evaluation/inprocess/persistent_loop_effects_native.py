#!/usr/bin/env python3
"""Same paired-v2 native corpus with the explicit effects archive; no owner credit."""
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
from persistent_loop_native_build import (FIXTURE, compile_subject, reader_support,
    observed_layout, native_namespace, native_preparation)

ROOT = Path(__file__).resolve().parents[2]
PROFILE = 'persistent-loop-effects-native-v1'
ORDER = tuple((case, placement) for case in range(7) for placement in range(4))
INSTRUCTIONS = (106, 25, 35, 13, 13, 1, 2)
FRAMES = (107, 26, 36, 14, 14, 3, 4)
CONTROL_COUNTS = (1431, 689, 782, 579, 579, 478, 487)
SCHEDULE = (
    ('tracked-input-list', 'metadata'),
    *((('resolve-'+name), 'metadata') for name in ('cargo','rustc','cc1','collect2','as','ld')),
    *((('version-'+name), 'metadata') for name in ('cc','cargo','rustc','python')),
    ('cargo-metadata','metadata'), ('default-headers-0','metadata'), ('default-headers-1','metadata'),
    ('selected-build','build'), ('archive-text-exports','inspect'), ('bridge-undefined','inspect'),
    ('bridge-elf','inspect'), ('generic-observer-headers','metadata'), ('generic-observer-link','metadata'),
    ('app-interpreter-headers','metadata'), ('app-interpreter-link','release_build'),
    ('app-interpreter-undefined','inspect'), ('app-interpreter-symbols','inspect'),
    ('app-headers','metadata'), ('app-link','release_build'), ('app-undefined','inspect'),
    ('app-elf','inspect'), ('app-objdump-version','metadata'), ('app-symbols','inspect'),
    *((('app-body-'+name), 'inspect') for name in
      ('main','lp_inputs','lp_model_init','lp_advance','copy','same','ua_data_pattern','ua_stack_pattern')),
    ('app-copy-headers','finite'), ('app-pure-preprocess','finite'), ('copy-pure-preprocess','finite'),
    ('app-copy-link','finite'), ('app-copy-symbols','finite'), ('app-copy-body','finite'),
    ('app-copy-libraries','finite'), ('app-copy-run','finite'),
    ('policy-headers','metadata'), ('policy-link','release_build'),
    ('layout-gdb-version','metadata'), ('native-layout','inspect'),
    ('seed-headers','metadata'), ('seed-link','release_build'), ('seed-libraries','inspect'),
    ('seed-prerequisite','seed'),
    *((('subject-native-'+str(case)+'-'+str(placement)), 'program') for case, placement in ORDER))


def summary(parsed, case, placement):
    """Small descriptive result; the actual raw frames remain the authority."""
    need(parsed['lane'] == 0 and parsed['mode'] == case and parsed['placement'] == placement and
         parsed['native_reference_complete'] is True and parsed['application_complete'] is True and
         parsed['actual_fault'] is (case >= 5) and parsed['native_instructions'] == INSTRUCTIONS[case] and
         parsed['native_frames'] == len(parsed['frames']) == FRAMES[case] and
         all(parsed[k] is False for k in ('owner_validated','mixed_policy_validated',
                                         'qualification_credit','performance_credit')),
         'complete native observations, including genuine stopped read faults, without owner credit')
    return dict(case=case, placement=placement, raw_sha256=parsed['raw_sha256'],
        native_instructions=parsed['native_instructions'], native_frames=parsed['native_frames'],
        actual_fault=parsed['actual_fault'], native_reference_complete=True, application_complete=True,
        owner_validated=False, mixed_policy_validated=False, qualification_credit=False, performance_credit=False)


def control_summary(value, count, raw_sha256):
    names = value['refusals']; metadata = value['layout_controls']
    need(value['status'] == 'passed' and value['scope'] == 'supplied_native_reference_corruptions_only' and
         value['count'] == count and type(names) is list and len(names) == len(set(names)) == count and
         all(type(name) is str and name for name in names) and value['raw_sha256'] == raw_sha256 and
         value['layout_count'] == len(metadata) == len(set(metadata)) == 20 and
         all(type(name) is str and name for name in metadata) and value['native_operations'] == 0 and
         value['owner_pair_unavailable'] is True and value['owner_validated'] is False and
         value['mixed_policy_validated'] is False and value['qualification_credit'] is False and
         value['performance_credit'] is False, 'all original native and layout corruption controls')
    return dict(native=count, layout=20)


def public_result(r, receipt, argv):
    rows = [dict(case=c['mode'], placement=c['placement'], status=c['status'],
        expected_exit=0, exit=c.get('exit'), elapsed_ns_validation_only=c.get('whole_process_ns'),
        native=c.get('native'), controls=c.get('control_counts')) for c in r['cases']]
    value = dict(schema=1, profile=PROFILE, status=r['status'], revision=r['revision'], cpu=r['cpu'],
        source_sha256=digest(r['source']), hardware=r['hardware'], receipt=fact(receipt),
        reproducible_argv=argv, commands=len(r['commands']), bounds=r['bounds'],
        source_unchanged=r['source_unchanged'], inputs_unchanged=r['inputs_unchanged'],
        cleanup_complete=r['cleanup_complete'], cases=rows,
        elf_controls=r.get('elf_control_count'), qualification_credit=False, performance_credit=False,
        owner_validated=False, mixed_policy_validated=False,
        scope='28 actual native references only; elapsed values are validation cost; fault cases retain original SIGSEGV')
    text=json.dumps(value,sort_keys=True,indent=2)+'\n'
    need('/home/' not in text and str(ROOT) not in text and len(text.encode()) < 32 << 10,
         'bounded public projection without host paths or raw logs')
    output=io.StringIO();writer=csv.writer(output,lineterminator='\n')
    writer.writerow(('case','placement','status','exit','elapsed_ns_validation_only',
                     'native_instructions','native_frames','actual_fault','native_controls','layout_controls'))
    for row in rows:
        native=row['native'] or {}; controls=row['controls'] or {}
        writer.writerow((row['case'],row['placement'],row['status'],row['exit'],row['elapsed_ns_validation_only'],
            native.get('native_instructions'),native.get('native_frames'),native.get('actual_fault'),
            controls.get('native'),controls.get('layout')))
    return text,output.getvalue()


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision',required=True);ap.add_argument('--cpu',type=int,required=True)
    ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    need(re.fullmatch('[0-9a-f]{40}',args.expect_revision) and not sys.flags.optimize and
         sorted(os.sched_getaffinity(0)) == [args.cpu], 'exact revision, assertions and one externally reserved CPU')
    need(len(SCHEDULE)==82 and len({n for n,_ in SCHEDULE})==82 and len(ORDER)==28,
         'one fixed build/seed schedule and all seven-by-four native cases')
    os.chdir(ROOT);private=args.output.absolute()
    need(private.parent==ROOT/'target/evaluation/inprocess' and not private.exists(),'fresh direct-child native output')
    private.mkdir(parents=True,exist_ok=False)
    r=dict(schema=1,profile=PROFILE,status='failed',revision=args.expect_revision,cpu=args.cpu,
        hardware=hardware(args.cpu),source=None,source_unchanged=False,inputs_unchanged=False,
        cleanup_complete=False,commands=[],bounds=dict(BOUNDS),error=None,final_errors=[],
        owner_validated=False,mixed_policy_validated=False,qualification_credit=False,performance_credit=False,
        seed_prerequisite=dict(planned=1,status='unexecuted',launched=False,expected_exit=0,bounds=BOUNDS['seed'],
            completed_applications=0,owner_subjects=0,performance_credit=False),
        cases=[dict(label='subject-native-'+str(c)+'-'+str(p),lane=0,mode=c,placement=p,
                    expected_exit=0,status='unexecuted',launched=False)for c,p in ORDER])
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
    def run(name,argv,profile='metadata',expected=0,env=None,record=False):
        closure();need(sorted(os.sched_getaffinity(0))==[args.cpu],'same reserved CPU before every child')
        need(expected==0 and record is False and len(r['commands'])<len(SCHEDULE) and
             (name,profile)==SCHEDULE[len(r['commands'])],'fixed complete native schedule and original expected-zero bounds')
        row=dict(name=name,argv=list(map(str,argv)),environment=dict(ENV if env is None else env),
            profile=profile,bounds=BOUNDS[profile],capture_limit=16<<20,expected_exit=0);r['commands'].append(row)
        try:
            out,err=(program_invoke if name.startswith('subject-')else invoke)(row,private,args.cpu,record=False)
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
        original=compile_subject(builder,private,pin,binary,aliases,run,r)
        reader,controls,native_policy=reader_support(builder,private,pin,binary,run,r)
        layout=observed_layout(builder,original,private,pin,binary,run,r)
        image=reader.elf(original.read_bytes(),native_policy,layout,r['application_build']['headers'])
        r['elf_controls']=controls.elf_controls(reader,original.read_bytes(),native_policy,layout,r['application_build']['headers'])
        need(r['elf_controls']['status']=='passed' and r['elf_controls']['count']==29,'all actual ELF/source controls')
        r['elf_control_count']=29
        native_namespace(original,r['application_build'],pin,r)
        seed=seed_prerequisite(builder,private,pin,binary,run,r)
        seed_row=r['commands'][-1];need(seed_row['name']=='seed-prerequisite','actual separate seed row')
        seed=(*seed,(private/seed_row['captures']['stdout']['file']).read_bytes())
        launcher=pin(FIXTURE/'launch.py');imported_sources(pin)
        for case in r['cases']:
            mode,placement,label=case['mode'],case['placement'],case['label'];case['status']='failed'
            directory=private/label;directory.mkdir();errors=[]
            try:
                row,out,err=run(label,[builder.tools['python'],'-B',launcher,'--root',ROOT,'--role','native','--case',mode,
                    '--placement',placement,'--control','0','--original',original,'--library-root',original.parent,
                    '--preparation',directory/'preparation.json'],profile='program')
                need(not err,'whole native reference stderr is empty')
                native_preparation(directory/'preparation.json',row,original,mode,placement,args.cpu,binary)
                parsed=reader.read(out,0,mode,placement,row['exit'],image,row['pid'],args.cpu,seed)
                case['native']=summary(parsed,mode,placement)
                case['controls']=controls.controls(reader,out,0,mode,placement,row['exit'],image,row['pid'],args.cpu,seed)
                case['control_counts']=control_summary(case['controls'],CONTROL_COUNTS[mode],parsed['raw_sha256'])
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
        need(tuple((c['name'],c['profile'])for c in r['commands'])==SCHEDULE and
             all(c['status']=='observed_native_reference'for c in r['cases']),
             'all28 complete references and all controls; every failed case stays failed')
        r['status']='observed_native_references'
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
    argv=['python3','evaluation/inprocess/persistent_loop_effects_native.py','--expect-revision',args.expect_revision,
          '--cpu',str(args.cpu),'--output',str(private.relative_to(ROOT))]
    text,csv_text=public_result(r,private/'receipt.json',argv)
    (private/'public.json').write_text(text);(private/'public.csv').write_text(csv_text)
    print(json.dumps(dict(status=r['status'],receipt=str((private/'receipt.json').relative_to(ROOT)))))
    return int(r['status']!='observed_native_references')


if __name__=='__main__':raise SystemExit(main())
