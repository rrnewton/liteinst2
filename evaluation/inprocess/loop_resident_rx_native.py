#!/usr/bin/env python3
"""Finite DIRECT44 native/release/DIFF plus one restored causal RX subject.

Original DIRECT41 and all qualification cohorts remain separate requirements.
The observer proves actual per-member permission calls, not an old NX capture.
"""
import argparse
import json
import os
from pathlib import Path
import sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
MODULE_PATHS=dict(build='loop_resident_rx_build.py',app_build='direct_frontier_loop_build.py',
    app_helpers='direct_frontier_loop_helpers.py',observer='loop_resident_rx_fixture.py',
    terminal='loop_resident_rx_reports.py',fused='persistent_fused_counter_terminal.py',
    effects='persistent_loop_effects_performance_reports.py',certificate='loop_ro_certificate_reports.py')
LANES=(('release','release',0,0),('differential','differential',0,0),('causal','differential',1,125))
APP_SCHEDULE=(('app-interpreter-headers','metadata'),('app-interpreter-link','release_build'),
    ('app-interpreter-undefined','inspect'),('app-interpreter-symbols','inspect'),
    ('app-headers','metadata'),('app-link','release_build'),('app-undefined','inspect'),
    ('app-elf','inspect'),('app-objdump-version','metadata'),('app-symbols','inspect'))+tuple(
        ('app-body-'+name,'inspect') for name in ('main','collect','copy','same','ua_data_pattern','ua_stack_pattern'))+tuple(
        (name,'finite') for name in ('app-copy-headers','app-pure-preprocess','copy-pure-preprocess',
            'app-copy-link','app-copy-symbols','app-copy-body','app-copy-libraries','app-copy-run'))
SCHEDULE=APP_SCHEDULE+(('policy-headers','metadata'),('policy-link','release_build'),
    ('seed-headers','metadata'),('seed-link','release_build'),('seed-libraries','inspect'),('seed-prerequisite','seed'))+tuple(
    (lane+'-'+name,profile) for lane,_,_,_ in LANES for name,profile in (
        ('build','release_build'),('headers','metadata'),('undefined','inspect'),('symbols','inspect'),('carrier','program')))+tuple(
    ('subject-'+lane,'program') for lane in ('native','release','differential','causal'))



def execute(a, *, context=None, cache8=False):
    """Explicit compiler/reader context; original source authority remains natural."""
    if context is not None and (type(context)is not dict or set(context)!=
            {'root','selected','reader_root','modules'}):
        raise ValueError('complete explicit compiler/reader context')
    if type(cache8)is not bool:raise ValueError('explicit additive cache8 selector')
    module_paths=MODULE_PATHS if not cache8 else dict(MODULE_PATHS,
        cache8='loop_cache8_reports.py',row='loop_ro_oracle_reports.py')
    root=ROOT if context is None else Path(context['root']).resolve(strict=True)
    reader_root=ROOT if context is None else Path(context['reader_root']).resolve(strict=True)
    selected=root/'tools/page-entry/selected' if context is None else Path(context['selected']).resolve(strict=True)
    # Old archive/source/tool authorities are always imported from the real tree.
    # Private changed modules are supplied explicitly, never silently substituted.
    previous_path=list(sys.path)
    try:
        sys.path[:0]=[str(root/'evaluation/inprocess'),str(root/'tools/page-entry')]
        from checks import source
        from run import hardware
        from page_selected import ENV,fact,need,save
        from page_selected_process import invoke
        from page_selected_effect_ls import program_invoke
        from persistent_dynamic import BOUNDS,imported_sources,seed_prerequisite,named,H,load
        from loop_ro_current_archive import current_archive
        if context is None:
            import importlib
            modules={key:importlib.import_module(Path(name).stem) for key,name in module_paths.items()}
        else:modules=context['modules']
    finally:sys.path[:]=previous_path
    need(type(modules)is dict and set(modules)==set(module_paths), 'complete explicit helper modules')
    for key,name in module_paths.items():
        need(Path(modules[key].__file__).resolve(strict=True)==reader_root/'evaluation/inprocess'/name,
             'canonical explicit helper module '+key)
    need('persistent_terminal_extent' in sys.modules and
         Path(sys.modules['persistent_terminal_extent'].__file__).resolve(strict=True)==
         reader_root/'evaluation/inprocess/persistent_terminal_extent.py',
         'canonical single shared original NX extent helper')
    for name in ('checks','run','page_selected','page_selected_process','page_selected_effect_ls',
                 'persistent_dynamic','loop_ro_current_archive','persistent_loop_effects_native_prerequisite'):
        need(name in sys.modules and Path(sys.modules[name].__file__).resolve(strict=True)==
             root/'evaluation/inprocess'/(name+'.py'), 'canonical unchanged authority '+name)
    build_rx=modules['build'].build_rx;compile_subject=modules['app_build'].compile_subject
    reader_support=modules['app_helpers'].reader_support
    prepare_inputs=modules['app_helpers'].prepare_inputs;preparation=modules['app_helpers'].preparation
    observer=modules['observer'];reports=modules['terminal'].configured(
        modules['fused'],modules['effects'],modules['certificate'])
    fixture=selected/('tests/loop_cache8_app' if cache8 else 'tests/persistent_direct_frontier_app')
    reference='cache8-abc169' if cache8 else 'direct44'
    if cache8:
        reports=modules['cache8'].configured(modules['row'].row,modules['terminal'],
            modules['certificate'],modules['terminal'].effects)
    need(not sys.flags.optimize and len(os.sched_getaffinity(0))==1,'assertions and reserved singleton')
    cpu=next(iter(os.sched_getaffinity(0)));private=Path(a.output).absolute()
    need(private.parent==root/'target/evaluation/inprocess','private output under the original root')
    private.mkdir(exist_ok=False)
    r=dict(schema=1,profile='loop-resident-rx-direct44-v1',status='failed',revision=a.expect_revision,
        source=None,source_unchanged=False,inputs_unchanged=False,cleanup_complete=False,
        cpu=cpu,hardware=hardware(cpu),bounds=BOUNDS,commands=[],cases=[],namespace_aliases={},
        error=None,final_errors=[],qualification_credit=False,performance_credit=False,
        whole_profile_qualified=False,compiled_source_context=str(selected),
        source_context_is_natural=selected==root/'tools/page-entry/selected' and reader_root==root,
        reader_source_context=str(reader_root),
        scope='complete44-step native model and application state; typed RX observer/32 restored controls; no old owner capture or full19 credit',
        seed_prerequisite=dict(planned=1,status='unexecuted',launched=False,expected_exit=0,
            bounds=BOUNDS['seed'],owner_subjects=0,completed_applications=0,performance_credit=False))
    if cache8:
        r['profile']='loop-cache8-abc169-v1'
        r['scope']='additive ABC169 full native state and real four-epoch/24-refusal wire; old49 remains separate'
    pins={};artifacts={};aliases={};presence={}
    def pin(path):
        alias=Path(os.path.abspath(path));p=alias.resolve(strict=True);v=fact(p)
        need(str(alias)not in aliases or aliases[str(alias)]==str(p),'stable actual input alias')
        need(str(p)not in pins or pins[str(p)]==v,'stable whole actual input')
        pins[str(p)]=v;aliases[str(alias)]=str(p);return p
    def binary(path):
        p=Path(path).resolve(strict=True);v=dict(fact(p),mode=p.stat().st_mode&0o777)
        need(str(p)not in artifacts or artifacts[str(p)]==v,'stable actual artifact')
        artifacts[str(p)]=v;return p
    def closure():
        need(all(fact(p)==v for p,v in pins.items()),'whole inputs unchanged')
        need(all(dict(fact(p),mode=Path(p).stat().st_mode&0o777)==v for p,v in artifacts.items()),
             'whole outputs and modes unchanged')
        need(all(str(Path(p).resolve(strict=True))==v for p,v in aliases.items()),'all input aliases unchanged')
        need(all(os.path.lexists(p)==v for p,v in presence.items()),'loader presence unchanged')
        need(all(Path(p).is_symlink() and os.readlink(p)==v for p,v in r['namespace_aliases'].items()),
             'all actual sealed namespace aliases unchanged')
    def run(name,argv,profile='metadata',expected=0,env=None,record=False):
        closure();need(not any(c['name']==name for c in r['commands']),'unique actual command')
        need(len(r['commands'])<len(SCHEDULE) and SCHEDULE[len(r['commands'])]==(name,profile),
             'one exact fixed49 command/profile schedule')
        row=dict(name=name,argv=list(map(str,argv)),environment=dict(ENV if env is None else env),
            profile=profile,bounds=BOUNDS[profile],capture_limit=16<<20,expected_exit=expected)
        r['commands'].append(row)
        try:
            out,err=(program_invoke if name.startswith('subject-') else invoke)(row,private,cpu,record=record)
            need(row['exit']==expected,'actual required command exit: '+name);return row,out,err
        finally:
            for capture in row.get('captures',{}).values():
                try:need(fact(binary(private/capture['file']))=={k:capture[k] for k in ('bytes','sha256')},'whole capture join')
                except BaseException as e:r['final_errors'].append(repr(e))
            path=private/(name+'.json')
            if path.exists():need(json.loads(binary(path).read_bytes())==row,'literal retained command record')
    def lane_run(prefix):
        def call(name,argv,profile='metadata',expected=0,env=None,record=False):
            return run(prefix+'-'+name,argv,profile=profile,expected=expected,env=env,record=record)
        return call
    try:
        r['source']=source();need(r['source']['revision']==a.expect_revision,'exact clean tracked revision')
        pin(__file__)
        for module in modules.values():pin(module.__file__)
        r['extent_controls']=modules['terminal'].extent_controls()
        for path in ('/etc/ld.so.cache','/etc/ld.so.preload'):
            presence[path]=os.path.lexists(path)
            if presence[path]:pin(path)
        need(not presence['/etc/ld.so.preload'],'no global preload')
        builder,archive,r['archive_provider']=current_archive(a.current_build,a.current_build_sha256,root,pin,binary,aliases)
        original=compile_subject(builder,private,pin,binary,aliases,run,r,reference=reference,fixture=fixture)
        reader,_,native_policy=reader_support(builder,private,pin,binary,run,r,fixture=fixture)
        image=reader.elf(original.read_bytes(),native_policy)
        seed=seed_prerequisite(builder,private,pin,binary,run,r)
        need(r['seed_prerequisite']['status']=='passed','original independent seed prerequisite')
        if cache8:observer=load('loop_cache8_actual_observe',fixture/'observe.py',pin)
        launcher=pin((selected/'tests/persistent_direct_frontier_app' if cache8 else fixture)/'launch.py')
        subject={};r['lanes']={}
        for label,mode,control,expected in LANES:
            directory=private/(label+'-build');directory.mkdir();holder=r['lanes'][label]={}
            call=lane_run(label)
            if cache8:
                bridge=build_rx(builder,archive,original,directory,pin,binary,aliases,call,holder,mode,
                    cache8=True,cache8_observe=control,selected=selected,root=root)
            else:
                bridge=build_rx(builder,archive,original,directory,pin,binary,aliases,call,holder,mode,
                            control=control,selected=selected,root=root)
            inputs=prepare_inputs(original,bridge,builder,directory,pin,binary,call,holder,r['application_build'])
            subject[label]=(holder,bridge,*inputs)
        imported_sources(pin);native=None
        for label,mode,control,expected in (('native','release',0,0),)+LANES:
            c=dict(label=label,lane='native' if label=='native' else 'gated',mode=0,control=0,
                   certificate_mode=mode,oracle_control=control,expected_exit=expected,status='failed')
            r['cases'].append(c);directory=private/('subject-'+label);directory.mkdir()
            holder,bridge,interp,roots,objects,description,images,raws,carrier=subject['release' if label=='native' else label]
            role='native' if label=='native' else 'gated'
            argv=[builder.tools['python'],'-B',launcher,'--root',root,'--role',role,'--mode','0','--control','0',
                '--original',original,'--preparation',directory/'preparation.json']
            for library_root in roots:argv+=['--library-root',library_root]
            if role=='gated':argv+=['--carrier',carrier,'--namespace',directory/'namespace','--record-fd','{record_fd}']
            try:
                row,out,err=run('subject-'+label,argv,profile='program',expected=expected,record=role=='gated')
                preparation(c,row,directory,original,roots,objects,description,carrier,private,binary,r)
                if cache8:
                    if label=='causal':
                        need(native is not None and len(out)==reader.PREFIX,'actual failed ABC169 application prefix only')
                        prefix=reader._prefix(out,0,False,image,row['pid'],cpu,seed,reference=reference)
                        need(all(prefix[k]==native[k]for k in('seed','source','stack','data','rsp','predecessor','hardware')),
                             'whole actual causal source/seed/hardware equals fresh native')
                        parsed=None;c['application_complete']=False
                    else:
                        parsed=reader.read(out,0,role=='native',row['exit'],image,row['pid'],cpu,seed,reference=reference)
                        c['application_complete']=True
                    if role=='native':
                        c['application_controls']=reader.controls(out,0,True,row['exit'],image,row['pid'],cpu,seed,reference=reference)
                        named(c['application_controls'],45,H(out))
                        need(err==b'' and parsed['header'][5]==1,'actual native169 reference and empty stderr')
                        native=parsed;c['native_instructions']=169;c['native_frames']=12
                    else:
                        need(native is not None and row['captures']['record']['bytes']==observer.WIRE+64,
                             'complete actual independent CACHE8 wire; no old capture cast')
                        record_path=binary(private/row['captures']['record']['file']);record=record_path.read_bytes()
                        st=record_path.stat()
                        need(st.st_uid==os.getuid() and observer.q(record,256,2)==(st.st_dev,st.st_ino),
                             'captured sink identity equals actual post-reap record inode')
                        backing=fact(binary(carrier))
                        need(backing==holder['subject_artifacts']['carrier'],
                             'whole independently prepared actual carrier backing identity')
                        c['carrier_backing']=backing
                        c['observer']=observer.read(record,reader,native,image,row['pid'],st.st_uid,control,row['exit'],parsed,
                            backing_size=backing['bytes'])
                        c['observer_controls']=observer.controls(record,reader,native,image,row['pid'],st.st_uid,control,row['exit'],parsed,
                            backing_size=backing['bytes'])
                        named(c['observer_controls'],109 if control else 81,H(record))
                        need(len(c['observer_controls']['phase_refusals'])==
                             len(set(c['observer_controls']['phase_refusals']))==40,
                             'all40 separate coherent phase-counter corruptions required')
                        need(len(c['observer_controls']['backing_refusals'])==
                             len(set(c['observer_controls']['backing_refusals']))==20,
                             'all20 independent actual and external backing-size corruptions required')
                        need(c['observer']['actual_refusals']==c['observer']['actual_restorations']==(24 if control else 0),
                             'every literal genuine mutation/restoration or exact positive zero')
                        if not control:c['pair']=c['observer']['native_pair']
                        c['terminal']=reports.read(err,record,control,mode)
                        c['terminal_controls']=reports.controls(err,record,control,mode)
                        need(len(c['terminal_controls']['refusals'])==len(set(c['terminal_controls']['refusals']))==10,
                             'all ten exact typed terminal/binary-join corruptions')
                else:
                    if role=='gated':need(row['captures']['record']['bytes']==0,'no old protected owner wire or capture cast')
                    if label=='causal':
                        need(native is not None and len(out)==reader.PREFIX,'actual failed application prefix only')
                        prefix=reader._prefix(out,0,False,image,row['pid'],cpu,seed,reference='direct44')
                        need(all(prefix[k]==native[k] for k in ('seed','source','stack','data','rsp','predecessor','hardware')),
                             'whole actual causal prefix source/seed/hardware equals fresh native')
                        c['observer'],ordinary=observer.observed(err,1)
                        c['observer_controls']=observer.controls(err,1)
                        c['application_complete']=False
                    else:
                        parsed=reader.read(out,0,role=='native',row['exit'],image,row['pid'],cpu,seed,reference='direct44')
                        if role=='native':
                            c['application_controls']=reader.controls(out,0,True,row['exit'],image,row['pid'],cpu,seed,reference='direct44')
                            named(c['application_controls'],40,H(out))
                            need(err==b'' and parsed['header'][5]==1,'actual native44 reference and empty stderr')
                            native=parsed;c['native_instructions']=44;c['native_frames']=12
                        else:
                            need(native is not None and parsed['header'][4:6]==(0,0),
                                 'actual same-mode gated role before common full-state comparison')
                            c['pair']=reader.application_pair(native,parsed)
                            c['observer'],ordinary=observer.observed(err,0)
                            c['observer_controls']=observer.controls(err,0)
                            c['terminal']=reports.finite(ordinary,mode)
                        c['application_complete']=True
                c.update(status='passed',exit=row['exit'],duration_ns=row['duration_ns'],captures=row['captures'])
            except Exception as e:
                c['error']=type(e).__name__+': '+str(e)
                if r['error'] is None:r['error']=c['error']
                last=r['commands'][-1]
                need(last.get('reaped')is True and last.get('cleanup_errors')==[] and
                     all(d.get('closed')is True for d in last.get('descriptors',[])),
                     'failed subject closed before the next fixed subject')
        need(len(SCHEDULE)==49 and len(r['commands'])==49 and
             len(r['cases'])==4 and all(c['status']=='passed' for c in r['cases']),
             'all four actual fixed subjects and every unchanged comparator required')
        r['status']='passed'
    except BaseException as e:
        if r['error'] is None:r['error']=type(e).__name__+': '+str(e)
    finally:
        try:closure();r['inputs_unchanged']=True
        except BaseException as e:r['final_errors'].append(repr(e))
        try:need(source()==r['source'],'exact source unchanged');r['source_unchanged']=True
        except BaseException as e:r['final_errors'].append(repr(e))
        r['cleanup_complete']=all(c.get('reaped') and not c.get('cleanup_errors') and
            all(d['closed'] for d in c.get('descriptors',[])) for c in r['commands'])
        if r['error'] or r['final_errors'] or not all(r[k] for k in ('source_unchanged','inputs_unchanged','cleanup_complete')):r['status']='failed'
        r.update(inputs=pins,artifacts=artifacts,aliases=aliases,presence=presence)
        save(private/'receipt.json',r)
    return 0 if r['status']=='passed' else 1


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('expect-revision','current-build','current-build-sha256','output'):p.add_argument('--'+name,required=True)
    return execute(p.parse_args())


if __name__=='__main__':raise SystemExit(main())
