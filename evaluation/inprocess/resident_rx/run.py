#!/usr/bin/env python3
"""Finite retained-RX development cohort; original R3/generation gates stay separate.

The fixed cohort has one unchanged native/positive pair and seven causal
subjects across six risk categories. Case7 is a trusted replacement injection,
not an admitted guest mapping. No qualification or performance credit is granted.
"""
import argparse,hashlib,json,os,re,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3];HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(ROOT/'evaluation/inprocess'),str(ROOT/'tools/page-entry')]
from checks import source,ROOT as CHECK_ROOT
from run import hardware
from page_selected import ENV,fact,need,save,interpreter
from page_selected_process import invoke
from page_selected_effect_ls import program_invoke
from loop_ro_current_archive import current_archive
from direct_frontier_loop_helpers import prepare_inputs
from unrolled_hash_owner import seed_prerequisite
from resident_three import terminal_reports,certificate_reports
from resident_three.audit_semantics import module,loaded_application_relation,gated_controls

BUILD=[30,512<<20,16<<20,60];NATIVE=[5,512<<20,16<<20,15];INSPECT=[10,256<<20,4<<20,20]
MASK=0xffffffffbffbfae7


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--current-build-receipt',type=Path,required=True)
    p.add_argument('--current-build-sha256',required=True)
    p.add_argument('--expect-revision',required=True);p.add_argument('--cpu',type=int,required=True)
    p.add_argument('--output',type=Path,required=True)
    return execute(p.parse_args())


def execute(a,*,context=None):
    if context is None:
        from resident_rx import build as build_module
        from resident_generation.audit_semantics import gated_process
        root=ROOT;compiler_root=ROOT;reader_root=ROOT;contract_path=HERE/'CONTRACT.json';prior=None
    else:
        need(set(context)=={'root','compiler_root','reader_root','contract','build_module',
             'gated_process','prior_case0'},'only explicit source/reader context and closed compiler prefix')
        root=context['root'];compiler_root=context['compiler_root'];reader_root=context['reader_root']
        contract_path=context['contract'];build_module=context['build_module']
        gated_process=context['gated_process'];prior=context['prior_case0']
        need(root==CHECK_ROOT and all(p.is_absolute()for p in(root,compiler_root,reader_root,contract_path)),
             'ordinary helpers retain their actual repository root; source paths are explicit')
    here=root/'evaluation/inprocess/resident_rx';private=a.output.absolute()
    need(private.parent==root/'target/evaluation/inprocess'and not private.exists(),'fresh direct output child')
    need(not sys.flags.optimize and sorted(os.sched_getaffinity(0))==[a.cpu]and
        re.fullmatch('[0-9a-f]{40}',a.expect_revision)and re.fullmatch('[0-9a-f]{64}',a.current_build_sha256),
        'assertions enabled, explicit clean revision and exact reserved CPU')
    private.mkdir();receipt=private/'receipt.json'
    r=dict(schema=1,profile='resident-rx-development-v1',status='failed',source=source(),
        revision=a.expect_revision,cpu=a.cpu,hardware=hardware(a.cpu),inputs={},aliases={},artifacts={},
        cases=[],source_unchanged=False,inputs_unchanged=False,cleanup_complete=False,error=None,
        final_errors=[],qualification_credit=False,performance_credit=False,
        original_r3_generation_qualification='separate_required_unmodified_collectors')
    def pin(path,expected=None):
        alias=Path(path).absolute();q=alias.resolve(strict=True);v=fact(q)
        need(expected is None or all(expected[k]==v[k]for k in('bytes','sha256')),'whole supplied input')
        need(str(q)not in r['inputs']or r['inputs'][str(q)]==v,'stable whole input')
        need(str(alias)not in r['aliases']or r['aliases'][str(alias)]==str(q),'stable whole alias')
        r['inputs'][str(q)]=v;r['aliases'][str(alias)]=str(q);return q
    def binary(path):
        q=Path(path).resolve(strict=True);v=dict(fact(q),mode=q.stat().st_mode&0o777)
        need(str(q)not in r['artifacts']or r['artifacts'][str(q)]==v,'immutable actual artifact')
        r['artifacts'][str(q)]=v;return q
    def closure():
        need(all(fact(p)==v for p,v in r['inputs'].items()),'all whole inputs unchanged')
        need(all(str(Path(p).resolve(strict=True))==v for p,v in r['aliases'].items()),'whole literal aliases unchanged')
        need(all(dict(fact(p),mode=Path(p).stat().st_mode&0o777)==v for p,v in r['artifacts'].items()),'whole artifacts unchanged')
        need(sorted(os.sched_getaffinity(0))==[a.cpu],'same reserved CPU')
    try:
        need(r['source']['revision']==a.expect_revision and r['source']['tracked_clean']and
            r['source']['head_sources_match'],'exact clean installed source')
        pin(__file__);pin(build_module.__file__);contract=json.loads(pin(contract_path).read_bytes())
        for relative in contract['reader_paths']:pin(reader_root/relative)
        if context is not None:
            r['source_context']=dict(root=str(root),compiler_root=str(compiler_root),reader_root=str(reader_root),
                contract=dict(path=str(contract_path),**fact(contract_path)),qualification_credit=False)
            pin(gated_process.__code__.co_filename)
        retained,archive,proof=current_archive(a.current_build_receipt,a.current_build_sha256,root,pin,binary,r['aliases'])
        r['archive_build']=proof;tools=retained.tools
        need(pin(sys.executable)==pin(tools['python']),'actual current archive compiler Python')
        # Original native seed and app are freshly executed once. No historical
        # subject or incomplete causal stdout is relabelled a native reference.
        reference=None;native_result=None
        for case in range(8):
            reuse=prior is not None and case==0
            directory=prior['directory']if reuse else private/('case-'+str(case))
            if not reuse:directory.mkdir()
            else:
                need(directory.is_dir()and len(prior['commands'])==7 and
                     [x['name']for x in prior['commands']]==contract['compile_commands'][:7],
                     'exact closed compiler prefix; no retained native or gated subject')
                pin(prior['receipt_fact']['path'],prior['receipt_fact'])
            c=dict(case=case,cpu=a.cpu,status='failed',commands=[],builds={},error=None,
                qualification_credit=False,performance_credit=False)
            if reuse:c['retained_prefix']={k:v for k,v in prior.items()if k not in('directory','commands')}
            c['command_origins']=[]
            r['cases'].append(c);save(receipt,r)
            def run(name,argv,profile='metadata',env=None,record=False):
                closure();need(not any(x['name']==name for x in c['commands']),'fixed command used once')
                bounds=NATIVE if profile in('finite','seed')else INSPECT if profile=='inspect'or name=='seed-headers'else BUILD
                row=dict(name=name,argv=list(map(str,argv)),profile=profile,bounds=list(bounds),
                    environment=dict(ENV if env is None else env),capture_limit=16<<20,
                    expected_exit=125 if name=='gated-fixture'and case else 0)
                index=len(c['commands'])
                if reuse and index<7:
                    actual=prior['commands'][index]
                    need(not record and all(actual[k]==v for k,v in row.items()),
                         'whole literal retained compiler argv/environment/profile/bounds/outcome request')
                    need(json.loads(pin(directory/(name+'.json')).read_bytes())==actual and
                         set(actual['captures'])=={'stdout','stderr'},'whole closed retained command and capture roster')
                    data={}
                    for stream,value in actual['captures'].items():
                        capture=pin(directory/value['file'],value)
                        need(capture.parent==directory and value['bytes']<=actual['capture_limit'],
                             'whole bounded retained capture at its original path')
                        binary(capture);data[stream]=capture.read_bytes()
                    row=actual;out=data['stdout'];err=data['stderr']
                    c['commands'].append(row);c['command_origins'].append('retained_compiler_prefix')
                    save(receipt,r)
                else:
                    need(not(directory/(name+'.json')).exists()and
                         all(not(directory/(name+'.'+s)).exists()for s in('stdout','stderr','record')),
                         'fresh command and captures never overwrite a closed attempt')
                    c['commands'].append(row);c['command_origins'].append('fresh');save(receipt,r)
                    try:out,err=program_invoke(row,directory,a.cpu,record=True)if record else invoke(row,directory,a.cpu)
                    finally:
                        for v in row.get('captures',{}).values():binary(directory/v['file'])
                        save(receipt,r)
                need(row['exit']==row['expected_exit']and row['reaped']is True and row['timed_out']is False and
                    row['error']is None and not row['cleanup_errors']and all(x['closed']is True for x in row['descriptors']),
                    'original bounded actual command '+name)
                return row,out,err
            try:
                app,interp,bridge,builder,layout,binding=build_module.build(directory,archive,tools,c,pin,binary,r['aliases'],run,fact,case,source_context=context)
                need(pin(interpreter(app))==interp,'actual source-owned application interpreter')
                if not case:
                    c['seed_prerequisite']=dict(planned=1,status='unexecuted',launched=False,expected_exit=0,
                        bounds=NATIVE,completed_applications=0,owner_subjects=0,performance_credit=False)
                    reference=seed_prerequisite(builder,directory,pin,binary,run,c)
                    native_prep=directory/'native-preparation.json';native_launch=pin(here.parent/'resident_three/native_launch.py')
                    try:nrow,nraw,nerr=run('native-fixture',[tools['python'],'-I','-S','-B',native_launch,'--root',root,
                        '--original',app,'--preparation',native_prep],profile='finite')
                    finally:
                        if native_prep.is_file():binary(native_prep)
                    prep=json.loads(native_prep.read_bytes())
                    need(not nerr and prep['schema_version']==1 and prep['status']=='prepared_not_executed'and
                        prep['role']=='native'and prep['pid']==nrow['pid']and prep['cpu']==[a.cpu]and
                        prep['reset_mask']==0 and prep['launch_mask']==MASK and prep['observer']is None and
                        prep['argv']==[str(app),'native']and prep['default_rseq']is False and
                        prep['environment']==dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',LD_BIND_NOW='1',
                            GLIBC_TUNABLES='glibc.pthread.rseq=0',LD_LIBRARY_PATH='/usr/lib64')and
                        [v['signal']for v in prep['dispositions']]==[i for i in range(1,65)if i not in(9,19)]and
                        all(v['after']==0 for v in prep['dispositions']),'whole unchanged native preparation')
                    app_reader=module('rx_app',pin(reader_root/'tools/page-entry/selected/tests/resident_generation_app/read.py'))
                    policy=module('rx_policy',pin(reader_root/'tools/page-entry/selected/tests/oneshot_integrated/check.py'))
                    app_image=app_reader.elf(app.read_bytes(),policy.native_policy)
                    native_result=app_reader.read(nraw,True,nrow['exit'],app_image,nrow['pid'],a.cpu,reference)
                    c['native_controls']=app_reader.controls(nraw,True,nrow['exit'],app_image,nrow['pid'],a.cpu,reference)
                    need(c['native_controls']['records']==2 and all(len(x['result']['refusals'])==80
                        for x in c['native_controls']['controls']),'all160 original native application mutations')
                application=dict(interpreter=dict(path=str(interp),**fact(interp)))
                _,roots,_,_,_,_,carrier=prepare_inputs(app,bridge,builder,directory,pin,binary,run,c,application)
                preparation=directory/'preparation.json';launcher=pin(here.parent/'resident_three/launch.py')
                argv=[tools['python'],'-B',launcher,'--root',root,'--role','gated','--mode','0','--control','0',
                    '--original',app,'--preparation',preparation]
                for library_root in roots:argv+=['--library-root',library_root]
                argv+=['--carrier',carrier,'--namespace',directory/'namespace','--record-fd','{record_fd}']
                try:run('gated-fixture',argv,profile='program',record=True)
                finally:
                    for path in(preparation,directory/'namespace/namespace.json',directory/'namespace/launch.json'):
                        if path.is_file():binary(path)
                def capture(parent,row,stream):
                    value=row['captures'][stream];path=pin(parent/value['file'])
                    need(path.parent==parent and fact(path)=={k:value[k]for k in('bytes','sha256')},'complete contained actual capture')
                    return path.read_bytes()
                headers={p:{k:v[k]for k in('bytes','sha256')}for p,v in c['builds']['bridge']['headers'].items()}
                row,raw,stderr,record,image,_=gated_process(root,here,directory/'receipt.json',c,pin,capture,
                    layout,binding,headers,'maintained','rrx_bundle',layout['types']['r3o_wire']['bytes'])
                if case:
                    need(raw==b'','failed causal subjects do not fabricate deferred application output')
                    actual,parsed=certificate_reports.failed_prefix(stderr)
                    reader=module('rx_refusal',pin(reader_root/'tools/page-entry/selected/tests/resident_rx_owner/refusal.py'))
                    c['semantic']=reader.refusal(record,layout,image,row['pid'],a.cpu,row['exit'],case,actual)
                    need(actual['LI2_LOADER']['status']==125 and
                        actual['LI2_LOADER']['failure_code']==c['semantic']['code'],
                        'same real failed terminal and actual causal record')
                    c['refusal_controls']=reader.controls(record,layout,image,row['pid'],a.cpu,row['exit'],case,actual)
                    need(c['refusal_controls']['count']==(25 if case==7 else 17)and
                         c['refusal_controls']['source_join_count']==20 and
                         c['refusal_controls']['ingress_count']==(0 if case in(5,7)else 14)and
                         c['refusal_controls']['retirement_count']==(12 if case==3 else 0)and
                         c['refusal_controls']['descriptor_count']==(22 if case==7 else 0),
                         'all original failed-prefix/source joins plus exact typed-ingress controls')
                    c['terminal']=actual;c['status']='observed_causal_refusal'
                else:
                    c['terminal']=terminal_reports.check(stderr);c['terminal_controls']=terminal_reports.controls(stderr)
                    application=app_reader.read(raw,False,row['exit'],app_image,row['pid'],a.cpu,reference)
                    c['gated_controls']=[gated_controls(app_reader.original,raw[i*341960:(i+1)*341960],False,
                        row['exit'],app_image,row['pid'],a.cpu,reference)for i in range(2)]
                    owner=module('rx_owner',pin(reader_root/'tools/page-entry/selected/tests/resident_rx_owner/read.py'))
                    args=(record,layout,image,application,row['pid'],a.cpu,row['exit'])
                    actual=owner.read(*args)
                    c['semantic']={k:actual[k]for k in('version','scope','publications','entries','completed',
                        'interior_signals','preserved_boundary_effects','stable_api_deltas','final_api_calls',
                        'final_lifetime_counts','final_closed_pages','signal_counts','transport',
                        'qualification_credit','performance_credit')}
                    c['pair']=owner.pair(native_result,application,actual)
                    c['pair_controls']=owner.pair_controls(native_result,application,actual)
                    c['owner_controls']=[owner.record_controls(*args,i)for i in range(2)]
                    c['prepared_controls']=[owner.record_prepared_controls(*args,i)for i in range(2)]
                    c['generation_controls']=owner.generation_controls(*args);c['rx_controls']=owner.rx_controls(*args)
                    need([x['count']for x in c['owner_controls']]==[231,231]and
                        [x['count']for x in c['prepared_controls']]==[24,24]and
                        c['generation_controls']['count']==40 and c['rx_controls']['count']==101 and
                        c['pair_controls']['count']==88,'all old and additive state comparisons remain mandatory')
                    c['signal_join']=terminal_reports.resident_signals(stderr,actual['signal_counts'])
                    c['signal_controls']=terminal_reports.resident_signal_controls(stderr,actual['signal_counts'])
                    need(c['signal_controls']['count']==87,'all original signal/terminal controls')
                    c['application_relation']=loaded_application_relation(app.read_bytes(),app.read_bytes(),interp,interp)
                    c['status']='observed_positive_pair'
                names=(['app-prepare']if case else[])+contract['compile_commands']+(
                    ['seed-headers','seed-link','seed-libraries','seed-prerequisite','native-fixture']if not case else[])+['carrier','gated-fixture']
                need([x['name']for x in c['commands']]==names,'whole fixed actual case schedule')
            except Exception as e:
                c['error']=repr(e)
                raise
            finally:save(receipt,r)
        need([x['case']for x in r['cases']]==list(range(8))and
            [x['status']for x in r['cases']]==['observed_positive_pair']+['observed_causal_refusal']*7,
            'one full native pair and all seven causal subjects; no skipped cases')
        r['logical_commands']=sum(len(c['commands'])for c in r['cases'])
        r['fresh_commands']=sum(c['command_origins'].count('fresh')for c in r['cases'])
        need(r['logical_commands']==148 and r['fresh_commands']==(141 if prior is not None else 148),
             'all148 logical commands; only the exact seven closed compiler rows may be retained')
        r['status']='observed_unqualified'
    except Exception as e:r['error']=repr(e)
    finally:
        try:
            for m in tuple(sys.modules.values()):
                path=getattr(m,'__file__',None)
                if path and Path(path).is_file():pin(path)
            closure();r['inputs_unchanged']=True
        except Exception as e:r['final_errors'].append(repr(e));r['status']='failed'
        r['source_unchanged']=source()==r['source']
        r['cleanup_complete']=all(v.get('reaped')is True and not v.get('cleanup_errors')and
            all(d['closed']is True for d in v.get('descriptors',[]))for c in r['cases']for v in c['commands'])
        if not r['source_unchanged']or not r['cleanup_complete']:r['status']='failed'
        save(receipt,r)
    print(json.dumps({k:r[k]for k in('status','error','source_unchanged','inputs_unchanged','cleanup_complete')},sort_keys=True))
    return int(r['status']!='observed_unqualified')

if __name__=='__main__':raise SystemExit(main())
