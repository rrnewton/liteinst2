#!/usr/bin/env python3
"""Distinct linked epoch: metadata, original16, four retry failures, and reuse65 pair."""
import argparse,ctypes,csv,hashlib,importlib.util,io,json,os,platform,re,shlex,shutil,struct,sys
from datetime import datetime,timezone
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
SELECTED=ROOT/'tools/page-entry/selected';FIXTURE=SELECTED/'tests/linked_epoch_app'
OWNER=SELECTED/'tests/linked_epoch_owner'
REUSE_FIXTURE=SELECTED/'tests/linked_epoch_reuse_app';REUSE_OWNER=SELECTED/'tests/linked_epoch_reuse_owner'
sys.path[:0]=[str(HERE),str(SELECTED.parent)]
from checks import source
from run import hardware
from page_selected import ENV,elf,fact,interpreter,need,save
from page_selected_generic_build import Build,PROFILES
from page_selected_process import invoke
from page_selected_effect_ls import program_invoke
from page_selected_oneshot_build import before_default
from page_selected_register_time_build import expand,recipe
from linked_epoch_build import build_bridge
import namespace
import unrolled_hash_owner as donor
import linked_epoch_reports as reports
import scalar_region_owner as columns
import scalar_case_strings as strings
BOUNDS=dict(PROFILES,release_build=[30,512<<20,16<<20,60],program=[30,512<<20,16<<20,60],seed=[5,512<<20,16<<20,15],finite=[5,512<<20,16<<20,15])
MASK=((1<<64)-1)^sum(1<<(s-1)for s in(4,5,9,11,19,31))
H=lambda b:hashlib.sha256(b).hexdigest()
ORDER=tuple((lane,mode,0)for lane in('native','gated')for mode in range(6))+tuple(('gated',m,c)for m,c in((0,1),(5,2),(0,3),(0,4)))
OWNER_COUNTS={(0,0):41,(1,0):41,(2,0):43,(3,0):43,(4,0):43,(5,0):45,(0,1):43,(5,2):45,(0,3):43,(0,4):43}
APP_COUNTS={0:32,1:32,2:32,3:32,4:32,5:38}
REUSE_ORDER=(('native',6,0),('gated',6,0))
REUSE_OWNER_COUNTS={(6,0):47};REUSE_APP_COUNTS={6:36}
REFAULT_ORDER=tuple(('gated',0,0,k)for k in(1,2,3,4))
ALL_ORDER=tuple((*row,0)for row in ORDER)+REFAULT_ORDER+tuple((*row,0)for row in REUSE_ORDER)
REFAULT_COUNTS={(0,0,0):9,(1,0,0):9,(2,0,0):9,(3,0,0):9,(4,0,0):9,(5,0,0):29,
    (0,1,0):9,(5,2,0):9,(0,3,0):9,(0,4,0):9,**{(0,0,k):17 for k in(1,2,3,4)}}
REUSE_REFAULT_COUNTS={(6,0):9}
TERMINAL_REFAULT_COUNTS={k:298 for k in(1,2,3,4)}
PAIR_CONTROL_COUNT=4
HINT_ORDER=tuple((*row,0)for row in ALL_ORDER[:-2])+tuple(('gated',0,0,0,k)for k in(1,2,3))+tuple((*row,0)for row in ALL_ORDER[-2:])
HINT_COUNTS={(m,c,rc,0):(44 if(m,c,rc)==(5,0,0)else 16)for m,c,rc in REFAULT_COUNTS}
HINT_COUNTS.update({(0,0,0,k):30 for k in(1,2,3)})
REUSE_HINT_COUNTS={(6,0):24}
HINT_TERMINAL_COUNT=41
HINT_FAILURE_COUNTS={k:298 for k in(1,2,3)}
HINT_CASE_FIELDS=('hint_control','hint_reference','hint_witness')
HINT_CSV_COLUMNS=('hint_control','hint_owner_control_count','hint_terminal_control_count')
METADATA=SELECTED/'tests/linked_epoch_metadata'
METADATA_SUMMARY=dict(schema=1,linked_code_forms=131,independent_calls=1283,varied_register_calls=5132,
    independent_refusals=27,graph_checks=23,max_heads=64,max_frontiers=8,selected_bytes=320,postseal_equal=1)
METADATA_ROWS=(dict(schema=1,code_forms=131,accepted=1283,old_accepts=53,refusals=26,
    plan_controls=49,none_checks=1283,max_register_rows=4,postseal_equal=1),METADATA_SUMMARY)
METADATA_STDOUT=b''.join((json.dumps(row,separators=(',',':'))+'\n').encode()for row in METADATA_ROWS)
CASE_FIELDS=('label','lane','mode','control','refault_control','expected_exit','status','launched','exit','whole_process_ns',
    'timed_out','captures','pair','owner_summary','control_reference','refault_reference','refault_witness','error_type')
METADATA_FIELDS=('status','planned','launched','expected_exit','bounds','exit','pid','whole_process_ns',
    'timed_out','captures','summary','instruction_execution_credit')
CSV_COLUMNS=('lane','mode','control','refault_control','status','expected_exit','exit','whole_process_ns',
    'application_control_count','terminal_control_count','owner_control_count','pair_control_count','refault_control_count')
# These exact donor helpers own unchanged actual closure and seed/native shim
# proofs; they receive this collector's explicit process/build capabilities.
nested_emission=donor.nested_emission
seed_prerequisite=donor.seed_prerequisite
prepare_inputs=donor.prepare_inputs
image_inventory=donor.image_inventory


def digest(value):return H(json.dumps(value,sort_keys=True,separators=(',',':')).encode())

def public_case(c):
    value={k:c[k]for k in CASE_FIELDS if k in c}
    for prefix,key in(('terminal','terminal_controls'),('application','application_controls'),('owner','owner_reader_controls')):
        value[prefix+'_control_count']=len(c.get(key,{}).get('refusals',[]))
        if prefix!='application':value[prefix+'_controls_sha256']=digest(c.get(key,{}))
    for prefix,key,names in(('pair','pair_controls','refusals'),('refault','refault_reader_controls','refault_refusals')):
        value[prefix+'_control_count']=len(c.get(key,{}).get(names,[]))
        value[prefix+'_controls_sha256']=digest(c.get(key,{}))
    if 'hint_control'in c:
        value.update({k:c[k]for k in HINT_CASE_FIELDS if k in c})
        for prefix,key in(('hint_owner','hint_reader_controls'),('hint_terminal','hint_terminal_controls')):
            value[prefix+'_control_count']=len(c.get(key,{}).get('hint_refusals',[]))
            value[prefix+'_controls_sha256']=digest(c.get(key,{}))
    return value

def public_metadata(r):return {k:v for k,v in r.get('linked_metadata',{}).items()if k in METADATA_FIELDS}

def csv_projection(cases,md,*,native_hint=False):
    need(type(native_hint)is bool,'literal public projection profile')
    fields=CSV_COLUMNS+HINT_CSV_COLUMNS if native_hint else CSV_COLUMNS
    stream=io.StringIO(newline='');writer=csv.writer(stream,lineterminator='\n');writer.writerow(fields)
    writer.writerow(['metadata','','','',md.get('status','unexecuted'),0,md.get('exit',''),md.get('whole_process_ns',''),0,0,0,0,0]+(['',0,0]if native_hint else[]))
    for c in cases:writer.writerow([c.get(k,'')for k in fields])
    return stream.getvalue().encode()

def prerequisite(path,r,pin,binary,*,native_hint=False):
    """Authenticate exactly the selected closed23 or distinct26 profile; no replay."""
    need(type(native_hint)is bool,'literal prerequisite profile')
    import scalar_reuse_performance as prior
    from scalar_span_trace_build import fast_bytes_completed
    path=Path(path).resolve(strict=True)
    need(path.parent==HERE/'results'and path.suffix=='.json'and path.stat().st_size<=32<<10,'exact public linked prerequisite location')
    def pinned(p,want=None):
        result=pin(p)
        if want is not None:need(digest(fact(result))==digest(want),'exact retained prerequisite input')
        return result
    public,actual=prior.closed(path,r,pinned,binary)
    need(public['profile']==actual['profile']==('linked-epoch-native-hint-v3'if native_hint else'linked-epoch-finite-v2')and public['status']==actual['status']=='passed',
         'only the complete distinct linked23 prerequisite')
    expected=dict(planned=23,hardware_planned=22,metadata_qualified=1,launched=23,qualified=23,
        native=7,gated=7,owner_controls=4,qualified_pairs=7,completed_applications=10,
        required_read_faults=2,required_reference_faults=2,required_owner_refusals=4,
        application_reader_refusals=234,terminal_reader_refusals=4570,owner_reader_refusals=477,
        required_refault_refusals=4,pair_reader_refusals=4,refault_reader_refusals=187,actual_refault_witnesses=1)
    if native_hint:expected.update(planned=26,hardware_planned=25,launched=26,qualified=26,terminal_reader_refusals=5464,
        required_hint_rejections=3,hint_owner_reader_refusals=366,hint_terminal_reader_refusals=738,actual_hint_witnesses=1)
    need(actual.get('native_hint',False)is native_hint,'same exact explicit private profile')
    need(digest(actual['totals'])==digest(expected)and digest(public['totals'])==digest(expected)and
         digest(actual['bounds'])==digest(BOUNDS)and digest(public['bounds'])==digest(BOUNDS),
         'exact23 populations, all original16/reuse65 plus retry controls and unchanged resource bounds')
    need(digest(actual['source'])==digest(r['source'])and digest(actual['hardware'])==digest(r['hardware'])and
         type(actual['cpu'])is int and actual['cpu']==r['cpu']and public['performance_credit']is False and
         public['whole_ls_eligibility_credit']is False,'same actual full source/hardware/CPU; finite scope only')
    build=actual['build'];need(digest(build['decoder_features'])==digest(['scalar-region','scalar-span','linked-epoch'])and
         type(build['archive_text_exports']['li2_decoder_link_none'])is int and build['archive_text_exports']['li2_decoder_link_none']==1,
         'actual three-feature archive and unique static NONE provider')
    archive={k:build['artifacts']['decoder.a'][k]for k in('bytes','sha256')}
    commands={x['name']:x for x in actual['commands']};cases=actual['cases']
    schedule=[(c['lane'],c['mode'],c['control'],c['refault_control'],c['hint_control'])for c in cases]if native_hint else[(c['lane'],c['mode'],c['control'],c['refault_control'])for c in cases]
    need(digest(schedule)==digest(HINT_ORDER if native_hint else ALL_ORDER),
         'original16, four distinct helper refusals, then real reuse65 pair; no original case removed')
    def named(v,n,what,key='refusals'):
        names=v[key];need(type(names)is list and len(names)==len(set(names))==n and
            all(type(x)is str for x in names)and type(v['native_operations'])is int and v['native_operations']==0,
            'exact supplied '+what+' refusals, no native work')
    for c in cases:
        lane,mode,control,rc=c['lane'],c['mode'],c['control'],c['refault_control'];hc=c.get('hint_control',0);exit_status=125 if control or rc or hc or mode in(2,3)else 0
        status='qualified_native_reference'if lane=='native'else 'qualified_required_hint_rejection'if hc else 'qualified_required_refault_refusal'if rc else 'qualified_required_owner_refusal'if control else 'qualified_required_read_failure'if mode in(2,3)else'qualified_linked_epoch'
        row=commands[c['label']]
        need(c['launched']is True and c['status']==status and
             digest([c['exit'],c['expected_exit'],row['exit'],row['expected_exit']])==digest([exit_status]*4)and
             row['profile']=='program'and digest(row['bounds'])==digest(BOUNDS['program'])and
             c['timed_out']is False and c['whole_process_ns']==row['duration_ns']and
             digest(c['captures'])==digest({k:{j:v[j]for j in('bytes','sha256')}for k,v in row['captures'].items()}),
             'every actual subject retains its exact source-required outcome/capture/bounds')
        if lane=='native':
            named(c['application_controls'],REUSE_APP_COUNTS[mode]if mode==6 else APP_COUNTS[mode],'app')
            need(c['application_controls']['original_sha256']==row['captures']['stdout']['sha256'],'native controls bind actual output')
        else:
            if not rc and not hc:
                named(c['owner_reader_controls'],REUSE_OWNER_COUNTS[(mode,control)]if mode==6 else OWNER_COUNTS[(mode,control)],'owner')
                need(c['owner_reader_controls']['original_sha256']==row['captures']['record']['sha256'],
                     'all old owner controls bind their unchanged actual cases')
            else:need('owner_reader_controls'not in c,'no old mutation population credited to new helper failures')
            named(c['terminal_controls'],HINT_FAILURE_COUNTS[hc]if hc else TERMINAL_REFAULT_COUNTS[rc]if rc else reports.CONTROL_COUNTS[(mode,control)],'terminal')
            if not hc:
                named(c['refault_reader_controls'],REUSE_REFAULT_COUNTS[(mode,control)]if mode==6 else REFAULT_COUNTS[(mode,control,rc)],'retry','refault_refusals')
                need(c['refault_reader_controls']['original_sha256']==row['captures']['record']['sha256'],
                     'all full retry record controls bind exact actual captures')
            else:need('refault_reader_controls'not in c,'no old retry mutation credit on advisory stop')
            need(c['terminal_controls']['original_stderr_sha256']==row['captures']['stderr']['sha256'],
                 'all terminal controls bind exact actual stderr')
            if native_hint:
                named(c['hint_reader_controls'],REUSE_HINT_COUNTS[(mode,control)]if mode==6 else HINT_COUNTS[(mode,control,rc,hc)],'advisory record','hint_refusals')
                named(c['hint_terminal_controls'],HINT_TERMINAL_COUNT,'advisory terminal','hint_refusals')
                need(c['hint_reader_controls']['original_sha256']==row['captures']['record']['sha256']and
                     c['hint_terminal_controls']['original_stderr_sha256']==row['captures']['stderr']['sha256'],
                     'all additional advisory mutations bind actual complete records/reports')
            if hc:
                need(digest(c['hint_reference'])==digest(dict(qualified_hint_control=1,hint_control=hc,completed_prefix=1,native_operations=0)),
                     'actual completed focal native reference before advisory harness stop')
                w=c['hint_witness'];need(type(w)is dict and set(w)=={'present','control','advisory_rejected','native_refused','trace_ordinal','retained_serial'}and
                    all(type(v)is int for v in w.values())and w['present']==w['advisory_rejected']==1 and w['native_refused']==0 and w['control']==hc and
                    w['trace_ordinal']>0 and w['retained_serial']>0,'actual advisory invalidation witness is not a native-policy refusal')
            elif rc:
                need(digest(c['refault_reference'])==digest(dict(qualified_retry_control=1,refault_control=rc,completed_prefix=1,native_operations=0)),
                     'all four actual helper refusals retain the whole completed native focal reference')
                w=c['refault_witness'];need(digest({k:v for k,v in w.items()if k!='retained_serial'})==digest(dict(present=1,control=rc,required_refusal={1:3002,2:3002,3:3001,4:3003}[rc]))and
                     type(w['retained_serial'])is int and w['retained_serial']>0,'exact actual negative-call witness without invented native completion')
            elif control:need(digest(c['control_reference'])==digest(dict(qualified_control=1,control=control,invocations=2 if control==2 else 1,completed_prefix=int(control==2),generated_owner_credit=0)),
                            'real exact control reference preserves failed generated-owner outcome')
            elif mode==6:need(digest(c['pair'])==digest(dict(qualified_pair=1,invocations=65,generated_completed=65,actual_replacement=1,required_fault=0,lifecycle_effects=0)),
                              'all65 genuine entries and actual completed replacement are mandatory')
            else:need(digest(c['pair'])==digest(dict(qualified_pair=1,invocations=6 if mode==5 else 1,generated_completed=0 if mode in(2,3)else 6 if mode==5 else 1,required_fault=int(mode in(2,3)),frontier_completed=int(mode==4),lifecycle_effects=6 if mode==5 else 0)),
                      'all original six full-state pairs and lifecycle/frontier/fault outcomes')
            if mode==4 and not control and not rc:
                named(c['pair_controls'],PAIR_CONTROL_COUNT,'actual frontier pair')
            else:need('pair_controls'not in c,'no invented frontier pair controls on other cases')
            if mode==5 and not control and not rc:
                w=c['refault_witness'];need(type(w)is dict and set(w)=={'present','control','retained_serial','trace_ordinal','nx_ordinal','closed_ordinal','native_seed','native_closed'}and
                    all(type(v)is int for v in w.values())and w['present']==w['native_seed']==w['native_closed']==1 and w['control']==0 and
                    w['retained_serial']>0 and 0<w['trace_ordinal']<w['nx_ordinal']==w['trace_ordinal']+1 and
                    w['closed_ordinal']==w['nx_ordinal']+1,'mandatory actual TRACE-to-NX native admission and full close witness')
                if native_hint:
                    w=c['hint_witness'];need(type(w)is dict and set(w)=={'present','control','retained_serial','trace_ordinal','nx_ordinal','closed_ordinal','native_seed','native_closed'}and
                        all(type(v)is int for v in w.values())and w['present']==w['native_seed']==w['native_closed']==1 and w['control']==0 and
                        w['retained_serial']>0 and 0<w['trace_ordinal']<w['nx_ordinal']==w['trace_ordinal']+1 and
                        w['closed_ordinal']==w['nx_ordinal']+1,'mandatory separate actual GRAPH-to-NX native admission and full close witness')
    need(digest(columns.expand_cases(public))==digest([public_case(c)for c in cases]),
         'every original public case value/type/presence joins actual private data')
    md=actual['linked_metadata'];command=commands['subject-linked-metadata']
    need(md['status']=='passed'and md['launched']is True and type(md['planned'])is int and md['planned']==1 and
         digest([md['exit'],md['expected_exit'],command['exit'],command['expected_exit']])==digest([0]*4)and command['profile']=='finite'and digest(md['bounds'])==digest(BOUNDS['finite'])and
         digest(md['summary'])==digest(METADATA_SUMMARY)and md['instruction_execution_credit']is False and
         digest(public['linked_metadata'])==digest(public_metadata(actual))and
         digest(md['captures'])==digest({k:{j:v[j]for j in('bytes','sha256')}for k,v in command['captures'].items()})and
         digest(md['archive'])==digest(archive),'actual linked metadata/static NONE/graph prerequisite and whole public projection')
    private=ROOT/'target/evaluation/inprocess'/path.stem
    executable=binary(md['argv'][-1])
    need(digest(command['argv'])==digest([str(executable)])and digest(fact(executable))==digest(md['artifact'])and
         binary(private/command['captures']['stdout']['file']).read_bytes()==METADATA_STDOUT and
         binary(private/command['captures']['stderr']['file']).read_bytes()==b'',
         'one actual retained metadata executable produced both exact original and linked rows without stderr')
    bindings=[]
    for state in(actual,actual['reuse_cohort']):
        release=state['release_build'];binding=release['linked_binding']
        need(release.get('native_hint',False)is native_hint and release['argv'].count('-DLI2_LINKED_NATIVE_HINT=1')==int(native_hint)and
             all((str((SELECTED/name).resolve())in release['headers'])==native_hint for name in('linked_native_hint.h','linked_native_hint.inc')),
             'each actual bridge has exactly the selected advisory macro/header profile')
        need(release['status']==state['application_build']['status']=='passed'and state['cohort_complete']is True and
             digest(release['archive'])==digest(archive)and digest(binding['archive'])==digest(archive),
             'each actual capture bridge/application closes against this exact linked archive')
        fast_bytes_completed(release,actual['commands'],binary)
        need(digest(fact(binary(binding['path'])))==digest(binding['header'])and
             digest(fact(binary(binding['manifest_path'])))==digest(binding['manifest']),
             'actual fresh immutable policy header and binding manifest retained')
        bindings.append({k:binding[k]for k in('version','archive','policy_sha256','header')})
    need(digest(bindings[0])==digest(bindings[1])and type(bindings[0]['version'])is int and bindings[0]['version']==1,
         'same complete exact archive/policy authority across both capture profiles')
    seed=actual['seed_prerequisite'];seed_command=commands['seed-prerequisite']
    need(seed['status']=='passed'and seed['launched']is True and
        digest([seed['exit'],seed['expected_exit'],seed_command['exit'],seed_command['expected_exit']])==digest([0]*4)and
        digest(seed['bounds'])==digest(BOUNDS['seed'])and actual['nested_emission']['status']=='passed'and
        digest(actual['nested_emission']['bridge'])==digest(actual['release_build']['bridge'])and
        digest(actual['namespace_controls'])==digest(dict(status='passed',tests=12,existing=5,added=7)),
        'fresh independent full-state seed, actual whole nested shim and original namespace controls')
    need(pinned(path.with_suffix('.csv')).read_bytes()==csv_projection([public_case(c)for c in cases],public_metadata(actual),native_hint=native_hint),
         'all23 exact public CSV rows equal the actual private outcomes')
    return dict(file=path.name,**fact(pinned(path)),private_receipt=public['private_receipt'],
        profile=actual['profile'],status=actual['status'],totals=expected,archive=archive,binding=bindings[0],
        commands=len(actual['commands']),commands_sha256=digest(actual['commands']),performance_credit=False)

def load(name,path,pin):
    spec=importlib.util.spec_from_file_location(name,pin(path));module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module);return module

def reader_support(builder,private,pin,binary,run,r,fixture=FIXTURE,owner_dir=OWNER):
    reader=load('linked_epoch_app_read_'+fixture.name,fixture/'read.py',pin)
    owner=load('linked_epoch_owner_read_'+owner_dir.name,owner_dir/'read.py',pin)
    policy=private/'native-policy.so';unit=pin(SELECTED/'native_policy.c')
    flags=['-std=gnu11','-O2','-g','-Wall','-Wextra','-Werror','-fPIC','-shared']
    _,out,err=run('policy-headers',[builder.tools['cc'],*flags,'-M','-MT','li2_policy',unit],env=builder.environment)
    lines=out.decode().replace('\\\n',' ').splitlines()
    need(not err and len(lines)==1 and lines[0].startswith('li2_policy: '),'complete policy include rule')
    headers={str(pin(path)):fact(pin(path))for path in shlex.split(lines[0].split(':',1)[1])}
    need(str(unit)in headers and str(SELECTED/'native_policy.h')in headers,'actual policy sources')
    run('policy-link',[builder.tools['cc'],*flags,'-Wl,-z,noexecstack,--build-id=none',unit,'-o',policy],profile='release_build',env=builder.environment)
    r['reader_support']=dict(headers=headers,native_policy=fact(binary(policy)))
    lib=ctypes.CDLL(str(policy));lib.li2_native_policy.argtypes=(ctypes.c_void_p,ctypes.c_size_t);lib.li2_native_policy.restype=ctypes.c_uint
    return reader,owner,lambda data:lib.li2_native_policy(data,len(data))

def compile_subject(builder,private,pin,binary,run,r,fixture=FIXTURE):
    script=pin(fixture/'build.sh')
    rows=recipe(script,'"$cc"');need(len(rows)==1,'one exact three-TU app recipe')
    output=private/'application';output.mkdir()
    argv=expand(rows[0],{'$cc':builder.tools['cc'],'$source_dir':fixture,'$output':output})
    sources=[str(pin(fixture/x))for x in('main.c','pure.c','machine.S')]
    need(argv[-2:]==['-o',str(output/'linked-epoch-app')]and[x for x in argv if x.endswith(('.c','.S'))]==sources and
         [x for x in argv if x.startswith('-D')]==['-DLI2_FAST_EQUAL=1']and all(x in argv for x in
         ('-O2','-g','-Wall','-Wextra','-Werror','-fno-builtin','-mgeneral-regs-only','-mcmodel=large',
          '-fno-asynchronous-unwind-tables','-fno-unwind-tables','-fno-pie','-no-pie')),
         'actual release application source/whole-range helper configuration')
    linker=pin(fixture/'pure.ld');need('-Wl,-T,'+str(linker)in argv,'exact retained helper-page linker source')
    state=r['application_build']=dict(status='failed',recipe=fact(script),linker=fact(linker),argv=argv)
    flags=[x for x in argv[1:-2]if x not in sources and not x.startswith('-Wl,')]
    _,out,err=run('app-headers',[builder.tools['cc'],*flags,'-M','-MT','li2_app',*sources],env=builder.environment)
    lines=out.decode().replace('\\\n',' ').splitlines()
    need(not err and len(lines)==3 and all(x.startswith('li2_app: ')for x in lines),'complete actual three-TU app include closure')
    includes={}
    for line in lines:
        for name in shlex.split(line.split(':',1)[1]):p=pin(name);includes[str(p)]=fact(p)
    need(set(sources)|{str(fixture/'app.h')}<=set(includes),'actual complete app header/source inputs before compilation')
    state['headers']=includes
    run('app-link',argv,profile='release_build',env=builder.environment)
    original=binary(output/'linked-epoch-app');_,head,segments=elf(original)
    need(head[1:4]==(2,62,1)and not any(s[0]==1 and s[1]&3==3 for s in segments),'actual non-PIE x86-64 app without WX')
    _,_,err=run('app-elf',[builder.tools['readelf'],'-h','-l','-d','-r','-W',original],profile='inspect',env=builder.environment)
    need(not err,'actual complete app ELF inspection')
    objdump=pin(shutil.which('objdump',path=ENV['PATH']))
    _,out,err=run('app-objdump-version',[objdump,'--version'],env=builder.environment);need(out and not err,'actual app disassembler identity')
    _,out,err=run('app-symbols',[builder.tools['nm'],'-S','--defined-only',original],profile='inspect',env=builder.environment)
    need(not err,'actual emitted helper symbols');symbols={}
    for name in ('main','copy','same','ua_data_pattern','ua_stack_pattern'):
        found=[line.split()for line in out.decode().splitlines()if line.split()[-1:]==[name]]
        need(len(found)==1 and len(found[0])==4 and found[0][2]=='T','one complete actual app text symbol')
        address,size=int(found[0][0],16),int(found[0][1],16)
        need(size>0 and sum(p[0]==1 and p[1]==5 and p[3]<=address<address+size<=p[3]+p[5]for p in segments)==1,'whole symbol in exact actual RX segment')
        if name!='main':need(0x200001000<=address<address+size<=0x200002000,'actual high full-range helper body')
        symbols[name]=dict(address=address,bytes=size)
        _,assembly,err=run('app-body-'+name,[objdump,'-d','-w','-M','att','--start-address='+hex(address),'--stop-address='+hex(address+size),original],profile='inspect',env=builder.environment)
        need(assembly and not err and ('<'+name+'>:').encode()in assembly,'complete emitted helper/caller inspection')
        emitted=[];cursor=address
        for line in assembly.decode().splitlines():
            matched=re.fullmatch(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)',line)
            if matched:
                chunk=bytes.fromhex(matched[2]);need(int(matched[1],16)==cursor and chunk and cursor+len(chunk)<=address+size,
                    'every emitted instruction byte lies contiguously inside the actual symbol')
                emitted.append(chunk);cursor+=len(chunk)
        segment=next(p for p in segments if p[0]==1 and p[1]==5 and p[3]<=address<address+size<=p[3]+p[5])
        offset=segment[2]+address-segment[3]
        need(cursor==address+size and b''.join(emitted)==original.read_bytes()[offset:offset+size],
             'complete actual nm-sized body bytes equal the retained ELF range')
        if name=='main':main_assembly=assembly.decode()
    for name in ('copy','same','ua_data_pattern','ua_stack_pattern'):
        need(re.search(r'\bmovabsq?\s+\$0x'+format(symbols[name]['address'],'x')+r',',main_assembly)is not None,
             'actual main materializes each full-width high helper address without truncated relocation')
    state.update(status='passed',artifact=fact(original),symbols=symbols);return original

def observed_layout(builder,bridge,private,pin,binary,run,r,owner_dir=OWNER,record_type='leto_wire'):
    gdb=pin(shutil.which('gdb',path=ENV['PATH']));script=pin(owner_dir/'layout.py')
    _,out,err=run('layout-gdb-version',[gdb,'--version'],env=builder.environment);need(out and not err,'actual GDB identity')
    _,out,err=run('owner-layout',[gdb,'-q','-nx','-nh','-batch','-iex','set auto-load off','-iex','set debuginfod enabled off',
        '-iex','set index-cache enabled off','-iex','maintenance set worker-threads 1','--readnow','--se='+str(bridge),'-x',script],
        profile='inspect',env=dict(builder.environment,MALLOC_ARENA_MAX='1'))
    need(not err and out.endswith(b'\n')and out.count(b'\n')==1,'one actual bounded DWARF observation; no inferior execution')
    layout=json.loads(out);need(layout['record']==record_type and 0<layout['types'][record_type]['bytes']+64<16<<20,'actual retained owner wire')
    path=private/'owner-dwarf-layout.json'
    with path.open('xb')as f:f.write(out)
    r['owner_layout']=dict(artifact=fact(binary(path)),bridge=fact(bridge),reader=fact(script));return layout

def preparation(case,row,directory,original,roots,objects,description,carrier,private,binary,r):
    lane,mode,control=case['lane'],case['mode'],case['control'];prep=json.loads(binary(directory/'preparation.json').read_bytes())
    need(not any(k in prep for k in('current_custody','current_control','physical_fallback')),'no unrelated launch profile')
    need(prep['schema_version']==1 and prep['status']=='prepared_not_executed'and prep['role']==lane and
        prep['pid']==row['pid']and prep['cpu']==[r['cpu']]and prep['reset_mask']==0 and prep['launch_mask']==(MASK if lane=='native'else 0)and
        prep['argv']==[str(original),str(mode),lane]and prep['default_rseq']is False and prep['mode']==mode and prep['control']==control and type(prep['refault_control'])is int and prep['refault_control']==case['refault_control']and
        [x['signal']for x in prep['dispositions']]==[n for n in range(1,65)if n not in(9,19)]and all(x['after']==0 for x in prep['dispositions']),
        'actual exact launch signal/mode/environment preparation')
    native_hint=r.get('native_hint',False)
    if native_hint:need(prep.get('native_hint')is True and type(prep.get('hint_control'))is int and prep['hint_control']==case['hint_control'],'exact explicit advisory preparation')
    else:need('native_hint'not in prep and 'hint_control'not in prep,'baseline preparation has no advisory profile')
    if lane=='native':
        need(prep['observer']is None and prep['environment']==dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',LD_BIND_NOW='1',GLIBC_TUNABLES='glibc.pthread.rseq=0',LD_LIBRARY_PATH=':'.join(map(str,roots))),'actual closed native exec environment')
        return None
    ns=directory/'namespace';manifest=json.loads(binary(ns/'namespace.json').read_bytes());launch=json.loads(binary(ns/'launch.json').read_bytes())
    need(all(manifest[k]==v for k,v in description.items())and len(manifest['objects'])==len(objects)and manifest['schema_version']==1 and
        manifest['scope']=='explicit_sealed_dependency_namespace'and manifest['status']=='prepared_not_executed'and manifest['directory']==str(ns)and
        manifest['search_policy']=='explicit roots; no RPATH/RUNPATH/cache emulation'and manifest['identity_policy']=='sealed copies and private paths; not filesystem transparency',
        'actual namespace matches complete independent source plan')
    fds=[]
    for observed,item in zip(manifest['objects'],objects,strict=True):
        need(observed['names']==item['names']and observed['needed']==item['info']['needed']and observed['source']==str(item['path'])and
            observed['descriptive_pt_interp']==(str(item['info']['interpreter'])if item['info']['interpreter']else None)and observed['sha256']==H(item['bytes'])and
            observed['size']==len(item['bytes'])and observed['seals']==namespace.SEALS and type(observed['fd'])is int and observed['fd']>3 and observed['fd']not in fds and
            type(observed['device'])is int and observed['device']>0 and type(observed['inode'])is int and observed['inode']>0,'actual sealed dependency identity')
        fds.append(observed['fd'])
        for name in item['names']:
            p=ns/name;value='/proc/self/fd/'+str(observed['fd']);need(p.is_symlink()and os.readlink(p)==value,'actual sealed dependency alias');r['namespace_aliases'][str(p)]=value
    need(launch==dict(schema_version=1,scope='first_entry_loader_candidate',status='prepared_not_executed',argv=prep['argv'],dependency_fds=fds,
        carrier_sha256=fact(carrier)['sha256'],carrier_size=fact(carrier)['bytes'],environment=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',
        LD_BIND_NOW='1',GLIBC_TUNABLES='glibc.pthread.rseq=0',LD_LIBRARY_PATH=str(ns),LI2_DEPENDENCY_FDS=','.join(map(str,fds)),LI2_LINKED_EPOCH_CAPTURE_CONTROL=str(control),
        LI2_LINKED_EPOCH_APP_MODE=str(mode),LI2_LINKED_REFAULT_CONTROL=str(case['refault_control']),**(dict(LI2_LINKED_NATIVE_HINT_CONTROL=str(case['hint_control']))if native_hint else{})))and
        prep['late_sonames']==[]and prep['environment_source']==str(ns/'launch.json'),'actual exact gated capture-control exec environment')
    record=private/row['captures']['record']['file'];st=record.stat()
    need(prep['observer']==dict(fd=3,device=st.st_dev,inode=st.st_ino)and st.st_nlink==1 and st.st_mode&0o7777==0o600,'same exclusive owner record descriptor')
    return manifest

def metadata(builder,products,private,pin,binary,aliases,run,r):
    from page_selected_register_time_build import headers
    fixture=METADATA;script=pin(fixture/'build.sh');rows=recipe(script,'"$cc_bin"')
    need(len(rows)==1,'one exact linked metadata recipe');output=private/'metadata';output.mkdir()
    exe=output/'linked-metadata';archive=pin(products['archive'])
    argv=expand(rows[0],{'$cc_bin':builder.tools['cc'],'$selected':SELECTED,'$fixture':fixture,'$archive':archive,'$output':exe})
    units=[str(pin(x))for x in(fixture/'metadata.c',SELECTED/'tests/decoder/support.c',SELECTED/'region_plan.c',SELECTED/'linked_plan.c')]
    need(argv[-2:]==['-o',str(exe)]and[x for x in argv if x.endswith(('.c','.S'))]==units and
         [x for x in argv if x.startswith('-D')]==['-DLI2_FAST_MEMSET=1','-DLI2_FAST_EQUAL=1','-DLI2_SCALAR_SPAN=1','-DLI2_LINKED_EPOCH=1']and
         all(x in argv for x in('-O2','-g','-fstack-usage','-mgeneral-regs-only','-fno-builtin','-fno-tree-vectorize','-Wall','-Wextra','-Werror')),
         'actual exact metadata compiler and feature tuple')
    state=r['linked_metadata']=dict(status='failed',planned=1,launched=False,expected_exit=0,bounds=BOUNDS['finite'],recipe=fact(script),archive=fact(archive),argv=argv)
    headers('linked-metadata-headers',argv,units,archive,builder,pin,aliases,run,state)
    need({str((SELECTED/x).resolve())for x in('linked_plan.h','linked_rseq.h','region_plan.h','region_decode.h','write_footprint.h','tests/scalar_span/metadata.c')}<=set(state['headers']),
         'complete original metadata plus linked header closure')
    run('linked-metadata-link',argv,profile='release_build',env=builder.environment)
    exe=binary(exe);data,head,segments=elf(exe)
    need(head[1]in(2,3)and all(p[2]+p[5]<=len(data)and p[5]<=p[6]and p[1]&3!=3 for p in segments if p[0]==1),'whole actual metadata ELF without WX')
    interp=[p for p in segments if p[0]==3];need(len(interp)==1,'one actual metadata interpreter')
    item=interp[0];name=data[item[2]:item[2]+item[5]]
    need(name.startswith(b'/')and name.endswith(b'\0')and b'\0'not in name[:-1],'whole actual metadata PT_INTERP');loader=pin(os.fsdecode(name[:-1]))
    _,out,err=run('linked-metadata-libraries',[loader,'--list',exe],profile='inspect',env=builder.environment);need(not err,'actual metadata loader inspection')
    libraries={}
    for line in out.decode().splitlines():
        if re.fullmatch(r'\s*linux-vdso.so.1 \(0x[0-9a-f]+\)',line):continue
        m=re.fullmatch(r'\s*(?:\S+ => )?(/\S+) \(0x[0-9a-f]+\)',line);need(m is not None,'one exact resolved metadata library')
        path=pin(m[1]);need(str(path)not in libraries,'unique metadata library');libraries[str(path)]=fact(path)
    need(str(loader)in libraries,'actual metadata loader in full closure')
    _,_,err=run('linked-metadata-elf',[builder.tools['readelf'],'-h','-l','-d','-r','-W',exe],profile='inspect',env=builder.environment);need(not err,'whole actual metadata ELF inspection')
    _,out,err=run('linked-metadata-symbols',[builder.tools['nm'],'-S','--defined-only',exe],profile='inspect',env=builder.environment);need(not err,'whole metadata symbol output')
    for name in('li2_decoder_link_none','li2_decoder_span_describe','li2_decoder_write_footprint','li2_link_plan_page','li2_link_plan_validate'):
        found=[x.split()for x in out.decode().splitlines()if x.split()[-1:]==[name]]
        need(len(found)==1 and len(found[0])==4 and found[0][2]in('T','t')and int(found[0][1],16)>0,'one actual metadata provider '+name)
    checker=load('linked_metadata_read',fixture/'read.py',pin);state.update(artifact=fact(exe),runtime_libraries=libraries)
    try:row,out,err=run('subject-linked-metadata',[exe],profile='finite',env=builder.environment)
    finally:
        if r['commands'][-1]['name']=='subject-linked-metadata':
            row=r['commands'][-1];state.update(launched=type(row.get('pid'))is int,exit=row.get('exit'),pid=row.get('pid'),whole_process_ns=row.get('duration_ns'),timed_out=row.get('timed_out'))
            state['captures']={k:{j:v[j]for j in('bytes','sha256')}for k,v in row.get('captures',{}).items()}
    summary=checker.check(out,err,row['exit'])
    need(digest(summary)==digest(METADATA_SUMMARY),
         'complete exact linked metadata tuple')
    state.update(status='passed',summary=summary,instruction_execution_credit=False)


def cohort(builder,products,private,pin,binary,aliases,run,r,*,reuse=False,seed_reference=None):
    native_hint=r.get('native_hint',False);need(type(native_hint)is bool,'literal finite cohort profile')
    capture_root=private;fixture=REUSE_FIXTURE if reuse else FIXTURE;owner_dir=REUSE_OWNER if reuse else OWNER
    state=r
    if reuse:
        private=private/'reuse65';private.mkdir()
        state=r['reuse_cohort']={}
        original_run=run
        def run(name,*args,**kwargs):
            return original_run(name if name.startswith('subject-')else 'reuse-'+name,*args,**kwargs)
    reader,owner_reader,native_policy=reader_support(builder,private,pin,binary,run,state,fixture,owner_dir)
    if native_hint:(owner_reader.base if reuse else owner_reader).hint_module()
    original=compile_subject(builder,private,pin,binary,run,state,fixture)
    app_layout=reader.elf(original.read_bytes(),native_policy)
    state['application_layout']={k:v for k,v in app_layout.items()if k!='source'}
    if not reuse:seed_reference=seed_prerequisite(builder,private,pin,binary,run,r)
    need(seed_reference is not None,'same actual independent seed qualification')
    extra=('LINKED_EPOCH_CAPTURE','LINKED_EPOCH_REUSE_CAPTURE')if reuse else('LINKED_EPOCH_CAPTURE',)
    bridge=build_bridge(builder,products,private,pin,binary,aliases,run,state,extra,capture_image=original,**(dict(native_hint=True)if native_hint else{}))
    if not reuse:nested_emission(builder,bridge,pin,run,state)
    layout=observed_layout(builder,bridge,private,pin,binary,run,state,owner_dir,'lero_wire'if reuse else'leto_wire')
    interp,roots,objects,description,images,raws,carrier=prepare_inputs(original,bridge,builder,private,pin,binary,run,state)
    carrier_bytes=carrier.read_bytes();launcher=pin(FIXTURE/'launch.py');native_records={}
    for module in tuple(sys.modules.values()):
        path=getattr(module,'__file__',None)
        if path and Path(path).is_file():pin(path)
    owner_counts=REUSE_OWNER_COUNTS if reuse else OWNER_COUNTS;app_counts=REUSE_APP_COUNTS if reuse else APP_COUNTS
    need(digest({str(k):v for k,v in owner_reader.CONTROL_COUNTS.items()})==digest({str(k):v for k,v in owner_counts.items()}),'literal finite protected refusal table')
    need(digest(reader.APP_CONTROL_COUNTS)==digest(app_counts),'literal finite native refusal table')
    need(sum(reports.CONTROL_COUNTS.values())==3378 and set(reports.CONTROL_COUNTS)==set(OWNER_COUNTS)|{(6,0)}and
         digest(reports.REFAULT_CONTROL_COUNTS)==digest(TERMINAL_REFAULT_COUNTS),'literal original and distinct failed-helper terminal-refusal tables')
    refault_counts=REUSE_REFAULT_COUNTS if reuse else REFAULT_COUNTS
    need(digest({str(k):v for k,v in owner_reader.REFAULT_CONTROL_COUNTS.items()})==digest({str(k):v for k,v in refault_counts.items()}),
         'literal separate actual refault observation mutation table')
    if not reuse:need(type(reader.FRONTIER_PAIR_CONTROL_COUNT)is int and reader.FRONTIER_PAIR_CONTROL_COUNT==PAIR_CONTROL_COUNT,
         'four actual mode4 CR2-history pair controls')
    if native_hint:
        hint_counts=REUSE_HINT_COUNTS if reuse else HINT_COUNTS
        need(digest({str(k):v for k,v in owner_reader.HINT_CONTROL_COUNTS.items()})==digest({str(k):v for k,v in hint_counts.items()})and
             type(reports.HINT_TERMINAL_CONTROL_COUNT)is int and reports.HINT_TERMINAL_CONTROL_COUNT==HINT_TERMINAL_COUNT and
             digest(reports.HINT_FAILURE_CONTROL_COUNTS)==digest(HINT_FAILURE_COUNTS),'exact additional advisory record and terminal tables')
    cases=[c for c in r['cases']if(c['mode']==6)==reuse]
    for c in cases:
        lane,mode,control,rc=c['lane'],c['mode'],c['control'],c['refault_control'];hc=c.get('hint_control',0);label=c['label'];c['status']='failed';directory=private/label;directory.mkdir()
        argv=[builder.tools['python'],'-B',launcher,'--root',ROOT,'--role',lane,'--mode',str(mode),'--control',str(control),'--refault-control',str(rc),
            '--original',original,'--preparation',directory/'preparation.json']
        if native_hint:argv+=['--native-hint','--hint-control',str(hc)]
        for p in roots:argv+=['--library-root',p]
        if lane=='gated':argv+=['--carrier',carrier,'--namespace',directory/'namespace','--record-fd','{record_fd}']
        try:
            try:row,out,err=run(label,argv,profile='program',expected=c['expected_exit'],record=lane=='gated')
            finally:
                if r['commands'][-1]['name']==label:
                    actual=r['commands'][-1];c.update(exit=actual.get('exit'),whole_process_ns=actual.get('duration_ns'),timed_out=actual.get('timed_out'),launched=type(actual.get('pid'))is int)
                    c['captures']={k:{j:v[j]for j in('bytes','sha256')}for k,v in actual.get('captures',{}).items()}
            manifest=preparation(c,row,directory,original,roots,objects,description,carrier,capture_root,binary,r)
            parsed=reader.hint_read(out,mode,False,row['exit'],app_layout,row['pid'],r['cpu'],seed_reference,hint_control=hc)if hc else reader.refault_read(out,mode,False,row['exit'],app_layout,row['pid'],r['cpu'],seed_reference,refault_control=rc)if rc else reader.read(out,mode,lane=='native',row['exit'],app_layout,row['pid'],r['cpu'],seed_reference,control=control)
            if lane=='native':
                need(err==b'','native stderr remains empty');native_records[mode]=(out,row['pid']);c['status']='qualified_native_reference'
                c['application_controls']=reader.controls(out,mode,True,row['exit'],app_layout,row['pid'],r['cpu'],seed_reference)
                need(len(c['application_controls']['refusals'])==app_counts[mode]and c['application_controls']['native_operations']==0 and c['application_controls']['original_sha256']==H(out),'complete actual native supplied controls')
            else:
                capture=row['captures']['record'];record_path=binary(capture_root/capture['file'])
                need(fact(record_path)=={k:capture[k]for k in('bytes','sha256')},'whole actual protected TRACE record')
                record=record_path.read_bytes();image=image_inventory(original,interp,carrier,objects,manifest);image['bridge']=bridge.read_bytes();image['binding']=state['release_build']['linked_binding'];image['headers']=state['release_build']['headers']
                actual_owner=owner_reader.read(record,layout,image,parsed,row['pid'],r['cpu'],row['exit'],control=control,**(dict(native_hint=True)if native_hint else{}),**({}if reuse else dict(refault_control=rc,**(dict(hint_control=hc)if native_hint else{}))))
                terminal_args=(row['pid'],row['exit'],row['stdout_provenance_before'],images,raws,fact(carrier),carrier_bytes,actual_owner,owner_reader,mode)
                terminal,c['terminal']=reports.check(err,*terminal_args);r['terminal_reports'][label]=terminal
                c['terminal_controls']=reports.controls(err,*terminal_args)
                if native_hint:
                    c['hint_terminal_controls']=reports.hint_controls(err,*terminal_args)
                    c['hint_reader_controls']=owner_reader.hint_controls(record,layout,image,parsed,row['pid'],r['cpu'],row['exit'],control=control,native_hint=True,**({}if reuse else dict(refault_control=rc,hint_control=hc)))
                    addition=c['hint_reader_controls'];want=hint_counts[(mode,control)if reuse else(mode,control,rc,hc)]
                    need(type(addition['native_operations'])is int and addition['native_operations']==0 and len(addition['hint_refusals'])==want and addition['original_sha256']==H(record),'complete separate actual advisory record controls')
                    need(type(c['hint_terminal_controls']['native_operations'])is int and c['hint_terminal_controls']['native_operations']==0 and len(c['hint_terminal_controls']['hint_refusals'])==HINT_TERMINAL_COUNT and c['hint_terminal_controls']['original_stderr_sha256']==H(err),'complete separate advisory report controls')
                c['owner_summary']=actual_owner['summary']
                need(type(c['owner_summary'])is dict and c['owner_summary']and all(type(k)is str and type(v)is int and 0<=v<1<<64 for k,v in c['owner_summary'].items()),'only actual numeric global owner summary')
                need(mode in native_records,'same-mode genuine native reference required');nout,npid=native_records[mode]
                if not reuse:c['refault_witness']=actual_owner['refault']
                if native_hint and not reuse:c['hint_witness']=actual_owner['hint']
                if hc:
                    native=reader.read(nout,mode,True,0,app_layout,npid,r['cpu'],seed_reference)
                    c['hint_reference']=reader.hint_control_reference(native,parsed,actual_owner)
                    need(digest(c['hint_reference'])==digest(dict(qualified_hint_control=1,hint_control=hc,completed_prefix=1,native_operations=0)),'actual completed focal graph precedes explicit advisory harness stop')
                    c['status']='qualified_required_hint_rejection'
                elif rc:
                    native=reader.read(nout,mode,True,0,app_layout,npid,r['cpu'],seed_reference)
                    c['refault_reference']=reader.refault_control_reference(native,parsed,actual_owner)
                    need(digest(c['refault_reference'])==digest(dict(qualified_retry_control=1,refault_control=rc,completed_prefix=1,native_operations=0)),
                         'actual completed graph reference before distinct required helper failure')
                    c['status']='qualified_required_refault_refusal'
                elif control:
                    native=reader.read(nout,mode,True,0,app_layout,npid,r['cpu'],seed_reference)
                    c['control_reference']=reader.control_reference(native,parsed,actual_owner)
                    need(c['control_reference']['qualified_control']==1 and c['control_reference']['control']==control,'exact source-causal reference binding')
                    c['status']='qualified_required_owner_refusal'
                else:
                    def compare(n,g):
                        native=reader.read(n,mode,True,125 if mode in(2,3)else 0,app_layout,npid,r['cpu'],seed_reference)
                        gated=reader.read(g,mode,False,row['exit'],app_layout,row['pid'],r['cpu'],seed_reference)
                        owner=owner_reader.read(record,layout,image,gated,row['pid'],r['cpu'],row['exit'],**(dict(native_hint=True)if native_hint else{}))
                        return reader.pair(native,gated,owner)
                    c['pair']=compare(nout,out)
                    need(c['pair']['qualified_pair']==1,'actual full-state native/generated pair')
                    c['status']='qualified_required_read_failure'if mode in(2,3)else'qualified_linked_epoch'
                if not rc and not hc:
                    c['owner_reader_controls']=owner_reader.controls(record,layout,image,parsed,row['pid'],r['cpu'],row['exit'],control=control,**(dict(native_hint=True)if native_hint else{}))
                    need(len(c['owner_reader_controls']['refusals'])==owner_reader.CONTROL_COUNTS[mode,control]and c['owner_reader_controls']['native_operations']==0 and c['owner_reader_controls']['original_sha256']==H(record),'complete fixed supplied record refusals')
                if not hc:
                    c['refault_reader_controls']=owner_reader.refault_controls(record,layout,image,parsed,row['pid'],r['cpu'],row['exit'],control=control,**(dict(native_hint=True)if native_hint else{}),**({}if reuse else dict(refault_control=rc)))
                    addition=c['refault_reader_controls'];expected=refault_counts[(mode,control)if reuse else(mode,control,rc)]
                    need(len(addition['refault_refusals'])==expected and addition['native_operations']==0 and addition['original_sha256']==H(record),
                         'complete separate retry witness mutations against the actual whole record')
                if mode==4 and not control and not rc:
                    native=reader.read(nout,mode,True,0,app_layout,npid,r['cpu'],seed_reference)
                    c['pair_controls']=reader.pair_controls(native,parsed,actual_owner)
                    need(len(c['pair_controls']['refusals'])==PAIR_CONTROL_COUNT and c['pair_controls']['native_operations']==0,
                         'all four actual frontier CR2-history pair refusals')
        except Exception as error:
            c.update(status='failed',error_type=type(error).__name__,error=type(error).__name__+': '+str(error))
            if r['error']is None:r['error']=c['error']
            last=r['commands'][-1]if r['commands']else{}
            if not(last.get('name')==label and last.get('reaped')is True and last.get('cleanup_errors')==[]and isinstance(last.get('descriptors'),list)and all(d.get('closed')is True for d in last['descriptors'])):raise
    state['cohort_complete']=all(c['status'].startswith('qualified_')for c in cases)
    if state['cohort_complete']:
        need(len(cases)==(2 if reuse else 23 if native_hint else 20)and
             sum(c.get('pair',{}).get('qualified_pair',0)for c in cases)==(1 if reuse else 6)and
             sum(c.get('control_reference',{}).get('qualified_control',0)for c in cases)==(0 if reuse else 4)and
             sum(len(c.get('application_controls',{}).get('refusals',[]))for c in cases)==(36 if reuse else 198)and
             sum(len(c.get('owner_reader_controls',{}).get('refusals',[]))for c in cases)==(47 if reuse else 430)and
             sum(len(c.get('terminal_controls',{}).get('refusals',[]))for c in cases)==(318 if reuse else 5146 if native_hint else 4252)and
             sum(c.get('refault_reference',{}).get('qualified_retry_control',0)for c in cases)==(0 if reuse else 4)and
             sum(len(c.get('pair_controls',{}).get('refusals',[]))for c in cases)==(0 if reuse else 4)and
             sum(len(c.get('refault_reader_controls',{}).get('refault_refusals',[]))for c in cases)==(9 if reuse else 178),
             'exact separate finite/reuse hardware, pair and supplied-refusal populations')
        if native_hint:
            need(sum(c.get('hint_reference',{}).get('qualified_hint_control',0)for c in cases)==(0 if reuse else 3)and
                 sum(len(c.get('hint_reader_controls',{}).get('hint_refusals',[]))for c in cases)==(20 if reuse else 326)and
                 sum(len(c.get('hint_terminal_controls',{}).get('hint_refusals',[]))for c in cases)==(41 if reuse else 697),
                 'all separate advisory rejection/reference/record/report outcomes remain mandatory')
    return seed_reference


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--expect-revision',required=True)
    parser.add_argument('--native-hint',action='store_true',help='distinct v3 profile; all baseline cases plus three advisory invalidations')
    args=parser.parse_args()
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',args.expect_revision)and len(os.sched_getaffinity(0))==1,'exact revision/assertions and one reserved CPU')
    os.chdir(ROOT);cpu=next(iter(os.sched_getaffinity(0)));stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+('-linked-epoch-native-hint-'if args.native_hint else'-linked-epoch-')+args.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(mode=0o700)
    pins,aliases,artifacts,presence={},{},{},{}
    r=dict(schema=1,profile='linked-epoch-finite-v2',status='failed',expected_revision=args.expect_revision,started_utc=stamp,cpu=cpu,
        hardware=hardware(cpu),commands=[],cases=[dict(label='subject-'+lane+'-'+str(mode)+'-'+str(control)+('-refault-'+str(rc)if rc else''),lane=lane,mode=mode,control=control,refault_control=rc,
        expected_exit=125 if control or rc or mode in(2,3)else 0,status='unexecuted',launched=False)for lane,mode,control,rc in ALL_ORDER],
        namespace_aliases={},terminal_reports={},bounds=BOUNDS,error=None,final_errors=[],
        seed_prerequisite=dict(planned=1,status='unexecuted',launched=False,expected_exit=0,
            bounds=BOUNDS['seed'],owner_subjects=0,completed_applications=0,performance_credit=False))
    if args.native_hint:
        r.update(profile='linked-epoch-native-hint-v3',native_hint=True)
        r['cases']=[dict(label='subject-'+lane+'-'+str(mode)+'-'+str(control)+('-refault-'+str(rc)if rc else'')+('-hint-'+str(hc)if hc else''),
            lane=lane,mode=mode,control=control,refault_control=rc,hint_control=hc,expected_exit=125 if control or rc or hc or mode in(2,3)else 0,
            status='unexecuted',launched=False)for lane,mode,control,rc,hc in HINT_ORDER]
    def pin(path):
        alias = Path(os.path.abspath(path))
        p = alias.resolve(strict=True)
        value = fact(p)
        need(str(alias) not in aliases or aliases[str(alias)] == str(p), 'stable input alias')
        need(str(p) not in pins or pins[str(p)] == value, 'stable input bytes')
        aliases[str(alias)], pins[str(p)] = str(p), value
        return p

    def binary(path):
        p = Path(path).resolve(strict=True)
        value = dict(fact(p), mode=p.stat().st_mode & 0o777)
        need(str(p) not in artifacts or artifacts[str(p)] == value, 'stable retained artifact')
        artifacts[str(p)] = value
        return p

    def stable():
        need(all(fact(p) == value for p, value in pins.items()), 'all input bytes unchanged')
        need(all(str(Path(p).resolve(strict=True)) == value for p, value in aliases.items()), 'all input aliases unchanged')
        need(all(dict(fact(p), mode=Path(p).stat().st_mode & 0o777) == value
                 for p, value in artifacts.items()), 'all artifact bytes unchanged')
        need(all(os.path.lexists(p) == value for p, value in presence.items()), 'loader configuration presence')
        need(all(Path(p).is_symlink() and os.readlink(p) == value for p, value in r['namespace_aliases'].items()),
             'sealed namespace aliases unchanged')

    def run(name, argv, profile='metadata', expected=0, env=None, record=False):
        stable()
        need(not any(c['name'] == name for c in r['commands']), 'unique command/capture name')
        row = dict(name=name, argv=list(map(str, argv)), environment=dict(ENV if env is None else env),
                   profile=profile, bounds=BOUNDS[profile], capture_limit=16 << 20, expected_exit=expected)
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

    builder=Build(r,private,pin,binary,build_run,extra_decoder_sources=('region.rs',),scalar_span=True,linked_epoch=True)
    try:
        r['source']=source();need(r['source']['revision']==args.expect_revision,'exact clean committed source')
        git=pin(shutil.which('git',path=ENV['PATH']))
        _,names,err=run('source-paths',[git,'-C',ROOT,'ls-files','-z','tools/page-entry','evaluation/inprocess']);need(not err,'source enumeration stderr')
        tracked={os.fsdecode(name)for name in names.split(b'\0')if name}
        required={str(p.relative_to(ROOT))for p in (Path(__file__),HERE/'linked_epoch_reports.py',HERE/'linked_epoch_terminal.py',HERE/'scalar_region_owner.py',HERE/'scalar_case_strings.py',HERE/'linked_epoch_base_reports.py',HERE/'linked_epoch_build.py',HERE/'linked_epoch_cache_reports.py',HERE/'scalar_span_trace_chain_reports.py',HERE/'scalar_span_trace_repeat_reports.py',HERE/'scalar_span_trace_build.py',HERE/'unrolled_hash_owner.py',HERE/'scalar_reuse_performance_reports.py',
            FIXTURE/'main.c',FIXTURE/'pure.c',FIXTURE/'pure.ld',FIXTURE/'machine.S',FIXTURE/'app.h',FIXTURE/'read.py',FIXTURE/'build.sh',FIXTURE/'launch.py',OWNER/'read.py',OWNER/'layout.py',OWNER/'wire.py',OWNER/'plan.py',OWNER/'refault.py')}
        required|={str((SELECTED/name).relative_to(ROOT))for name in('linked_refault_observe.h','linked_refault_observe.inc')}
        required|={str((SELECTED/'tests/provider_app/seed_probe'/n).relative_to(ROOT))for n in('probe.c','record.h','read.py','build.sh')}
        required.add(str((SELECTED/'tests/b2_reference/xstate.py').relative_to(ROOT)))
        required|={str((SELECTED/name).relative_to(ROOT))for name in
            ('span_fast_bytes.h','tests/span_fast_bytes/oracle.c','tests/span_fast_bytes/build.sh')}
        required|={str((METADATA/n).relative_to(ROOT))for n in('metadata.c','build.sh','read.py')}
        required|={str((REUSE_FIXTURE/n).relative_to(ROOT))for n in('main.c','pure.c','pure.ld','machine.S','app.h','read.py','build.sh')}
        required|={str((REUSE_OWNER/n).relative_to(ROOT))for n in('read.py','layout.py','wire.py','plan.py')}
        if args.native_hint:
            required.add(str((OWNER/'hint.py').relative_to(ROOT)))
            required|={str((SELECTED/name).relative_to(ROOT))for name in('linked_hint_observe.h','linked_hint_observe.inc','linked_native_hint.h','linked_native_hint.inc','build-linked-epoch-native-hint.sh')}
        need(required<=tracked,'all application/owner/build/reader sources committed')
        for name in sorted(tracked):
            if not name.startswith('evaluation/inprocess/results/'):pin(ROOT/name)
        for name in('/etc/ld.so.cache','/etc/ld.so.preload'):
            presence[name]=os.path.lexists(name)
            if presence[name]:pin(name)
        need(not presence['/etc/ld.so.preload'],'no global preload')
        temporary=private/'tmp';temporary.mkdir()
        _,out,err=run('namespace-controls',[pin(sys.executable),'-B','-m','unittest','discover','-s',SELECTED.parent,'-p','namespace*_tests.py','-v'],
            profile='program',env=dict(ENV,TMPDIR=str(temporary)))
        need(not out and re.search(rb'\nRan 12 tests in [0-9.]+s\n\nOK\n\Z',err)is not None,'all five existing and seven additive namespace controls')
        r['namespace_controls']=dict(status='passed',tests=12,existing=5,added=7)
        products=builder.prepare()
        for module in tuple(sys.modules.values()):
            path=getattr(module,'__file__',None)
            if path and Path(path).is_file():pin(path)
        metadata(builder,products,private,pin,binary,aliases,run,r)
        seed_reference=cohort(builder,products,private,pin,binary,aliases,run,r)
        cohort(builder,products,private,pin,binary,aliases,run,r,reuse=True,seed_reference=seed_reference)
        need(r['linked_metadata']['status']=='passed'and len(r['cases'])==(25 if args.native_hint else 22) and all(c['status'].startswith('qualified_')for c in r['cases'])and not r['error'],'all23 metadata/native/application/owner/refault attempts required')
        need(digest({k:r['release_build']['linked_binding'][k]for k in('version','archive','policy_sha256','header')})==digest({k:r['reuse_cohort']['release_build']['linked_binding'][k]for k in('version','archive','policy_sha256','header')}),'same actual archive/policy/header across both capture builds')
        need(r['seed_prerequisite']['status']=='passed','independent seed prerequisite remains separately mandatory')
        r['status']='passed'
    except BaseException as error:
        if r['error']is None:r['error']=type(error).__name__+': '+str(error)
    finally:
        try:
            for module in tuple(sys.modules.values()):
                path=getattr(module,'__file__',None)
                if path and Path(path).is_file():pin(path)
        except BaseException as error:
            r['final_errors'].append('final imported source closure: '+repr(error))
        for p in sorted(private.rglob('*')):
            if p.is_file() and not p.is_symlink():
                try:
                    binary(p)
                except BaseException as error:
                    r['final_errors'].append('partial artifact: ' + repr(error))
        for label, fn in (('build', builder.finish), ('closure', stable)):
            try:
                errors = fn()
                if errors:
                    r['final_errors'].extend(errors)
            except BaseException as error:
                r['final_errors'].append(label + ': ' + repr(error))
        try:
            r['source_after'] = source()
            need(r['source_after'] == r.get('source'), 'committed source unchanged')
        except BaseException as error:
            r['final_errors'].append('source: ' + repr(error))
        r['inputs'], r['aliases'], r['artifacts'] = pins, aliases, artifacts
        r['inputs_before']=dict(pins);r['aliases_before']=dict(aliases);r['artifacts_before']=dict(artifacts)
        r['inputs_after']={};r['artifacts_after']={};r['aliases_after']={}
        for table,observed,fn in(('inputs_after',pins,fact),('artifacts_after',artifacts,lambda p:dict(fact(p),mode=Path(p).stat().st_mode&0o777)),
                                  ('aliases_after',aliases,lambda p:str(Path(p).resolve(strict=True)))):
            for p in observed:
                try:r[table][p]=fn(p)
                except BaseException as error:r['final_errors'].append(table+' '+p+': '+type(error).__name__)
        r['source_unchanged'] = r.get('source') is not None and r.get('source_after') == r['source'] and \
            r['inputs_before']==r['inputs_after'] and r['aliases_before']==r['aliases_after']
        r['cleanup_complete'] = all(type(c.get('exit'))is int and c.get('reaped') is True and c.get('timed_out')is False and
            not c.get('error') and c.get('cleanup_errors')==[] and all(d['closed'] for d in c.get('descriptors', []))
            for c in r['commands'])
        if r['error'] or r['final_errors'] or not r['source_unchanged'] or r['artifacts_before']!=r['artifacts_after'] or not r['cleanup_complete']:
            r['status'] = 'failed'
        r['totals']=dict(planned=26 if args.native_hint else 23,hardware_planned=25 if args.native_hint else 22,metadata_qualified=int(r.get('linked_metadata',{}).get('status')=='passed'),launched=int(r.get('linked_metadata',{}).get('launched',False))+sum(c['launched']for c in r['cases']),qualified=int(r.get('linked_metadata',{}).get('status')=='passed')+sum(c['status'].startswith('qualified_')for c in r['cases']),
            native=sum(c['lane']=='native'and c['status'].startswith('qualified_')for c in r['cases']),
            gated=sum(c['lane']=='gated'and not c['control']and not c['refault_control']and not c.get('hint_control',0)and c['status'].startswith('qualified_')for c in r['cases']),
            owner_controls=sum(c['status']=='qualified_required_owner_refusal'for c in r['cases']),
            qualified_pairs=sum(c.get('pair',{}).get('qualified_pair',0)for c in r['cases']if c['status'].startswith('qualified_')),
            completed_applications=sum(c['status'].startswith('qualified_')and c['control']==c['refault_control']==0 and not c.get('hint_control',0)and c['mode']not in(2,3) for c in r['cases']),
            required_read_faults=sum(c['status']=='qualified_required_read_failure'for c in r['cases']),
            required_reference_faults=sum(c['status']=='qualified_native_reference'and c['mode']in(2,3) for c in r['cases']),
            required_owner_refusals=sum(c['status']=='qualified_required_owner_refusal'for c in r['cases']),
            application_reader_refusals=sum(len(c.get('application_controls',{}).get('refusals',[]))for c in r['cases']),
            terminal_reader_refusals=sum(len(c.get('terminal_controls',{}).get('refusals',[]))for c in r['cases']),
            owner_reader_refusals=sum(len(c.get('owner_reader_controls',{}).get('refusals',[]))for c in r['cases']),
            required_refault_refusals=sum(c['status']=='qualified_required_refault_refusal'for c in r['cases']),
            pair_reader_refusals=sum(len(c.get('pair_controls',{}).get('refusals',[]))for c in r['cases']),
            refault_reader_refusals=sum(len(c.get('refault_reader_controls',{}).get('refault_refusals',[]))for c in r['cases']),
            actual_refault_witnesses=sum(c['mode']==5 and not c['control']and not c['refault_control']and c['lane']=='gated'and c['status'].startswith('qualified_')and c.get('refault_witness',{}).get('native_closed')==1 for c in r['cases']))
        if args.native_hint:r['totals'].update(
            required_hint_rejections=sum(c['status']=='qualified_required_hint_rejection'for c in r['cases']),
            hint_owner_reader_refusals=sum(len(c.get('hint_reader_controls',{}).get('hint_refusals',[]))for c in r['cases']),
            hint_terminal_reader_refusals=sum(len(c.get('hint_terminal_controls',{}).get('hint_refusals',[]))for c in r['cases']),
            actual_hint_witnesses=sum(c['mode']==5 and c['lane']=='gated'and c['control']==c['refault_control']==c['hint_control']==0 and c['status'].startswith('qualified_')and c.get('hint_witness',{}).get('native_closed')==1 for c in r['cases']))
        save(private/'receipt.json',r)
        hw=dict(r['hardware']);flags=hw.pop('isa_flags');hw.update(isa_flags_count=len(flags),isa_flags_sha256=digest(flags))
        public={k:r.get(k)for k in('schema','profile','status','expected_revision','started_utc','cpu','source','source_unchanged','cleanup_complete','bounds','totals','namespace_controls')}
        public['seed_prerequisite']={k:v for k,v in r['seed_prerequisite'].items()if k in
            ('planned','status','launched','expected_exit','bounds','owner_subjects','completed_applications','performance_credit',
             'elf','exit','pid','whole_process_ns','timed_out','captures','profile')}
        public['linked_metadata']=public_metadata(r)
        public['cases']=[public_case(c)for c in r['cases']]
        public.update(hardware=hw,private_receipt=fact(private/'receipt.json'),
            reproduce=['python3','-B','evaluation/inprocess/linked_epoch.py','--expect-revision',args.expect_revision],
            input_manifest_sha256=digest(pins),artifact_manifest_sha256=digest(artifacts),command_count=len(r['commands']),commands_sha256=digest(r['commands']),
            failure_type=r['error'].split(':',1)[0]if r['error']else None,final_error_count=len(r['final_errors']),
            performance_credit=False,whole_ls_eligibility_credit=False,
            scope='Distinct finite linked epoch: six genuine native references and six full-state pairs, with two actual read faults, unsupported frontier continuation and real map/GS/rseq lifecycle changes; four required owner failures and four distinct actual helper refusals. Mode5 retains the actual unchanged TRACE-to-NX/native-close witness. Original metadata and completed65-key replacement are separate mandatory subjects. No whole-program or performance qualification')
        if args.native_hint:
            public['reproduce'].append('--native-hint')
            public['scope']='Distinct finite native-hint profile: all baseline23 subjects remain mandatory, including full original/reuse65 state and both actual relocation and GRAPH retry native-close witnesses. Three added actual advisory receipt corruptions return choose0 and invalidate before an explicit harness stop; these are not native-policy refusals. No whole-program or performance qualification'
        raw=csv_projection(public['cases'],public['linked_metadata'],native_hint=args.native_hint);public_csv=HERE/'results'/(stem+'.csv');public_json=HERE/'results'/(stem+'.json')
        need(len(raw)<=8192,'all actual compact outcome CSV rows')
        public['csv']=dict(file=public_csv.name,bytes=len(raw),sha256=H(raw))
        plain=json.loads(json.dumps(public,sort_keys=True,separators=(',',':'),allow_nan=False))
        public.update(columns.case_projection(plain['cases']));public=strings.project(public)
        restored=strings.restore(json.loads(json.dumps(public,sort_keys=True,separators=(',',':'),allow_nan=False)))
        restored['cases']=columns.expand_cases(restored)
        for key in('case_encoding','case_columns','case_subcolumns'):restored.pop(key)
        need(digest(restored)==digest(plain),'complete typed inverse of all public fields; no omitted outcome')
        uncompressed=json.dumps(plain,sort_keys=True,separators=(',',':'),allow_nan=False)
        encoded=json.dumps(public,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
        need(len(encoded.encode())<=32<<10 and not any(x and len(x)>1 and(x in encoded or x in uncompressed or x in raw.decode())for x in(str(ROOT),str(Path.home()),platform.node(),'/home/')),'compact public numerical result without private paths/host names')
        with public_csv.open('xb')as f:f.write(raw)
        with public_json.open('x')as f:f.write(encoded)
        print(json.dumps(dict(status=r['status'],result=str(public_json.relative_to(ROOT)),commands=len(r['commands']),failure_type=public['failure_type']),sort_keys=True))
    return 0 if r['status']=='passed'else 1

if __name__=='__main__':raise SystemExit(main())
