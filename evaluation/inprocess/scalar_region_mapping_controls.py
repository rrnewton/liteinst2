"""Additive actual mapping refusals; no generated-owner or application credit.

The original40 owner subjects and their whole-state comparisons stay mandatory.
Each separate child must issue its declared request and fail in the existing
mapping guard. A returned request exits99 and cannot qualify.
"""
import hashlib,json,re,shlex,struct
from pathlib import Path
from page_selected import need,fact,elf,interpreter
from page_selected_register_time_build import recipe,expand
import scalar_region_app_reports as reports
import scalar_reuse_reports

CASES=(('write',1,10,3,0,0,155),('none',2,10,0,0,0,155),
       ('unmap',3,11,0,0,0,158),('replace',4,9,3,0x32,(1<<64)-1,144),
       ('write-only',5,10,2,0,0,155),('rwx',6,10,7,0,0,136),
       ('vdso-read',7,10,1,0,0,155),('vdso-exec',8,10,5,0,0,155))
ROOT=Path(__file__).resolve().parents[2]
PREFIX=14720
MAGIC=0x315044524155474c
H=lambda b:hashlib.sha256(b).hexdigest()


def check(out,err,record,exit_status,case,reader,layout,pid,cpu,seed_reference,parent):
    name,kind,number,prot,flags,fd,code=case
    need(exit_status==125 and type(out)is bytes and len(out)==PREFIX+80,
         'mapping request has exact failed outcome and complete prefix/request only')
    # This is a complete preparation prefix, not a fabricated owner control.
    app=reader._prefix(out[:PREFIX],0,False,layout,pid,cpu,seed_reference)
    request=struct.unpack_from('<10Q',out,PREFIX)
    need(type(record)is bytes and 576<=len(record)<=8<<20,'complete bounded actual protected capture')
    h=struct.unpack_from('<64Q',record);footer=struct.unpack_from('<8Q',record,len(record)-64)
    need(h[:3]==(0x31524f534c49324c,2,len(record)-64)and
         h[14]==h[18]==h[26]==1 and h[24]==h[25]==h[31]==h[32]==h[39]==h[53]==0 and
         h[27:30]==(125,code,7 if code==136 else 0) and
         footer[:4]==(0x314652534c49324c,2,h[2],h[2])and
         0<footer[4]<=64 and 0<footer[5]<=h[2]and footer[6:]==(125,code),
         'actual initialized protected capture has complete same-failure footer and no focal execution')
    need(4096<=h[56]<h[57]<(1<<47)and h[56]%4096==h[57]%4096==0 and
         h[57]-h[56]<=16*4096 and h[56]!=layout['page'],
         'independent runtime initialized exact bounded strict vDSO range')
    target=layout['page'] if kind<7 else h[56]
    need(request==(MAGIC,1,kind,number,target,4096,prot,flags,fd,0),
         'all ten actual request fields bind the declared source or strict vDSO target')
    scalar,reuse,suffix=scalar_reuse_reports.split(err)
    unrolled,suffix=reports.unrolled.split(suffix)
    view,original=reports.maps_view.split_report(suffix,'maintained')
    parsed=reports.old.reports(original);reports.old.extensions(parsed)
    _,same,gate=reports.old.gate(parsed,pid,125,parent,0)
    need(same is parsed and gate['application_completed']is False and gate['original_completed_rejected']is True,
         'mapping refusal cannot satisfy the original application completion gate')
    loader=parsed['loader'];effect=parsed['effect']
    need(all(row[k]==value for row in (scalar,reuse,unrolled,loader)
             for k,value in dict(status=125,failure_code=code,detail_abs=7 if code==136 else 0,detail_negative=0).items()),
         'all actual terminal streams retain the exact mapping refusal')
    need(loader['last_syscall']==number and loader['syscalls']==loader['forwarded']+1,
         'requested mapping syscall reached dispatch and did not return')
    need(all(effect[k]==v for k,v in dict(stage=4,busy=1,finished=0,kind=7,action=1,phase=4,
        callback_entered=0,callback_returned=0,native_entered=1,native_returned=0,exit_entered=0,
        post_guards_complete=0,post_callback_entered=0,post_callback_returned=0,committed=0,
        raw_entered=0,raw_returned=0,fp_after_initialized=0).items()),
        'actual intercepted mapping call failed before return, commit or guest continuation')
    need(scalar['active']==scalar['busy']==scalar['decoding']==0 and
         scalar['completed']==scalar['entries'] and
         scalar['events']==sum(scalar['signals'])and reuse['pending']==reuse['retiring']==0 and
         reuse['claims']==reuse['permits_issued']==scalar['completed'],
         'no scalar execution remains active at the mapping boundary')
    reports.prior_unrolled(unrolled)
    need(app['source_page_address']==layout['page'] and view['mismatches']==0,
         'same prepared page and no maintained-view mismatch')
    return dict(failure_code=code,syscall=number,request_sha256=H(out[PREFIX:]),
                completed_applications=0,generated_owner_credit=False)


def controls(checker,out,err,record):
    trials=[]
    for i in range(10):
        changed=bytearray(out);changed[PREFIX+8*i]^=1
        trials.append(('request-'+str(i),bytes(changed),err,record,125))
    trials.extend((('truncated',out[:-1],err,record,125),('appended',out+b'\0',err,record,125),
                   ('successful-exit',out,err,record,0)))
    lines=err.splitlines(keepends=True)
    for key in ('last_syscall','failure_code'):
        changed=list(lines);indices=[i for i,s in enumerate(lines)if s.startswith(b'LI2_LOADER ')]
        need(len(indices)==1,'one actual loader row for supplied control')
        index=indices[0];row=json.loads(lines[index].split(b' ',1)[1]);row[key]+=1
        changed[index]=b'LI2_LOADER '+json.dumps(row,separators=(',',':')).encode()+b'\n'
        trials.append((key,out,b''.join(changed),record,125))
    for name,offset in (('vdso-first',56*8),('vdso-end',57*8),('capture-failure',28*8),('capture-footer',len(record)-64)):
        changed=bytearray(record);changed[offset]^=1
        trials.append((name,out,err,bytes(changed),125))
    need(len(trials)==19,'all additive mapping-reader negative controls')
    for name,o,e,record_bytes,status in trials:
        rejected=False
        try:checker(o,e,record_bytes,status)
        except ValueError:rejected=True
        need(rejected,'mapping reader accepted supplied '+name)
    return 19


def run_controls(*,builder,private,pin,binary,run,r,reader,app_layout,seed_reference,
                 original,roots,objects,description,carrier,preparation,launcher):
    rows=[dict(name=case[0],status='unexecuted',launched=False,expected_exit=125,
               expected_failure=case[-1],completed_applications=0,generated_owner_credit=False)
          for case in CASES]
    state=r['mapping_controls']=dict(planned=8,status='failed',cases=rows)
    for spec,result in zip(CASES,rows,strict=True):
        name=spec[0];label='subject-mapping-'+name;directory=private/label;directory.mkdir()
        argv=[builder.tools['python'],'-B',launcher,'--root',ROOT,
              '--reuse','--role','gated','--mode','0','--control','0','--protection-test',name,
              '--original',original,'--preparation',directory/'preparation.json',
              '--carrier',carrier,'--namespace',directory/'namespace','--record-fd','{record_fd}']
        for p in roots:argv+=['--library-root',p]
        start=len(r['commands']);result['status']='failed'
        try:
            try:row,out,err=run(label,argv,profile='program',expected=125,record=True)
            finally:
                if len(r['commands'])>start and r['commands'][-1]['name']==label:
                    actual=r['commands'][-1]
                    result.update(launched=type(actual.get('pid'))is int,exit=actual.get('exit'),
                                  whole_process_ns=actual.get('duration_ns'),timed_out=actual.get('timed_out'))
            c=dict(lane='gated',mode=0,control=0,protection_test=name)
            preparation(c,row,directory,original,roots,objects,description,carrier,private,binary,r)
            prep=json.loads(binary(directory/'preparation.json').read_bytes())
            need(prep.get('protection_test')==name,'actual launcher selected this distinct mapping control')
            capture=row['captures']['record'];record_path=binary(private/capture['file'])
            need(fact(record_path)=={k:capture[k]for k in('bytes','sha256')},'same complete actual mapping capture')
            record=record_path.read_bytes()
            def checker(o,e,record_bytes,status):
                return check(o,e,record_bytes,status,spec,reader,app_layout,row['pid'],r['cpu'],seed_reference,
                             row['stdout_provenance_before'])
            result.update(checker(out,err,record,row['exit']))
            result['reader_refusals']=controls(checker,out,err,record)
            result['status']='qualified_mapping_refusal'
        except Exception as error:
            result['error_type']=type(error).__name__;result['error']=str(error)
            if r['error']is None:r['error']=type(error).__name__+': '+str(error)
            actual=r['commands'][start:]
            need(len(actual)==1 and actual[0]['name']==label and type(actual[0].get('exit'))is int and
                 actual[0].get('reaped')is True and not actual[0].get('error') and
                 actual[0].get('cleanup_errors')==[] and
                 all(d.get('closed')is True for d in actual[0].get('descriptors',[])),
                 'failed mapping child still requires complete command/descriptor cleanup')
    need(len(rows)==8 and all(c['status']=='qualified_mapping_refusal'and c['reader_refusals']==19 for c in rows),
         'all eight actual mapping refusals and all152 supplied reader controls remain required')
    state['status']='passed'


def public_summary(state):
    if state is None:return dict(planned=8,status='unexecuted',cases=[])
    keys=('name','status','launched','expected_exit','expected_failure','exit','whole_process_ns',
          'timed_out','failure_code','syscall','request_sha256','reader_refusals','error_type',
          'completed_applications','generated_owner_credit')
    return dict(planned=8,status=state['status'],cases=[{k:c[k]for k in keys if k in c}for c in state['cases']])


def guard_oracle(builder,private,pin,binary,run,r):
    """Compile and execute the production range predicate, not a model."""
    selected=ROOT/'tools/page-entry/selected';fixture=selected/'tests/initial_code_protection'
    script=pin(fixture/'build.sh');unit=pin(fixture/'oracle.c')
    rows=recipe(script,'"$cc_bin"');need(len(rows)==1,'one exact shared-predicate build recipe')
    output=private/'mapping-guard';output.mkdir()
    argv=expand(rows[0],{'$cc_bin':builder.tools['cc'],'$selected_dir':selected,
                         '$fixture_dir':fixture,'$output_dir':output})
    executable=output/'initial-code-protection'
    need(argv[-2:]==['-o',str(executable)] and [x for x in argv if x.endswith('.c')]==[str(unit)]and
         [x for x in argv if x.startswith('-D')]==['-DLI2_INITIAL_CODE_PROTECTION=1']and
         all(x in argv for x in('-std=c11','-O2','-g','-Wall','-Wextra','-Werror','-fno-builtin',
                               '-fno-tree-loop-distribute-patterns','-mgeneral-regs-only')),
         'exact production predicate release recipe and explicit capability')
    state=r['mapping_guard_oracle']=dict(status='failed',recipe=fact(script),argv=argv,
                                       native_owner_credit=False,performance_credit=False)
    flags=[x for x in argv[1:-2]if x!=str(unit)and not x.startswith('-Wl,')]
    _,out,err=run('mapping-guard-headers',[builder.tools['cc'],*flags,'-M','-MT','li2_guard',unit],env=builder.environment)
    lines=out.decode().replace('\\\n',' ').splitlines()
    need(not err and len(lines)==1 and lines[0].startswith('li2_guard: '),'one complete actual predicate include closure')
    includes={str(pin(name)):fact(pin(name))for name in shlex.split(lines[0].split(':',1)[1])}
    need({str(unit),str(selected/'initial_code_protection.h'),str(selected/'lifecycle_loader.h')}<=set(includes),
         'same actual shared production predicate and range ABI')
    state['headers']=includes
    run('mapping-guard-link',argv,profile='release_build',env=builder.environment)
    executable=binary(executable);data,head,segments=elf(executable)
    need(executable.stat().st_mode&0o111 and head[1]in(2,3)and head[2:4]==(62,1)and
         all(p[2]+p[5]<=len(data)and p[5]<=p[6]and p[1]&3!=3 for p in segments if p[0]==1),
         'complete actual predicate ELF without WX')
    loader=pin(interpreter(executable))
    _,out,err=run('mapping-guard-libraries',[loader,'--list',executable],profile='inspect',env=builder.environment)
    need(not err,'actual predicate library list');libraries={}
    for line in out.decode().splitlines():
        if re.fullmatch(r'\s*linux-vdso.so.1 \(0x[0-9a-f]+\)',line):continue
        match=re.fullmatch(r'\s*(?:\S+ => )?(/\S+) \(0x[0-9a-f]+\)',line)
        need(match is not None,'complete actual predicate resolved library')
        path=pin(match[1]);need(path.name not in libraries,'unique predicate library basename')
        libraries[path.name]=dict(path=str(path),**fact(path))
    need(any(v['path']==str(loader)for v in libraries.values()),'actual predicate interpreter in closure')
    state.update(artifact=fact(executable),runtime_libraries=libraries)
    row,out,err=run('mapping-guard-native',[executable],profile='mapping_guard',env=builder.environment)
    expected=dict(version=1,predicate_only=1,cases=754,allowed=273,refused=481,live_rseq=0,live_owner=0)
    need(not err and out==json.dumps(expected,separators=(',',':')).encode()+b'\n',
         'all754 literal shared-predicate cases, strict priority and whole input nonmutation')
    state.update(status='passed_predicate_only',result=expected,exit=row['exit'],
                 whole_process_ns=row['duration_ns'])
    return {k:state[k]for k in('status','artifact','result','exit','whole_process_ns',
                              'native_owner_credit','performance_credit')}
