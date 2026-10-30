"""Same eight actual mapping refusals under the distinct certificate capture.

Original mapping request/state gates and152 supplied refusals remain. Every
actual v3 record also gets the same70-window bounded metadata observation and
a complete protected certificate validation; neither grants graph completion.
"""
import json,struct
from page_selected import need,fact
import scalar_region_mapping_controls as donor
import scalar_region_app_reports as reports
import scalar_reuse_certificate_reports as certificate_reports
CASES,ROOT,PREFIX,MAGIC,H=donor.CASES,donor.ROOT,donor.PREFIX,donor.MAGIC,donor.H
guard_oracle=donor.guard_oracle


def check(out,err,record,exit_status,case,reader,layout,pid,cpu,seed_reference,parent,owner_reader,owner_layout,image,boundaries):
    name,kind,number,prot,flags,fd,code=case
    need(exit_status==125 and type(out)is bytes and len(out)==PREFIX+80,
         'mapping request has exact failed outcome and complete prefix/request only')
    # This is a complete preparation prefix, not a fabricated owner control.
    app=reader._prefix(out[:PREFIX],0,False,layout,pid,cpu,seed_reference)
    request=struct.unpack_from('<10Q',out,PREFIX)
    need(type(record)is bytes and 576<=len(record)<16<<20,'complete bounded actual protected capture')
    h=struct.unpack_from('<64Q',record);footer=struct.unpack_from('<8Q',record,len(record)-64)
    need(h[:3]==(0x31524f534c49324c,3,len(record)-64)and
         h[14]==h[18]==h[26]==1 and h[24]==h[25]==h[31]==h[32]==h[39]==h[53]==0 and
         h[27:30]==(125,code,7 if code==136 else 0) and
         footer[:4]==(0x314652534c49324c,3,h[2],h[2])and
         0<footer[4]<=64 and 0<footer[5]<=h[2]and footer[6:]==(125,code),
         'actual initialized protected capture has complete same-failure footer and no focal execution')
    need(4096<=h[56]<h[57]<(1<<47)and h[56]%4096==h[57]%4096==0 and
         h[57]-h[56]<=16*4096 and h[56]!=layout['page'],
         'independent runtime initialized exact bounded strict vDSO range')
    target=layout['page'] if kind<7 else h[56]
    need(request==(MAGIC,1,kind,number,target,4096,prot,flags,fd,0),
         'all ten actual request fields bind the declared source or strict vDSO target')
    owner=owner_reader.mapping(record,owner_layout,image,app,pid,cpu,exit_status,code,boundaries=boundaries)
    scalar,reuse,certificate,suffix=certificate_reports.split(err)
    unrolled,suffix=reports.unrolled.split(suffix)
    view,original=reports.maps_view.split_report(suffix,'maintained')
    parsed=reports.old.reports(original);reports.old.extensions(parsed)
    _,same,gate=reports.old.gate(parsed,pid,125,parent,0)
    need(same is parsed and gate['application_completed']is False and gate['original_completed_rejected']is True,
         'mapping refusal cannot satisfy the original application completion gate')
    owner_reader.terminal(parsed,scalar,unrolled,owner,reuse,certificate)
    loader=parsed['loader'];effect=parsed['effect']
    need(all(row[k]==value for row in (scalar,reuse,certificate,unrolled,loader)
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
                 original,roots,objects,description,carrier,preparation,launcher,
                 boundary_probe,owner_reader,owner_layout,image_inventory,interp,bridge):
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
        start=len(r['commands']);expected_commands=[label];result['status']='failed'
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
            manifest=json.loads(binary(directory/'namespace'/'namespace.json').read_bytes())
            image=image_inventory(original,interp,carrier,objects,manifest)
            image['certificate_bridge']=bridge.read_bytes()
            image['certificate_binding']=r['release_build']['certificate_binding']
            image['certificate_headers']=r['release_build']['headers']
            request=owner_reader.boundary_requests(record,owner_layout)
            need(type(request)is bytes and 32<=len(request)<=2272,'bounded actual mapping boundary request')
            magic,version,count,width=struct.unpack_from('<4Q',request)
            need((magic,version,width)==(0x315152534c49324c,1,32)and count<=70 and len(request)==32+32*count,
                 'unchanged70-window mapping metadata request contract')
            request_path=private/(label+'-boundary-request.bin')
            with request_path.open('xb')as stream:stream.write(request)
            binary(request_path)
            observation=result['boundary_observation']=dict(requests=count,request_bytes=len(request),request_sha256=H(request))
            metadata_label='boundary-'+label;expected_commands.append(metadata_label)
            try:metadata,boundaries,metadata_err=run(metadata_label,[boundary_probe,request_path],profile='boundary',env=builder.environment)
            finally:
                if r['commands'][-1]['name']==metadata_label:
                    actual=r['commands'][-1];observation['exit']=actual.get('exit')
                    cap=actual.get('captures',{}).get('stdout')
                    if cap:observation.update(response_bytes=cap['bytes'],response_sha256=cap['sha256'])
            need(not metadata_err and 128<=len(boundaries)<=24208 and
                 struct.unpack_from('<4Q',boundaries)==(0x315352534c49324c,1,count,344)and
                 len(boundaries)==128+344*count,'complete same bounded actual mapping metadata response')
            def checker(o,e,record_bytes,status):
                return check(o,e,record_bytes,status,spec,reader,app_layout,row['pid'],r['cpu'],seed_reference,
                             row['stdout_provenance_before'],owner_reader,owner_layout,image,boundaries)
            result.update(checker(out,err,record,row['exit']))
            result['reader_refusals']=controls(checker,out,err,record)
            app=reader._prefix(out[:PREFIX],0,False,app_layout,row['pid'],r['cpu'],seed_reference)
            extra=owner_reader.mapping_controls(record,owner_layout,image,app,row['pid'],r['cpu'],
                                                row['exit'],spec[-1],boundaries=boundaries)
            need(type(extra)is dict and set(extra)=={'certificate_refusals','original_sha256','native_operations'},
                 'whole typed additional certificate mapping-control result')
            names=extra['certificate_refusals']
            need(type(names)is list and all(type(name)is str for name in names)and
                 len(names)==len(set(names))==23 and type(extra['native_operations'])is int and
                 extra['native_operations']==0 and extra['original_sha256']==H(record),
                 'all old20 plus three exact mapping-abort mutations are actually refused')
            result['certificate_controls']=extra
            result['status']='qualified_mapping_refusal'
        except Exception as error:
            result['error_type']=type(error).__name__;result['error']=str(error)
            if r['error']is None:r['error']=type(error).__name__+': '+str(error)
            actual=r['commands'][start:]
            need([c.get('name')for c in actual]==expected_commands and
                 all(type(c.get('exit'))is int and c.get('reaped')is True and not c.get('error') and
                     c.get('cleanup_errors')==[] and isinstance(c.get('descriptors'),list)and
                     all(d.get('closed')is True for d in c['descriptors'])for c in actual),
                 'failed mapping subject and its single bound metadata child require full cleanup')
    need(len(rows)==8 and all(c['status']=='qualified_mapping_refusal'and c['reader_refusals']==19 and len(c['certificate_controls']['certificate_refusals'])==23 and c['boundary_observation']['exit']==0 for c in rows),
         'all eight actual mapping refusals retain old152 plus184 additional certificate controls')
    state['status']='passed'
