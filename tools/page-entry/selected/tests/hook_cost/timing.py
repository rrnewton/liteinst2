"""Strict fixed timing record; no architectural comparator is replaced here."""
import hashlib,json,struct
MAGIC=0x315443484932494c
BYTES=2304
MASK=0xffffffffbffbfaef
BASE=0x200400000
ROUTES=('nx_faults','old_steps','generic_tf_steps','repeat_steps','native_attempts',
        'native_admissions','native_closed','native_blocked','native_low_refusals','run_plan_misses')
def need(ok,why):
    if not ok:raise ValueError(why)
def check(raw,layout,ref,profile,mode):
    need(type(raw)is bytes and len(raw)==BYTES and type(mode)is int and mode in(0,1),'whole actual timing record/mode')
    need(layout=={'hc_record':{'bytes':2304,'fields':{'h':{'offset':0,'bytes':256},'rows':{'offset':256,'bytes':1024},'calibration':{'offset':1280,'bytes':1024}}},
                 'hc_row':{'bytes':256,'fields':{'v':{'offset':0,'bytes':256}}}},'complete actual timing DWARF layout')
    h=struct.unpack_from('<32Q',raw);rows=ref['rows'];n=len(rows)
    need(2<=n<=4,'finite unchanged reference rows')
    adjacent=sum(a['after']['registers']['rip']==b['before']['registers']['rip']for a,b in zip(rows,rows[1:]))
    calls=128+5*n-adjacent
    need(h[:22]==(MAGIC,1,BYTES,mode,n,0,0,0,n,n,n,n,0,calls,calls,4,64,1,1,profile['cpu'],profile['node'],0),
         'complete timing process/clock/script prefix, no partial operation accepted')
    need(h[27]==h[28] and h[26]>=h[27]+h[29]+h[30],'actual native close/count prefix')
    routes=dict(zip(ROUTES,h[22:]))
    calibration=[struct.unpack_from('<2Q',raw,1280+16*i)for i in range(64)]
    need(all(0<a<=b for a,b in calibration)and all(a[1]<=b[0]for a,b in zip(calibration,calibration[1:])),
         'all actual monotonic calibration pairs; zero deltas retained')
    result=[];prior=calibration[-1][1]
    for i,r in enumerate(rows):
        v=struct.unpack_from('<32Q',raw,256+256*i);before=r['before']['registers'];after=r['after']['registers']
        pc,nxt,flags=before['rip'],after['rip'],after['eflags']
        need(v[:5]==(5,i,r['kind'],pc,nxt)and v[10:21]==(1,1,1,0,11,2,14,21,nxt,flags|0x10000,MASK)and
             v[22]==1 and 1<=v[23]<=15 and nxt<=v[21]<nxt+v[23]and
             v[24:]==(flags,i+1,i+1,i+1,0,0,0,0),'actual typed effect and authenticated immediate successor NX')
        enter,cb0,cb1,leave,next_entry=v[5:10]
        need(0<prior<=enter<=cb0<=cb1<=leave<=next_entry,'ordered actual executable timing boundaries')
        if i and rows[i-1]['after']['registers']['rip']==pc:
            need(enter==result[-1]['timestamps_ns'][-1],'one shared timestamp for adjacent selected effects')
        need(BASE<=pc<BASE+5*4096 and BASE<=nxt<BASE+5*4096,'fixed actual reference address domain')
        service=leave-enter;tail=next_entry-leave;cycle=next_entry-enter
        need(service+tail==cycle,'exact service/refault decomposition')
        result.append(dict(ordinal=i,kind=r['kind'],pc_offset=pc-BASE,next_offset=nxt-BASE,
            timestamps_ns=list(v[5:10]),checked_callback_ns=cb1-cb0,handler_service_ns=service,
            return_and_refault_ns=tail,nx_service_refault_cycle_ns=cycle))
        prior=next_entry
    need(not any(raw[256+256*n:1280]),'every unused timing slot byte remains zero')
    return dict(mode=mode,completed=n,rows=result,calibration_ns=[[a,b]for a,b in calibration],
                record_bytes=BYTES,record_sha256=hashlib.sha256(raw).hexdigest(),timer_calls=calls,
                cpu=profile['cpu'],node=profile['node'],clock_id=4,route_counts=routes,subtracted_timer_overhead=False)

def summary(receipt):
    cases=receipt.get('hook_cost_measurements',[]);commands=receipt.get('commands',[])
    actual=closed=accepted=0;public=[];keys=set();pids=set();totals={0:0,1:0};by_kind={i:[]for i in range(1,8)}
    columns=('index','phase','round','actual','closed','accepted','record_sha256','timer_calls','route_counts','calibration','rows')
    for c in cases:
        identity=(c['index'],c['phase'],c['round']);need(identity not in keys,'unique timing sample identity');keys.add(identity)
        need(type(c['index'])is int and 0<=c['index']<5 and c['phase']in('warmup','measure')and
             type(c['round'])is int and 0<=c['round']<(3 if c['phase']=='warmup'else 10),'fixed timing inventory identity')
        names=[x for x in commands if x['name']==c.get('command')];need(len(names)<=1,'unique actual timing command')
        row=names[0]if names else {};started=type(row.get('pid'))is int and row['pid']>0
        if started:need(row['pid']not in pids,'distinct actual timing child PID');pids.add(row['pid'])
        terminal=started and type(row.get('exit'))is int and row.get('reaped')is True and row.get('timed_out')is False and not row.get('error')and row.get('cleanup_errors')==[]
        ok=terminal and row['exit']==0 and c.get('status')=='passed'and type(c.get('comparison'))is dict
        actual+=started;closed+=terminal;accepted+=ok
        out=dict(index=c['index'],phase=c['phase'],round=c['round'],actual=started,closed=terminal,accepted=ok)
        if ok:
            cmp=c['comparison'];need(cmp['mode']==1,'actual measurement-mode comparison')
            calibration=cmp['calibration_ns'];deltas=[b-a for a,b in calibration]
            out['record_sha256']=cmp['record_sha256'];out['timer_calls']=cmp['timer_calls']
            out['route_counts']=[cmp['route_counts'][k]for k in ROUTES]
            out['calibration']=dict(count=len(calibration),min_ns=min(deltas),max_ns=max(deltas),
                sha256=hashlib.sha256(json.dumps(calibration,separators=(',',':')).encode()).hexdigest())
            out['rows']=[[s['ordinal'],s['kind'],s['pc_offset'],s['next_offset'],*s['timestamps_ns']]for s in cmp['rows']]
            totals[c['phase']=='measure']+=cmp['completed']
            if c['phase']=='measure':
                for sample in cmp['rows']:by_kind[sample['kind']].append(sample)
        public.append([out.get(k)for k in columns])
    passed=receipt.get('status')=='passed'
    expected={(i,p,j)for i in range(5)for p,n in(('warmup',3),('measure',10))for j in range(n)}
    if passed:
        need(keys==expected and actual==closed==accepted==65 and totals=={0:51,1:170},'all exact actual timing processes and denominators')
        need([len(by_kind[i])for i in range(1,8)]==[20,20,40,30,40,10,10],'all seven measured class denominators')
    qualification=receipt.get('hook_cost_qualification',{});qualified=[]
    for c in qualification.get('cases',[]):
        matched=[x for x in commands if x['name']==c.get('command')]
        row=matched[0]if len(matched)==1 else {}
        ok=(type(row.get('pid'))is int and row['pid']>0 and type(row.get('exit'))is int and row['exit']==0 and
            row.get('reaped')is True and row.get('timed_out')is False and not row.get('error')and
            row.get('cleanup_errors')==[] and c.get('status')=='passed')
        qualified.append(dict(index=c['index'],accepted=ok,bridge=c.get('bridge'),carrier=c.get('carrier'),
            selected_callbacks=c.get('comparison',{}).get('selected_callbacks')))
    if passed:need(qualification.get('status')=='passed'and [c['index']for c in qualified]==list(range(5))and
                   all(c['accepted']for c in qualified)and sum(c['selected_callbacks']for c in qualified)==17,
                   'five actual same-ELF complete full-state qualification processes')
    metrics=('checked_callback_ns','handler_service_ns','return_and_refault_ns','nx_service_refault_cycle_ns')
    classes={}
    for kind,samples in by_kind.items():
        if samples:
            classes[str(kind)]=dict(count=len(samples),**{m:dict(min_ns=min(x[m]for x in samples),max_ns=max(x[m]for x in samples),
                twice_median_ns=sum(sorted(x[m]for x in samples)[(len(samples)-1)//2:len(samples)//2+1])*(2 if len(samples)%2 else 1))for m in metrics})
    return dict(scope='instrumented_fixture_C_NX_service_and_immediate_refault',qualified=passed,planned_processes=65,
                attempted_cases=len(cases),actual_processes=actual,closed_processes=closed,accepted_processes=accepted,
                warmup_callbacks=totals[0],measured_callbacks=totals[1],sample_columns=columns,samples=public,classes=classes,
                row_columns=('ordinal','kind','pc_offset','next_offset','enter_ns','callback_enter_ns','callback_return_ns','leave_ns','next_entry_ns'),
                route_columns=ROUTES,class_aggregation='distinct_fixture_sites_and_processes',
                qualification=qualified,
                no_retry=True,no_outlier_removal=True,no_overhead_subtraction=True,
                bare_instruction_cost=False,one_shot_cost=False,nonreturning_exit_cost=False,
                production_named_policy=False,full_b2_completion=False)
