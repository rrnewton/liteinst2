"""Strict evidence for a separate original-PC canonical REP STOSQ owner."""
import json
import struct
import page_selected_generic_compare as generic

need=generic.need
MASK=(1<<64)-1
SCALARS=set('version status failure_code detail_abs detail_negative attempts completed traces queries route pending'.split())
ARRAYS={'request':8,'source0':6,'source1':6,'owner':7,'event':7,'progress':12,'frames':14,
        'io':17,'last_closed':17,'query':31,'previous_query':31,'release':4,'borrow':2}


def parse(data):
    lines=data.splitlines()
    need(len(lines) in (1,2) and all(len(x)+1<=4096 for x in lines),'one loader and at most one bounded REP report')
    base=generic.parse(lines[0]+b'\n')
    if len(lines)==1:return base,None
    need(lines[1].startswith(b'LI2_REPEAT '),'explicit separate REP report')
    r=json.loads(lines[1][11:],object_pairs_hook=generic.unique,
                 parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite REP value')))
    need(type(r) is dict and set(r)==SCALARS|set(ARRAYS),'exact REP schema')
    for k in SCALARS:need(type(r[k]) is int and 0<=r[k]<=MASK,'unsigned scalar '+k)
    for k,n in ARRAYS.items():
        need(type(r[k]) is list and len(r[k])==n and all(type(v) is int and 0<=v<=MASK for v in r[k]),'exact unsigned array '+k)
    need(r['version']==1 and r['attempts']>0 and r['completed']<=r['attempts'],'REP identity/counters')
    need(all(r[k]==base[k] for k in ('status','failure_code','detail_abs','detail_negative')) and
         r['route']==base['step_route'],'same terminal operation')
    return base,r


def request(r):
    pc,nxt,code,length,available,opcode,flags,pages=r['request']
    need(0<pc<=MASK-3 and nxt==pc+3 and code==346 and length==3 and 3<=available<=15 and
         opcode==0xab48f3 and flags&0x10100==0,'exact canonical original request')
    count=1 if pc//4096==(nxt-1)//4096 else 2
    need(pages==count,'exact source bundle')
    for i in range(count):
        p=r['source'+str(i)]
        need(p[0]==(pc&~4095)+4096*i and p[1]>0 and p[2]>0 and p[3]%4096==0 and p[4:]==[1,5],
             'authenticated source page identity')
    if count==1:need(r['source1']==[0]*6,'unused source descriptor stays zero')
    need(r['borrow'][0]>0,'retained genuine borrow identity')
    return pc,nxt,flags,(1<<count)-1


def closed_io(row,mask):
    need(row==[mask]*4+[0,0,1]+[0]*10,'complete exact open/revoke/sync I/O prefix')


def query(q,pc):
    need(q[:6]==[pc,1,1,1,0,0] and q[7:12]==[0]*5,'completed actual closed query')
    need(q[12]>0 and q[13]>0 and q[14:17]==[1,1,1],'complete real maps read/close')
    need(q[17]==pc&~4095 and q[18]>0 and q[19]>0 and q[20]%4096==0 and q[21:23]==[5,1],
         'original closed executable continuation page')
    need(q[24]==0 and q[25]&15==15 and q[26:29]==[0,0,0] and q[29:]==[1,1],
         'actual immutable backing seal/stat proof')


def completed(r):
    pc,nxt,flags,mask=request(r)
    n,remaining,traces,closed,reopened,final,post_pc,post_flags,started,complete,err,neg=r['progress']
    need(r['attempts']==r['completed']>0 and r['traces']>=traces>=1 and
         r['traces']>=r['completed'] and r['queries']==traces,'completed instruction and actual trace counts')
    if r['attempts']==1:need(r['traces']==traces,'single instruction owns every recorded trace')
    need((n==0 and traces==1) or (n>0 and traces<=n),'positive bounded hardware iteration progress')
    need([remaining,closed,reopened,final,post_pc,post_flags,started,complete,err,neg]==
         [0,traces,traces-1,1,nxt,flags|0x100,1,1,0,0],'full final original-PC progress')
    need(r['owner']==[5,0,0,0,0,1,0] and r['event']==[5,0,2,0,0,0,nxt],'genuine final TRACE')
    f=r['frames']
    need(f[:3]==[pc,flags|0x10000,n] and f[4]<(1<<47) and 512<=f[5]<=65536 and f[6]==f[5] and
         f[7:10]==[nxt,flags|0x100,0] and f[11:]==[f[4],f[5],f[5]],'actual before/final frame association')
    expected=(f[3]+(-8 if flags&0x400 else 8)*n)&MASK
    need(f[10]==expected,'literal final RDI progress')
    closed_io(r['io'],mask);closed_io(r['last_closed'],mask)
    query(r['query'],nxt)
    if traces==1:need(r['previous_query']==[0]*31,'no invented earlier query')
    else:query(r['previous_query'],pc)
    for q in (r['query'],r['previous_query']):
        if not q[1]:continue
        matches=[r['source'+str(i)] for i in range(r['request'][7]) if r['source'+str(i)][0]==q[17]]
        if matches:
            p=matches[0]
            need(q[17:23]==p[:4]+[p[5],p[4]],'query identity matches its actual retained source page')
    need(r['release']==[1,1,0,0] and r['borrow'][1]==0,'completed actual release after closed query')


def write_fault(r):
    pc,_,flags,mask=request(r)
    need(r['status']==125 and r['failure_code']==7 and r['detail_abs']==11 and r['detail_negative']==0 and
         r['attempts']==1 and r['completed']==r['traces']==r['queries']==0 and r['route']==3 and r['pending']==1,
         'real first-store fault, never completion')
    need(r['owner']==[6,7,11,0,1,0,1] and r['event'][:6]==[11,0,2,0,0,0], 'retained actual SIGSEGV ACCERR')
    need(r['progress']==[1,1]+[0]*10,'no invented successful iteration or query')
    f=r['frames']
    need(f[:3]==[pc,flags|0x10000,1] and f[3]==r['event'][6] and f[4]<(1<<47) and 512<=f[5]<=65536 and f[6]==f[5] and
         f[7:]==[pc,flags|0x10100,1,f[3],f[4],f[5],f[5]],'actual failing source/frame/address')
    closed_io(r['io'],mask)
    need(r['last_closed']==[0]*17 and r['query']==r['previous_query']==[0]*31 and
         r['release']==[0]*4 and r['borrow'][1]==1,'failure retains uncompleted protocol and held borrow')


def check(spec,base,r,command,stdout,native,image):
    need(r is not None,'REP programs must retain their own report')
    import hashlib
    need(hashlib.sha256(image).hexdigest()==spec['original_sha256'],'actual image binding')
    rows={v['name']:v for v in spec['rows']}
    need(len(rows)==len(spec['rows']) and len(set(spec['executed']))==len(spec['executed']),'unique actual instruction rows')
    for v in rows.values():
        code=bytes.fromhex(v['bytes']);off=4096+v['pc']-0x401000
        need(4096<=off<off+len(code)<=16384 and image[off:off+len(code)]==code,'exact original instruction bytes')
    reps=[rows[n] for n in spec['executed'] if rows[n]['route']=='repeat']
    need(len(reps)==len(spec['iterations']) and all(x['bytes']=='f348ab' for x in reps),'actual canonical requests')
    last=reps[-1]
    need(r['request'][:4]==[last['pc'],last['pc']+3,346,3] and
         r['progress'][0]==spec['iterations'][-1]['count'] and
         bool(r['request'][6]&0x400)==bool(spec['iterations'][-1]['df']) and
         r['frames'][3]==spec['iterations'][-1]['rdi'],'last original request/input association')
    names=['repeat_'+str(n)+'_df'+str(d) for n in (0,1,3) for d in (0,1)]+[
        'repeat_cross','repeat_next_page','repeat_reuse','repeat_write_fault']
    need(spec['name'] in names and spec['entry']==0x401000,'closed original program catalogue')
    name=spec['name'];fault=name=='repeat_write_fault';multi=name=='repeat_reuse'
    if name.startswith('repeat_') and '_df' in name:
        n,d=map(int,name.removeprefix('repeat_').split('_df'))
    else:n,d=(1,0) if fault else (3,int(name in ('repeat_next_page','repeat_reuse')))
    its=([{'count':0,'df':0,'rdi':0x600000}] if multi else [])+[{'count':n,'df':d,'rdi':0x600000+16*d}]
    need(spec['iterations']==its and spec['fault'] is fault,'literal count/direction/input catalogue')
    need(r['request'][6]&0x8d5==0x44,'defined CMP arithmetic flags survive REP exactly')
    need(rows['value']['bytes']=='48b88877665544332211','literal store value instruction')
    for j,it in enumerate(its):
        suffix=str(j)
        need(rows['count'+suffix]['bytes']==(b'\xb9'+struct.pack('<I',it['count'])).hex() and
             rows['destination'+suffix]['bytes']==(b'\xbf'+struct.pack('<I',it['rdi'])).hex() and
             rows['flags'+suffix]['bytes']==(bytes.fromhex('83f9')+bytes([it['count']])).hex() and
             rows['direction'+suffix]['bytes']==('fd' if it['df'] else 'fc'),'literal actual setup instructions')
    if name in ('repeat_cross','repeat_next_page'):
        want=0x401ffe if name=='repeat_cross' else 0x401ffd
        jump=rows['jump_repeat'];b=bytes.fromhex(jump['bytes'])
        need(last['pc']==want and b[:1]==b'\xe9' and len(b)==5 and
             jump['pc']+5+struct.unpack('<i',b[1:])[0]==want,'actual boundary REP control transfer')
    eh=struct.unpack_from('<16sHHIQQQIHHHHHH',image)
    need(eh[1:3]==(2,62) and eh[4]==0x401000 and eh[5]==64 and eh[9:11]==(56,7),'actual executable entry')
    ph=[struct.unpack_from('<IIQQQQQQ',image,64+i*56) for i in range(7)]
    need(ph[4]==(1,4 if fault else 6,16384,0x600000,0x600000,4096,4096,4096) and
         image[16384:]==b'\xa5'*4096,'actual data mapping and complete initial bytes')
    c=dict(old=4,generic=3,repeat=1,syscall=0,main=6) if fault else (
        dict(old=12,generic=11,repeat=2,syscall=2,main=25) if multi else
        dict(old=10,generic=10 if name in ('repeat_cross','repeat_next_page') else 9,repeat=1,syscall=2,
             main=21 if name in ('repeat_cross','repeat_next_page') else 20))
    need(spec['counters']==c,'independent literal instruction totals')
    need(base['selected_steps']==c['old'] and base['generic_tf_attempts']==base['generic_tf_steps']==c['generic'] and
         base['main_faults']==c['main'] and base['interpreter_faults']==2 and base['dependency_faults']==0 and
         base['nx_faults']==c['main']+2,'literal old/generic/REP instruction and fetch counts')
    # The completed generic owner is retained while the separately verified
    # REP fault owns route 3. Only that authenticated route field is projected.
    if spec['fault']:
        write_fault(r)
        generic.check_completed_owner(dict(base,step_route=0))
    else:generic.check_completed_owner(base)
    need(all(base[k]==0 for k in ('cpuid','rdtsc','rdtscp','rdrand','rdseed','rdpid','vdso_selected','tls_changes',
         'set_tid_address','set_robust_list','rseq','kernel_errors','partial_errors')),'no hidden providers or lifecycle changes')
    need(base['dependency_objects']==1 and base['mappings']==1 and base['generations']==7 and
         base['retired']==2 and base['live_pages']==5,'retained original pages and selftest retirement')
    if spec['fault']:
        write_fault(r)
        need(native['exit']==-11 and command['exit']==125 and stdout==native['stdout']==b'' and
             base['source_syscalls']==base['syscalls']==base['forwarded']==0,'native fault and gated terminal refusal')
        need(r['frames'][3]==0x600000,'literal read-only first-store address')
        return {'classification':'required_operand_fault','attempts':1,'completed':0,'traces':0}
    completed(r)
    need(r['progress'][2]==r['queries']==max(1,its[-1]['count']),'exact latest finite owner trace/query count')
    for q in (r['query'],r['previous_query']):
        if not q[1]:continue
        first=r['source0'];delta=q[17]-first[0]
        need(delta in (0,4096) and q[17:23]==[first[0]+delta,first[1],first[2]+delta//4096,first[3]+delta,5,1],
             'actual contiguous main-text query allocation/generation/offset identity')
    need(command['exit']==native['exit']==base['status']==base['failure_code']==base['detail_abs']==base['detail_negative']==0,
         'actual completed program')
    need(r['route']==r['pending']==0 and r['attempts']==r['completed']==len(spec['iterations']) and
         r['traces']==sum(max(1,x['count']) for x in spec['iterations']),'exact completed REP counters')
    need(base['source_syscalls']==base['syscalls']==base['forwarded']==2 and base['last_syscall']==60,'original write/exit')
    expected=bytearray(b'\xa5'*128)
    for it in spec['iterations']:
        for i in range(it['count']):
            at=it['rdi']-0x600000+(-8 if it['df'] else 8)*i
            need(0<=at<=120,'bounded literal stores')
            struct.pack_into('<Q',expected,at,0x1122334455667788)
    it=spec['iterations'][-1]
    struct.pack_into('<3Q',expected,64,0x1122334455667788,0,it['rdi']+(-8 if it['df'] else 8)*it['count'])
    need(stdout==native['stdout']==bytes(expected),'entire native/gated literal memory and register output')
    return {'classification':'completed','attempts':r['attempts'],'completed':r['completed'],'traces':r['traces']}
