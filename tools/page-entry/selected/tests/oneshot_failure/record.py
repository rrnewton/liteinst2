"""Pure complete-record reader. Layout comes from the retained ELF/DWARF."""
import hashlib,struct

def need(value,label):
    if not value:raise ValueError(label)

def expected(mode):
    need(type(mode)is int and 1<=mode<=49,'closed finite selector')
    cb=raw=ud=wrote=restored=published=transferred=0
    if mode<=8:
        cb=[3,4,4,6,6,8,9,9][mode-1];raw=mode;ud=int(mode>=4)
        wrote=int(mode>=2);restored=int(mode>=7);published=ud;transferred=1
    elif mode<=19:
        cb=mode-8;raw=[0,0,0,1,3,3,5,5,6,8,8][cb-1];ud=int(cb>=6)
        wrote=int(cb>=5);restored=int(cb>=10);published=ud;transferred=int(cb!=1)
    elif 31<=mode<=42:cb=5;raw=3;ud=wrote=published=transferred=1
    elif mode in(45,46):
        cb=5 if mode==45 else 11;raw=3 if mode==45 else 8
        ud=restored=int(mode==46);wrote=published=transferred=1
    elif mode>=48:cb=5;raw=3;wrote=transferred=1
    if mode<=8:error=1509 if mode in(3,5,8)else 1508
    elif mode<=19:error=[1506,1505,1511,1505,1505,1505,1505,1511,1505,1505,1513][mode-9]
    elif mode<=30:error=1504
    elif mode<=37:error=1510
    elif mode<=42:error=1504
    elif mode<=44:error=1566
    elif mode<=46:error=1512
    else:error=0 if mode==47 else 1505
    return dict(mode=mode,exit=0 if mode==47 else 125,owner_error=error,
        report_error=0 if mode==47 else 1566 if mode in(43,44)else 1573 if ud else 1571,
        callbacks=cb,raw_prefix=raw,raw=raw+2*transferred,ud=ud,wrote=wrote,restored_bytes=restored,
        published=published,transferred=transferred,cleanup=int(mode!=47),
        operation='refused_original_site'if mode==47 else 'failed',
        injection='genuine_kernel_einval'if mode<=8 else 'actual_backend_then_error'if mode<=19 else
                  'real_frame_negative_input'if mode<=42 else 'owner_state_or_geometry'if mode<=47 else
                  'actual_backend_error_and_genuine_cleanup_einval')

class View:
    def __init__(self,data,layout,name):
        self.data,self.layout,self.name=data,layout,name
        self.shape=layout['types'][name]
        need(len(data)==self.shape['bytes'],'complete '+name)
    def blob(self,name):
        f=self.shape['fields'][name];a,n=f['offset'],f['bytes']
        need(type(a)is int and type(n)is int and 0<=a<=len(self.data)and 0<n<=len(self.data)-a,'actual field extent')
        return self.data[a:a+n]
    def number(self,name,signed=False):
        b=self.blob(name);need(len(b)in(4,8),'actual integer width')
        return int.from_bytes(b,'little',signed=signed)
    def sub(self,name,kind):return View(self.blob(name),self.layout,kind)
    def array(self,name,kind):
        b=self.blob(name);n=self.layout['types'][kind]['bytes'];need(n and len(b)%n==0,'whole actual array')
        return [View(b[i:i+n],self.layout,kind)for i in range(0,len(b),n)]

def project_views(addresses,originals,expected,extents):
    """Project only explicitly expected changed bytes across authenticated aliases.

    Bytes outside initialized FP extent remain compared as retained zero storage.
    No byte is ignored, and no actual after-image supplies an expected value.
    """
    need(len(addresses)==len(originals)==len(expected)==len(extents)==3,'three complete actual frame views')
    for address,old,want,n in zip(addresses,originals,expected,extents):
        need(type(address)is int and type(n)is int and 0<address<1<<64 and 0<n<=len(old)==len(want)and
             address<=(1<<64)-1-n,'actual initialized frame view extent')
    for i in range(3):
        for j in range(i):
            first=max(addresses[i],addresses[j]);last=min(addresses[i]+extents[i],addresses[j]+extents[j])
            if first<last:
                need(originals[i][first-addresses[i]:last-addresses[i]]==
                     originals[j][first-addresses[j]:last-addresses[j]],'exact original bytes in actual overlapping views')
    edits={}
    for address,old,want,n in zip(addresses,originals,expected,extents):
        for offset,(a,b)in enumerate(zip(old[:n],want[:n])):
            if a!=b:
                at=address+offset
                need(at not in edits or edits[at]==b,'one consistent named physical edit')
                edits[at]=b
    need(len(edits)<=8,'one named scalar edit no wider than eight bytes')
    result=[bytearray(v)for v in expected]
    for address,want,n in zip(addresses,result,extents):
        for at,value in edits.items():
            if address<=at<address+n:want[at-address]=value
    return result

def read(data,layout,mode,pid,symbol_size):
    e=expected(mode);r=View(data,layout,'failure_record')
    need(len(data)==symbol_size and 0<symbol_size<16<<20,'actual ELF symbol/DWARF/record extent and fixed cap')
    for k,v in dict(magic=0x3146494f32494c,version=1,bytes=len(data),mode=mode,oracle_error=0,
        emitted=1,verified=1,pid=pid,tid=pid,initializations=1,raw_count=e['raw'],
        backend_count=e['callbacks'],ud_calls=e['ud'],nx_calls=int(mode not in(43,44)),
        injected=2 if mode>=48 else 1,cleanup=e['cleanup'],source_bytes=4096,
        source_before_observed=1,source_after_observed=1,data_before_observed=1,data_after_observed=1,
        backend_observed=1,source_protection_before=1,source_protection_after=5 if mode==48 else 1,
        fetch_busy_before=301,owner_result_observed=int(mode not in(43,44))).items():need(r.number(k)==v,'exact '+k)
    nx_result=1 if mode==47 else 0 if e['ud']or mode in(43,44,45)else 2
    ud_result=2 if e['ud']and mode!=46 else 0
    need(r.number('initialize_result',True)==(1503 if mode==43 else 0)and
         r.number('nx_result',True)==nx_result and r.number('ud_result',True)==ud_result and
         r.number('repeat_result',True)==(1503 if mode==44 else 2 if mode in(45,46)else 0),
         'actual returned entry results, distinct from sticky owner and controller errors')
    page,pc=r.number('source_page'),r.number('source_pc')
    need(pc==page and page>=8<<30 and page%4096==0 and r.number('data_address')==page+8192,'actual first-main page/data geometry')
    before,after=r.blob('source_before'),r.blob('source_after')
    need(len(before)==len(after)==4096 and before[:5]==bytes.fromhex('0f31909090'),'original literal RDTSC window')
    data_before,data_after=r.blob('data_before'),r.blob('data_after')
    need(len(data_before)==4096 and data_before==data_after and
         data_before[:328]==b'ONESHOT-READY!!\n'+bytes(312),'entire real application data page and literal initial prefix')
    o=r.sub('owner_after_cleanup','li2_oneshot_owner');state=o.sub('state','li2_oneshot_admission_state')
    need(o.number('initialized')==int(mode!=43),'actual successful initializer prefix')
    request=r.sub('request','li2_oneshot_plan')
    if mode in(43,44):need(not any(request.data),'no invented owner entry request')
    else:need(request.number('kind')==2 and request.number('pc')==pc and request.number('next_pc')==pc+2 and
              request.number('sequence')>0 and request.number('page_count')==1 and
              request.blob('original')==before[:5],'actual RDTSC request retained before negative input')
    for k,v in dict(first_error=e['owner_error'],phase=0 if mode==47 else 9,
                    published=e['published'],restored=int(mode==46)).items():need(state.number(k)==v,'actual owner '+k)
    for k,v in dict(transferred=e['transferred'],operations=e['raw'],
        write_completed_mask=31*e['wrote'],write_attempted_mask=31*e['wrote'],
        restore_completed_mask=31*e['restored_bytes'],restore_attempted_mask=31*e['restored_bytes']).items():
        need(o.number(k)==v,'owner actual write/operation prefix '+k)
    plan=o.sub('plan','li2_oneshot_plan');landing=plan.number('landing')
    want=bytearray(before)
    if e['wrote']:
        delta=landing-pc-5;need(-(1<<31)<=delta<1<<31,'actual rel32 reach')
        redirect=b'\xe9'+struct.pack('<i',delta)
        need(plan.blob('original')==before[:5]and plan.blob('redirect')==redirect,'literal original and actual E9')
        if not e['restored_bytes']:want[:5]=redirect
    need(bytes(want)==after,'every source byte exact for actual completed write prefix')
    # Cleanup may append only its actual two operation rows/count. It cannot
    # manufacture release, restoration, COMPLETE, or rewrite the first error.
    prior=r.sub('owner_before_cleanup','li2_oneshot_owner');wanted=bytearray(prior.data)
    for name in ('operations','operation'):
        f=o.shape['fields'][name];wanted[f['offset']:f['offset']+f['bytes']]=o.blob(name)
    need(bytes(wanted)==o.data,'all non-operation owner bytes unchanged by cleanup')
    raw=r.array('raw','failure_raw');ops=o.array('operation','li2_oneshot_operation')
    callbacks=r.array('backend','failure_backend')
    cb_kinds=[1,3,2,3,3,3,3,2,3,3,4]
    for i,b in enumerate(callbacks):
        if i>=e['callbacks']:need(not any(b.data),'unused backend row');continue
        inj=int(mode==i+9 or mode>=48 and i==4)
        for k,v in dict(number=i+1,kind=cb_kinds[i],started=1,returned=1,injected=inj,actual_result=0,
                        returned_result=-117 if inj else 0).items():need(b.number(k,k.endswith('result'))==v,'actual callback prefix '+k)
    kinds=[1,1,2,1,2,1,1,2];permissions=[3,5,0,1,0,3,1,0]
    for i,b in enumerate(raw):
        if i>=e['raw']:need(not any(b.data)and not any(ops[i].data),'unused operation row');continue
        cleanup=int(i>=e['raw_prefix']);kind=kinds[i]if not cleanup else 3+i-e['raw_prefix']
        perm=permissions[i]if not cleanup else 1 if kind==3 else 0
        number=10 if kind in(1,3)else 324
        inj=int(mode<=8 and i==mode-1 or mode==48 and kind==3 or mode==49 and kind==4)
        requested=[page if number==10 else 32,4096 if number==10 else 0,perm,0,0,0]
        issued=list(requested)
        if inj:issued[0]=page+1 if number==10 else 0x40000000
        for k,v in dict(number=i+1,cleanup=cleanup,started=1,returned=1,injected=inj,syscall_number=number,
                        result=-22 if inj else 0).items():need(b.number(k,k in('syscall_number','result'))==v,'genuine raw prefix '+k)
        need(list(struct.unpack('<6q',b.blob('requested')))==requested and
             list(struct.unpack('<6q',b.blob('issued')))==issued,'only named kernel arguments changed')
        call=ops[i].sub('call','li2_oneshot_call')
        need(ops[i].number('kind')==kind and ops[i].number('protection')==perm and not ops[i].number('page') and
             call.number('started')==call.number('returned')==1 and call.number('result',True)==(-22 if inj else 0),
             'actual owner operation joins gateway ledger')
        if cleanup:need(call.number('verified')==0,'cleanup is best effort, not verified closure')
    backend=r.sub('backend_after','li2_oneshot_lifecycle_progress')
    released=int(e['callbacks']==11);held=int(e['callbacks']>=1 and not released)
    need(backend.number('prepared')==1 and backend.number('held')==held and backend.number('released')==released and
         backend.number('first_error')==0 and backend.number('pid',True)==backend.number('tid',True)==pid and
         r.number('fetch_busy_after')==(0 if released else 301),'actual backend acquisition/release, including post-transfer error')
    events=r.array('event','failure_event');g=[];off=layout['offsets'];mask=((1<<64)-1)^sum(1<<(x-1)for x in(4,5,9,11,19,31))
    for lane,event in enumerate(events):
        received=int((lane==0 and mode not in(43,44))or lane==1 and e['ud'])
        need(event.number('received')==received,'actual event count')
        if not received:need(not any(event.data),'absent event entirely zero');continue
        need(event.number('authenticated')==event.number('after_observed')==1,'actual event authenticated and retained before return')
        si,uc=event.blob('original_si'),event.blob('original_uc');fp=event.blob('original_fp');n=event.number('fp_bytes')
        need(512<=n<=len(fp)and not any(fp[n:]),'complete kernel FP extent')
        if struct.unpack_from('<I',fp,464)[0]==0x46505853:
            need(struct.unpack_from('<I',fp,468)[0]==n and 576<=struct.unpack_from('<I',fp,480)[0]<=n-4 and
                 struct.unpack_from('<I',fp,n-4)[0]==0x46505845,'actual kernel xstate trailer')
        else:need(n==512,'actual legacy FP extent')
        greg=list(struct.unpack_from('<23Q',uc,off['greg']));g.append(greg)
        at=pc if lane==0 else landing;signal=11 if lane==0 else 4
        need(event.number('signal')==signal and struct.unpack_from('<i',si,off['si_signo'])[0]==signal and
             struct.unpack_from('<i',si,off['si_errno'])[0]==0 and struct.unpack_from('<i',si,off['si_code'])[0]==2 and
             struct.unpack_from('<Q',si,off['si_addr'])[0]==at and greg[16]==at and greg[20]==(14 if lane==0 else 6) and
             greg[19]==(21 if lane==0 else 0)and greg[22]==pc and greg[18]&65535==0x33 and
             greg[17]&(1<<16)and not greg[17]&256 and struct.unpack_from('<Q',uc,off['mask'])[0]==mask and
             struct.unpack_from('<Q',uc,off['fp_pointer'])[0]==event.number('fp_address'),'genuine NX or UD frame before named edit')
        want_si,want_uc,want_fp=bytearray(si),bytearray(uc),bytearray(fp)
        change=mode if (lane==0 and 20<=mode<=30)or(lane==1 and 31<=mode<=42)else 0
        if change in(20,31):struct.pack_into('<i',want_si,off['si_code'],0)
        if change in(21,32):struct.pack_into('<Q',want_si,off['si_addr'],at+1)
        index={22:16,23:22,24:20,25:19,26:18,28:17,29:17,33:16,34:20,35:19,38:22,39:17,40:13,41:18}.get(change)
        if index is not None:
            value=greg[index]
            if change in(22,23,33,38):value+=1
            elif change in(24,34):value=13
            elif change in(25,39,40):value^=1
            elif change in(26,41):value=(value&~65535)|0x23
            elif change==28:value|=256
            elif change==29:value&=~(1<<16)
            elif change==35:value=1
            struct.pack_into('<Q',want_uc,off['greg']+8*index,value)
        if change in(27,36):struct.pack_into('<Q',want_uc,off['mask'],mask^(1<<3))
        if change in(30,42):struct.pack_into('<Q',want_uc,off['fp_pointer'],event.number('fp_address')+1)
        if change==37:want_fp[160]^=1
        want_si,want_uc,want_fp=project_views(
            (event.number('si_address'),event.number('frame_address'),event.number('fp_address')),
            (si,uc,fp),(want_si,want_uc,want_fp),(len(si),len(uc),n))
        need(bytes(want_si)==event.blob('after_si')and bytes(want_uc)==event.blob('after_uc')and
             bytes(want_fp)==event.blob('after_fp'),'every frame/FP byte exact except the one named negative input')
    if len(g)==2:
        need(all(g[0][i]==g[1][i]for i in range(23)if i not in(16,19,20))and
             events[0].blob('original_fp')==events[1].blob('original_fp'),'actual NX-to-UD full preserved GREG/FP values')
    return dict(e,record_sha256=hashlib.sha256(data).hexdigest(),record_bytes=len(data),
        source_before_sha256=hashlib.sha256(before).hexdigest(),source_after_sha256=hashlib.sha256(after).hexdigest(),
        complete_data_page_equal=True,actual_events=len(g),actual_fp_bytes=[x.number('fp_bytes')for x in events if x.number('received')],
        real_backend_held=held,real_backend_released=released,source_protection_after=r.number('source_protection_after'))
