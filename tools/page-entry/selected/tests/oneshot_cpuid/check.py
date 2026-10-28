"""Real CPUID frames joined to original restored owner bytes; no process runs."""
import hashlib,struct
from page_selected import need
MAIN,DATA=0x200401000,0x200420000
GREG=(13,14,12,11,15,10,9,8,0,1,2,3,4,5,6,7)
U64=(1<<64)-1
Q=lambda b:struct.unpack('<'+'Q'*(len(b)//8),b)
W=lambda b,o:struct.unpack_from('<Q',b,o)[0]
VECTOR=bytes(1+(r*17+i*13)%255 for r in range(32)for i in range(64))
MASK=b''.join(struct.pack('<Q',0x1020304050607080+r*0x0101010101010101)for r in range(8))

def image(data,interpreter,geometry,native_policy):
    need(type(data)is bytes and type(geometry)is int and geometry in(0,1),'literal finite geometry')
    h=struct.unpack_from('<16sHHIQQQIHHHHHH',data)
    need(h[0][:7]==b'\x7fELF\2\1\1'and h[1:4]==(2,62,1)and h[4]==MAIN and h[8:10]==(64,56)and h[11]==64,'actual high fixed main')
    def extent(a,n):need(0<=a<=len(data)and 0<=n<=len(data)-a,'actual full file extent');return data[a:a+n]
    ph=[struct.unpack('<IIQQQQQQ',extent(h[5]+56*i,56))for i in range(h[10])];loads=[p for p in ph if p[0]==1]
    need(len(loads)==3 and [p[1]for p in loads]==[4,5,6]and loads[0][2:4]==(0,MAIN-4096)and loads[0][5]<=4096 and
         loads[1][2:4]==(4096,MAIN)and loads[1][5:7]==(65536,65536)and loads[2][3]==DATA and loads[2][5]>=32768 and
         all(p[7]==4096 and p[5]<=p[6]for p in loads)and not any(p[0]==7 for p in ph),'exact R/RX/RW geometry and no TLS')
    ip=[p for p in ph if p[0]==3]
    need(len(ip)==1 and extent(ip[0][2],ip[0][5])==str(interpreter).encode()+b'\0','actual lexical PT_INTERP')
    ss=[struct.unpack('<IIQQQQIIQQ',extent(h[6]+64*i,64))for i in range(h[12])]
    need(not any(s[1]in(4,9)and s[5]for s in ss),'no runtime relocations')
    tables=[s for s in ss if s[1]==2];need(len(tables)==1 and tables[0][9]==24,'actual symbol table')
    t=tables[0];strings=ss[t[6]];names=extent(strings[4],strings[5]);symbols={}
    for at in range(t[4],t[4]+t[5],24):
        n,info,other,index,value,size=struct.unpack('<IBBHQQ',extent(at,24))
        if n:
            name=names[n:names.index(b'\0',n)].decode();need(name not in symbols,'unique symbol');symbols[name]=value
    def read(a,n):
        p=next((p for p in loads if p[3]<=a and a+n<=p[3]+p[5]),None)
        need(p is not None,'actual mapped file extent');return extent(p[2]+a-p[3],n)
    sites=[symbols['oc_site'+str(i)]for i in range(9)];pcs=[symbols['oc_cpuid'+str(i)]for i in range(9)]
    need(read(MAIN,2)==b'\x0f\xa2'and symbols['pl_seed']==MAIN+4096 and native_policy(read(MAIN+4096-14,4096+28))==0,
         'actual first-main CPUID and complete qualified native helper/halos')
    for i,(pc,npc)in enumerate(zip(sites,pcs,strict=True)):
        need(npc==pc+2 and read(pc,5)==bytes.fromhex('0f050fa290'if i%2 else'0f310fa290')and
             read(pc+5,1)==b'\xe9'and pc+10+struct.unpack('<i',read(pc+6,4))[0]==symbols['pl_capture'],
             'exact selected/PC+2 CPUID/NOP/JMP stream '+str(i))
    need((sites[0]%4096,sites[1]%4096)==((32,64)if not geometry else(4093,4092))and
         all(pc%4096<=4091 for pc in sites[2:]),'exact aligned or cross-page five-byte windows')
    need(symbols['pl_data']==DATA and symbols['pl_data_end']==DATA+32768 and symbols['pl_stack_top']==DATA+32704 and
         symbols['nx_output']==DATA+7680 and read(DATA+512,2112)==VECTOR+MASK and Q(read(DATA,16))==(0x31584e4449555043,geometry),
         'complete literal data, stack and independent SIMD seed')
    interp=interpreter.read_bytes();ih=struct.unpack_from('<16sHHIQQQIHHHHHH',interp)
    first=bytes.fromhex('0fa248b8')+struct.pack('<Q',MAIN)+bytes.fromhex('ffe0')
    iph=[struct.unpack_from('<IIQQQQQQ',interp,ih[5]+56*i)for i in range(ih[10])];iloads=[p for p in iph if p[0]==1]
    need(len(interp)==8192 and ih[1:4]==(3,62,1)and ih[4]==4096 and interp[4096:4096+len(first)]==first and not any(interp[4096+len(first):])and
         [(p[1],p[2],p[3],p[5],p[6])for p in iloads]==[(4,0,0,4096,4096),(5,4096,4096,4096,4096)],'actual literal instruction-one interpreter CPUID')
    def im(b,entry,ls):return dict(data=b,entry=entry,loads=ls,bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
    return dict(geometry=geometry,sites=sites,pcs=pcs,symbols=symbols,source=read(MAIN,65536).hex(),initial_data=read(DATA,32768).hex(),
                images={1:im(data,MAIN,loads),2:im(interp,4096,iloads)})

def seeded(image,slot):
    g=[0x1122334455667700+i for i in range(16)];g[4]=DATA+32704;g[0]=0xa501020300000001;g[1]=0xb608090a00000000
    if slot%2:g[0]=1;g[7]=1;g[6]=image['sites'][slot];g[2]=5
    return g,0xed7

def output(data,image):
    need(type(data)is bytes and len(data)==20+21248,'all four source writes and nine full live captures')
    need(data[:20]==b''.join(bytes.fromhex('0f050fa290')for _ in range(4)),'actual source-reading writes see original restored five bytes')
    data=data[20:];need(Q(data[:16])==(0x3154554f584e5043,image['geometry'])and data[16:512]==bytes(496),'complete literal output header')
    slots=[]
    for i in range(9):
        b=data[512+2304*i:512+2304*(i+1)];g,flags=seeded(image,i);actual=Q(b[2112:2240])
        if i%2:g[11]=flags
        need(b[:2112]==VECTOR+MASK and b[2260:]==bytes(44)and all(actual[j]<1<<32 for j in(0,1,2,3))and
             all(actual[j]==g[j]for j in range(16)if j not in(0,1,2,3))and W(b,2240)==flags and
             struct.unpack_from('<6H',b,2248)==(0x33,0x2b,0,0,0,0),'complete actual live vectors/masks/nonoutputs/full flags/selectors '+str(i))
        slots.append(b)
    return slots

def data_state(image,slots,slot,completed=False):
    expected=bytearray.fromhex(image['initial_data'])
    for j in range(slot+1):
        g,flags=seeded(image,j)
        values={16:image['sites'][j],24:image['symbols']['setup'+str(j+1)]if j<8 else image['symbols']['oc_finish'],
                32:g[0],40:g[1],48:j,64:g[2],72:g[6],80:g[7],32704-8:flags}
        for at,value in values.items():struct.pack_into('<Q',expected,at,value)
        if j<slot or completed:
            expected[4096:4096+2304]=slots[j]
            expected[7680+512+j*2304:7680+512+(j+1)*2304]=slots[j]
    return bytes(expected)

def compare(native,gated,image):
    a,b=output(native,image),output(gated,image)
    for i,(left,right)in enumerate(zip(a,b,strict=True)):
        if i%2:need(left==right,'same actual syscall return5 and identical CPUID inputs/full live output')
        else:
            # These two RDTSC values are independent. Only CPUID's four defined
            # outputs can consequently differ; every other retained byte is exact.
            need(left[:2112]==right[:2112]and left[2144:]==right[2144:],'clock-derived CPUID: every non-output live byte exact')
    return dict(live_captures=9,source_reading_writes=4,same_input_cpuid_captures=4,clock_derived_cpuid_captures=5,bytes=len(gated))

def owners(data,layout,image,pid,old_record,oi,main_backing_bytes):
    images=image['images'];q,read,call,frame,changed,owner_frame,maps,backing=(getattr(oi,n)for n in('q','read','call','frame','changed','owner_frame','maps','backing'));MASK=oi.MASK
    V=old_record.View;r=V(data,layout,'oi_record');h=q(r.blob('h'))
    need(h[:6]==(0x31504c49534f324c,1,len(data),layout['uc_bytes'],layout['si_bytes'],1)and
         len(data)<16<<20 and h[6:9]==(0,0,0)and h[9]==8 and h[10]==h[11]==0 and
         h[18:20]==(pid,pid)and h[23:25]==(0,1)and not any(h[25:]),'complete successful finite terminal and actual PID')
    biases={1:h[12],2:h[15]};need(h[13]==h[12]+images[1]['entry']and h[16]==h[15]+images[2]['entry']and
         h[14]==images[1]['bytes']and h[17]==images[2]['bytes']and biases[1]==0 and biases[2]>0 and not biases[2]&4095,'actual initial image biases/entries/source extents')
    symbols=layout['symbols'];need(h[22]>0 and h[22]%4096==0 and h[20]==h[22]+symbols['selected_oneshot_owners']and
         h[21]==h[22]+symbols['selected_session'],'actual bridge ELF owner/session addresses')
    rows=r.array('owners','oi_owner');need(len(rows)==8,'fixed eight-owner record')
    contexts=set()
    result=[];published=restored=returned=started=clock=syscalls=0;required_clock=None
    for index,row in enumerate(rows):
        if index>=h[9]:need(not any(row.data),'every unused owner byte zero');continue
        a=q(row.blob('h'));request=row.sub('request','li2_oneshot_plan');o=row.sub('owner','li2_oneshot_owner');p=o.sub('plan','li2_oneshot_plan');state=o.sub('state','li2_oneshot_admission_state')
        need(a[0:2]==(1,index)and a[2]in(1,2)and a[3]==biases[a[2]]and a[5]==a[12]==1 and a[31]==0,'ordered actual attempt and source image')
        need(p.number('abi_version')==1 and p.number('sequence')==index+1 and p.number('kind')in(1,2)and p.number('reserved')==0 and not any(p.blob('reserved_bytes')),'closed actual plan')
        pc,npc,kind=p.number('pc'),p.number('next_pc'),p.number('kind');count=p.number('page_count');need(npc==pc+2 and count in(1,2)and count==1+int((pc&4095)>4091),'exact five-byte publication page count')
        need(p.blob('original')==read(images[a[2]],pc-a[3],5)and p.blob('original')[:2]==bytes.fromhex('0f05'if kind==1 else'0f31'),'actual original file-backed selected bytes')
        want_request=bytearray(p.data);f=p.shape['fields']['redirect'];want_request[f['offset']:f['offset']+f['bytes']]=bytes(5)
        need(bytes(want_request)==request.data,'exact backend request before planner constructs redirect')
        landing=p.number('landing');need(p.blob('redirect')==b'\xe9'+struct.pack('<i',landing-pc-5)and
             p.number('landing_allocation')==a[2]and p.number('landing_generation')==1,'literal rel32 and actual per-image landing registry')
        events=row.array('frames','oi_frame');need(len(events)==5,'five fixed actual event stages')
        nx,nxa=frame(events[0],layout),frame(events[1],layout);changed(nx,nxa,layout,{})
        need(nx['h'][1]==11 and nx['addr']==nx['g'][16]==nx['g'][22]==pc and nx['g'][19:21]==[21,14]and
             nx['g'][18]&65535==0x33 and nx['g'][17]&0x10000 and not nx['g'][17]&0x100 and a[4]==nx['g'][17]&~0x10000,'real original first-byte NX and logical flags')
        owner_frame(o.sub('before','li2_step_frame'),nx)
        need(o.number('initialized')==1 and o.number('session')==h[21]and not o.number('in_handler')and
             state.number('first_error')==state.number('first_detail',True)==0,'old initialized owner/session and no errors')
        hooks=o.sub('hooks','li2_oneshot_hooks');context=hooks.number('context')
        need(context>0 and context not in contexts,'distinct actual retained backend context');contexts.add(context)
        for field,symbol in dict(raw='raw',frame_range='selected_oneshot_frame_range',transfer='li2_lifecycle_oneshot_transfer',
                                advance_generation='li2_lifecycle_oneshot_advance',observe='li2_lifecycle_oneshot_observe',release='li2_lifecycle_oneshot_release').items():
            need(hooks.number(field)==h[22]+symbols[symbol],'actual retained ELF callback address '+field)
        backend=row.sub('backend','li2_oneshot_lifecycle_progress')
        need(backend.number('prepared')==1 and backend.number('pid',True)==backend.number('tid',True)==pid and
             backend.number('sequence')==index+1 and backend.number('first_error')==backend.number('first_detail',True)==0,'actual lifecycle owner identity')
        if a[6]in(1,3):
            need(a[7:12]==(0,0,0,0,0)and not any(a[13:])and all(not any(x.data)for x in events[2:])and
                 state.number('phase')==state.number('published')==state.number('restored')==0 and
                 o.number('transferred')==o.number('source_copied')==o.number('operations')==o.number('observations')==0 and
                 not any(row.blob('published')+row.blob('restored')+o.blob('original_pages')),'actual clean refusal never claimed publication')
            t=o.sub('transfer','li2_oneshot_transfer');call(t.sub('call','li2_oneshot_call'),1 if a[6]==1 else 2)
            need(t.number('old_authenticated')==1 and t.number('transaction_live')==0 and t.number('old_borrow_live')==int(a[6]==1),'exact clean transfer prefix')
            if a[6]==1:need(not any(t.blob('old_release')+t.blob('acquire')),'untouched borrow no release/acquisition')
            else:call(t.sub('old_release','li2_oneshot_call'));need(not any(t.blob('acquire')),'released clean refusal no acquisition')
            result.append(dict(sequence=index+1,image=a[2],file_offset=pc-a[3],kind=kind,published=0,returned=0));continue
        need(a[6]==a[9]==0 and a[7:9]==(1,1)and a[10]==1 and a[11]in(0,1),'real publication, landing and effect prefixes')
        ud,udr=frame(events[2],layout),frame(events[3],layout);changed(ud,udr,layout,{})
        need(ud['h'][1]==4 and ud['addr']==ud['g'][16]==landing and ud['g'][19:21]==[0,6]and ud['fp']==nx['fp'],'real UD landing and complete FP conservation')
        expected=list(nx['g']);expected[16]=landing;expected[19]=0;expected[20]=6
        need(ud['g']==expected and ud['h'][8:10]==nx['h'][8:10],'all23 GPR/flags/selector fields match exact publisher changes')
        owner_frame(o.sub('after','li2_step_frame'),ud)
        need(o.number('landing_frame')==ud['h'][3],'actual restored landing frame identity')
        need(state.number('phase')==(8 if a[11]else 7)and state.number('published')==state.number('restored')==1 and
             state.number('sequence')==index+1 and state.number('mutation_started')==1 and state.number('reserved')==0,'honest completed versus restored terminal owner')
        for name in('transferred','landing_observed','source_write_started','restore_started'):need(o.number(name)==1,'actual owner '+name)
        need(o.number('source_copied')==count,'all actual source pages copied')
        for name in('write_attempted_mask','write_completed_mask','restore_attempted_mask','restore_completed_mask'):need(o.number(name)==31,'all five actual source writes '+name)
        pages=p.array('pages','li2_oneshot_page');original=o.blob('original_pages')
        for j,page in enumerate(pages):
            if j>=count:need(not any(page.data)and not any(original[j*4096:(j+1)*4096]),'unused complete source page');continue
            need(page.number('address')==(pc&~4095)+j*4096 and page.number('allocation')>0 and page.number('generation')>0,'actual source page identity')
            offset=page.number('offset');part=original[j*4096:(j+1)*4096]
            need(offset+4096<=len(images[a[2]]['data'])and part==images[a[2]]['data'][offset:offset+4096]and
                 read(images[a[2]],page.number('address')-a[3],4096)==part,'entire sealed file page and executable mapping identity')
        expected=bytearray(original);expected[pc&4095:(pc&4095)+5]=p.blob('redirect')
        need(row.blob('published')==bytes(expected)and row.blob('restored')==original,'all published and restored page bytes')
        t=o.sub('transfer','li2_oneshot_transfer')
        for n in('call','old_release','acquire'):call(t.sub(n,'li2_oneshot_call'))
        need(t.number('old_authenticated')==t.number('transaction_live')==1 and t.number('old_borrow_live')==t.number('reserved')==0,'exact transfer ownership')
        generations=[tuple(page.number('generation')for page in pages)]
        for j,v in enumerate(o.array('generation','li2_oneshot_generation')):
            call(v.sub('call','li2_oneshot_call'));before,after=q(v.blob('before')),q(v.blob('after'))
            need(v.number('restoring')==j and v.number('attempted_mask')==v.number('completed_mask')==(1<<count)-1 and v.number('reserved')==0 and
                 before==generations[-1]and all(after[k]>before[k]for k in range(count))and not any(after[count:]),'two actual source-generation transitions');generations.append(after)
        need(q(o.blob('current_generation'))==generations[2],'final restored generations')
        rel=o.sub('release','li2_oneshot_release');call(rel.sub('call','li2_oneshot_call'));need(rel.number('transaction_live')==rel.number('reserved')==0,'verified actual release')
        protocol=[]
        for protection in (3,5,0,1,0,3,1,0):
            protocol.extend([(1,k,protection)for k in range(count)]if protection else[(2,0,0)])
        need(o.number('operations')==len(protocol)and o.number('observations')==7,'complete actual fixed publication protocol')
        for j,v in enumerate(o.array('operation','li2_oneshot_operation')):
            if j>=len(protocol):need(not any(v.data),'unused operation row');continue
            need(tuple(v.number(k)for k in ('kind','page','protection'))==protocol[j]and v.number('reserved')==0,'exact native protection/sync protocol');call(v.sub('call','li2_oneshot_call'))
        observations=o.array('observation','li2_oneshot_observation');calls=o.array('observation_call','li2_oneshot_call')
        for j,(v,c)in enumerate(zip(observations,calls,strict=True)):
            if j>=7:need(not any(v.data+c.data),'unused observation row');continue
            call(c);pp=v.array('pages','li2_oneshot_page')
            for k,page in enumerate(pages):
                if k>=count:need(not any(pp[k].data),'unused observed page');continue
                need(pp[k].number('address')==page.number('address')and pp[k].number('allocation')==page.number('allocation')and
                     pp[k].number('offset')==page.number('offset')and pp[k].number('generation')==generations[[0,1,1,1,1,2,2][j]][k],'fresh actual source identity/generation')
            need(struct.unpack('<2I',v.blob('protection'))==tuple([[1,3,5,5,1,3,1][j]]*count+[0]*(2-count))and
                 struct.unpack('<2I',v.blob('private_mapping'))==tuple([1]*count+[0]*(2-count))and not any(v.blob('writable_aliases'))and
                 v.number('page_count')==count and v.number('landing_protection')==5 and v.number('landing_private')==1 and
                 v.number('landing_writable_aliases')==0 and v.number('landing_page')==landing&~4095 and
                 v.number('landing_allocation')==a[2]and v.number('landing_generation')==1 and v.number('pid',True)==v.number('tid',True)==pid,'complete page and landing observations')
        need(backend.number('held')==0 and backend.number('released')==1 and backend.number('maps_started')==backend.number('maps_returned')==12 and
             backend.number('observations')==7 and backend.number('generation_steps')==2,'actual full backend release/fresh observations/backing')
        expected_bits=tuple([1]*count+[0]*(2-count))
        need(all(struct.unpack('<2I',backend.blob(k))==expected_bits for k in ('backing_started','backing_returned','backing_verified'))and
             struct.unpack('<2q',backend.blob('backing_result'))==tuple([4096]*count+[0]*(2-count)),'actual complete backing reads')
        for m in backend.array('maps','li2_fetch_map_progress'):maps(m,True)
        for j,v in enumerate(backend.array('backing','li2_fetch_backing')):
            if j<count:backing(v,main_backing_bytes if a[2]==1 else images[a[2]]['bytes'])
            else:need(not any(v.data),'unused backing observation')
        if kind==2:
            need(a[11]==1 and not any(a[13:23])and a[23:26]==(7,0,0)and a[27:29]==(0,0)and a[30]==0 and
                 a[26]<1<<32 and a[29]<1<<32,'real committed RDTSC sample and no syscall')
            edits={13:a[26],12:a[29],17:a[4],16:npc};clock+=1
            if a[2]==2 and pc-a[3]==0x1fd98:need(required_clock is None,'one first clock witness');required_clock=index
        else:
            need(a[13]==1 and a[15]==ud['g'][13]and a[16:22]==tuple(ud['g'][j]for j in(8,9,12,2,0,1))and a[30]==ud['h'][3]and not any(a[23:30]),'actual syscall input before clobber')
            if a[11]:need(a[14]==1,'actual returning dispatch result')
            else:need(a[14]==a[22]==0 and a[15]in(60,231)and a[16]==0 and not any(events[4].data),'honest nonreturning successful exit prefix')
            edits={13:a[22],14:npc,3:a[4],17:a[4],16:npc};syscalls+=1
        if a[11]:changed(udr,frame(events[4],layout),layout,edits)
        published+=1;restored+=1;started+=1;returned+=a[11]
        result.append(dict(sequence=index+1,image=a[2],file_offset=pages[0].number('offset')+(pc&4095),kind=kind,published=1,returned=a[11]))
    need(published==restored==returned==started==8 and clock==syscalls==4,'all eight actual publications restored/returned; no early owner consumed')
    need(not any(r.sub('continuation','li2_tf_chain_slot').data+r.sub('trace','oi_frame').data),'no fabricated system-interpreter TRACE in finite corpus')
    for i,row in enumerate(rows):
        plan=row.sub('owner','li2_oneshot_owner').sub('plan','li2_oneshot_plan')
        need(plan.number('pc')==image['sites'][i]and plan.number('kind')==(1 if i%2 else 2),'literal owner order/kind/site')
    return dict(owners=8,published=8,restored=8,completed=8,effect_started=8,effect_returned=8,syscall_patches=4,rdtsc_patches=4,active_phase=0,
        ordered_owners=result,full_saved_frames=True,all_source_pages_restored=True)

def registered_setup_image(image):
    """Additional literal execution entries; the old registered ELF checks run first."""
    source=bytes.fromhex(image['source_hex'])
    need(source[4093:4096]==bytes.fromhex('660f05')and
         source[36:41]==bytes.fromhex('e9d40f0000')and source[4143:4145]==bytes.fromhex('ebcc'),
         'both actual setup jumps enter the ignored-prefix SYSCALL at8189, nextPC8192')
    return image

def registered_setup(r,layout,images,pid,oi,bias,registration):
    """Two genuine preclobber/postcommit frames, exact old syscall effects only."""
    rows=r.array('setup','oc_setup');need(len(rows)==2,'two fixed complete setup rows')
    need(oi.read(images[1],8189,3)==bytes.fromhex('660f05'),'actual setup source is three-byte prefixed SYSCALL')
    address=None
    for i,row in enumerate(rows):
        a=Q(row.blob('h'));d=row.sub('decoded','li2_decoded');pc=bias+8189;npc=pc+3
        before=oi.frame(row.sub('before','oi_frame'),layout);after=oi.frame(row.sub('after','oi_frame'),layout)
        g=before['g'];flags=a[5];result=a[20]
        need(a[:5]==(2,i,pc,npc,(9,334)[i])and a[6:13]==(0,301,3,1,0,0,0)and
             a[13:20]==((0,0,0,0,0,0,0)if i==0 else(1,1,3,0,0,0,0))and a[21]==npc and not any(a[22:]),
             'ordered actual setup returned, no owner, exact borrow/registration/release state')
        need(tuple(d.number(k)for k in('pc','next_pc','abi_version','decode_status','code','kind','destination','width_bits','step_disposition','available','length','reserved'))==
             (pc,npc,1,0,870,7,16,0,5,3,3,0)and d.blob('bytes')==bytes.fromhex('660f05')+bytes(13),
             'complete actual ignored-prefix syscall decode: length3 and real PC+3')
        need(before['h'][1]==11 and g[16]==before['addr']==g[22]==pc and g[19:21]==[21,14]and
             g[18]&65535==0x33 and g[17]==flags|0x10000 and not flags&0x10100 and g[13]==a[4],
             'genuine first-byte setup NX and actual preclobber syscall number/logical flags')
        args=tuple(g[k]for k in(8,9,12,2,0,1))
        need(args==((0,4096,3,0x22,U64,0)if i==0 else(address,32,0,0x53053053,U64,0)),
             'actual anonymous mmap and actual registration inputs before architectural clobber')
        if i==0:
            need(0<result<0x800000000000 and not result&4095,'actual successful page-aligned user mmap return')
            address=result
        else:need(result==0,'actual successful registration return')
        oi.changed(before,after,layout,{13:result,14:npc,3:flags,16:npc,17:flags})
    owner=registration['owner']
    need(owner[1:4]==[1,1,3]and owner[7:11]==[pid,pid,address,address]and owner[11:14]==[32,0x53053053,1],
         'actual setup mmap/registration joins the unchanged terminal owner report')
    return dict(setup_syscalls=2,full_setup_frames=4,setup_instruction_bytes=3)

def cpuid(data,layout,image,pid,view,oi,stdout,ordinary=False,registered=False,main_backing_bytes=None,registration=None):
    """Append-only suffix. All old owner bytes and local frame rules remain."""
    first=layout['types']['oi_record']['bytes'];last=layout['types']['oc_record']['bytes']
    need(type(ordinary)is bool and type(registered)is bool and not(ordinary and registered)and len(data)==first+last<16<<20,'two exact complete records within unchanged cap')
    need(main_backing_bytes is None if ordinary or registered else type(main_backing_bytes)is int and main_backing_bytes>0,
         'finite mode requires exact retained main carrier extent; nonfinite modes forbid it')
    need(type(registration)is dict if registered else registration is None,'only registered mode requires actual registration report')
    images=image if ordinary or registered else image['images'];old=view.View(data[:first],layout,'oi_record')
    if registered:
        z=Q(old.blob('h'));need(z[:6]==(0x31504c49534f324c,1,first,layout['uc_bytes'],layout['si_bytes'],1)and not any(z[6:12])and z[18:20]==(pid,pid)and z[23:25]==(0,1)and not any(z[25:])and
            not any(old.blob('owners')+old.blob('continuation')+old.blob('trace')),'actual registered path retained zero one-shot attempts/owners/frames')
        need(z[13]==z[12]+images[1]['entry']and z[16]==z[15]+images[2]['entry']and z[14]==images[1]['bytes']and z[17]==images[2]['bytes']and
            z[12]>0 and z[15]>0 and not(z[12]|z[15])&4095 and z[22]>0 and not z[22]&4095 and
            z[20]==z[22]+layout['symbols']['selected_oneshot_owners']and z[21]==z[22]+layout['symbols']['selected_session'],
            'actual registered image/bridge/session/owner provenance')
        prefix=dict(owners=0,published=0,restored=0,completed=0,effect_started=0,effect_returned=0,syscall_patches=0,rdtsc_patches=0,active_phase=0)
    else:prefix=oi.check(data[:first],layout,images,pid,view)if ordinary else owners(data[:first],layout,image,pid,view,oi,main_backing_bytes)
    r=view.View(data[first:],layout,'oc_record');h=Q(r.blob('h'));oh=Q(old.blob('h'));count=h[9]
    need(h[:6]==(0x31584e50434f324c,2,last,layout['types']['oc_sample']['bytes'],first,1)and h[6:9]==(0,0,0)and
         1<=count<=40 and h[10]==0 and h[11]==count and h[12:14]==(pid,pid)and h[14:18]==(oh[13],oh[16],oh[12],oh[15])and
         h[18]==(2 if registered else int(not ordinary))and h[19]&0xe7==0xe7 and h[20:23]==(count,count,count)and h[23]==int(not ordinary and not registered)and h[26:28]==(2 if registered else 0,0)and not any(h[28:]),
         'complete actual CPUID suffix/terminal/PID/image/counts')
    hw=struct.unpack('<14I',r.blob('hardware'))
    need(hw[:2]==(1,0)and hw[2]>=13 and hw[8]&0x18000000==0x18000000 and hw[11]&0x40010000==0x40010000,'actual prearm hardware identity')
    components={}
    for row,expected in zip([Q(r.blob('xstate'))[i*4:i*4+4]for i in range(4)],((2,256),(5,64),(6,512),(7,1024)),strict=True):
        bit,size=expected;need(row[0]==bit and row[2]==size and row[1]>=576 and row[1]+size<=65532 and row[3]&1==0,'actual standard XSAVE component facts')
        components[bit]=(row[1],size)
    spans=sorted((a,a+n)for a,n in components.values());need(all(a[1]<=b[0]for a,b in zip(spans,spans[1:])),'disjoint actual XSAVE components')
    samples=r.array('samples','oc_sample');need(len(samples)==40 and all(not any(x.data)for x in samples[count:]),'whole zero unused sample tail')
    expected_pcs=[h[15]]if registered else None if ordinary else[h[15],MAIN]+image['pcs']
    slots=None if ordinary or registered else output(stdout,image)
    if ordinary:need(count==38,'all38 actual CPUID operations in the fixed ordinary true/interpreter corpus')
    elif registered:need(count==1,'one real first-interpreter CPUID before registration; no selected interpreter setup')
    elif not ordinary:need(count==11,'instruction-one interpreter/main and nine true PC+2 CPUIDs')
    biases={1:h[16],2:h[17]};post=[];rows=old.array('owners','oi_owner');captured=[]
    for i,row in enumerate(samples[:count]):
        a=Q(row.blob('h'));before=oi.frame(row.sub('before','oi_frame'),layout);after=oi.frame(row.sub('after','oi_frame'),layout)
        pc,npc=a[2:4];g=before['g'];flags=a[9]
        need(a[:2]==(2,i)and npc==pc+2 and a[4:9]==(1,1948,2,0,16)and a[10]==i and a[12]in(1,2)and a[13:16]==(301,0,0)and
             a[16:18]==(g[13]&0xffffffff,g[14]&0xffffffff)and a[18:29]==(i+1,3,1,1,i+1,i+1,i+1,pc,npc,a[16],a[17])and
             a[29:33]==a[33:37]and all(x<1<<32 for x in a[29:37])and a[37:42]==(a[11],0,301,0,0)and not any(a[42:]),
             'real source decode, raw input/sample/commit, unchanged owner and held borrow')
        need(before['h'][1]==11 and g[16]==pc and g[19:21]==[21,14]and pc<=before['addr']==g[22]<npc and
             g[18]&65535==0x33 and g[17]==flags|0x10000 and not flags&0x10100,'genuine original-PC NX current frame and logical flags')
        oi.changed(before,after,layout,{13:a[29],11:a[30],14:a[31],12:a[32],16:npc,17:flags})
        b=row.sub('builtin','selected_builtin_prefix')
        need(b.number('kind')==1 and b.number('phase')==0 and b.number('enable_result',True)==b.number('restore_result',True)==0 and
             tuple(b.number(k)for k in('a','b','c','d'))==a[29:33],'raw NX tuple is exact legacy phase0 tuple; no control/rearm claim')
        v=row.sub('view','li2_fetch_view');pages=row.array('pages','li2_fetch_page');borrowed=row.blob('borrowed')
        fetch_length=v.number('length');need(v.number('pc')==pc and v.number('page_count')==a[12]and v.number('bytes')>0 and v.number('pages')>0 and
             v.number('pid',True)==v.number('tid',True)==pid and v.number('identity_observed')==1 and 2<=fetch_length<=15 and
             borrowed[:2]==b'\x0f\xa2'and not any(borrowed[fetch_length:]),'actual complete authenticated decode source and identity')
        source=row.blob('source_before');need(source==row.blob('source_after'),'every source page byte unchanged by CPUID')
        for j,page in enumerate(pages):
            if j>=a[12]:need(not any(page.data)and not any(source[j*4096:(j+1)*4096]),'unused actual source page zero');continue
            address=page.number('address');need(address==(pc&~4095)+4096*j and page.number('allocation')>0 and page.number('generation')>0 and
                 page.number('logical')==5 and page.number('closed_prot')==1,'actual original logicalRX/closedR source identity')
            matches=[k for k,im in images.items()if any(p[1]&1 and p[3]<=address-biases[k]and address-biases[k]+4096<=p[3]+p[5]for p in im['loads'])]
            need(len(matches)==1,'one complete initial-image source page');k=matches[0]
            load=[p for p in images[k]['loads']if p[1]&1 and p[3]<=address-biases[k]and address-biases[k]+4096<=p[3]+p[5]]
            need(len(load)==1 and page.number('offset')==load[0][2]+address-biases[k]-load[0][3]and
                 source[j*4096:(j+1)*4096]==oi.read(images[k],address-biases[k],4096),'full original source file bytes and actual file offset')
            if not ordinary and not registered and 2<=i<10:
                owner=rows[i-2].sub('owner','li2_oneshot_owner');plan=owner.sub('plan','li2_oneshot_plan')
                original=[(n,p)for n,p in enumerate(plan.array('pages','li2_oneshot_page'))if p.number('address')==address]
                need(len(original)==1,'immediate PC+2 fetch remains inside the restored publication pages')
                owner_page_index,p=original[0]
                need(page.number('allocation')==p.number('allocation')and page.number('offset')==p.number('offset')and
                     page.number('generation')==Q(owner.blob('current_generation'))[owner_page_index],'fresh PC+2 borrow joins actual restored allocation/generation')
        need(source[pc&4095:(pc&4095)+fetch_length]==borrowed[:fetch_length],'actual entire source-borrow literal')
        db=row.blob('data_before');need(db==row.blob('data_after'),'all finite data/stack bytes unchanged locally')
        if ordinary or registered:
            need(not any(db),'nonfinite mode claims no fixed-address data copy')
            if registered:need(pc==h[15]and a[11]==0,'actual instruction-one interpreter CPUID before all registered fallback sites')
        else:
            need(pc==expected_pcs[i]and a[11]==min(max(i-1,0),8),'literal first-entry/owner/continuation order')
            if i<2:need(db==bytes.fromhex(image['initial_data']),'initial CPUID before setup retains whole data')
            if i==1:
                prior=post[0]['g'].copy();prior[13]=MAIN
                need(g[:16]==prior[:16]and flags==post[0]['g'][17]and before['fp']==post[0]['fp'],'genuine interpreter MOVABS/JMP inherited main state')
            if i>=2:
                slot=i-2;seed,expected_flags=seeded(image,slot)
                need(db==data_state(image,slots,slot),'all current setup/stack/previous live/output data from literal program writes')
                if slot<8:
                    handoff=oi.frame(rows[slot].array('frames','oi_frame')[4],layout)
                    need(g[:16]==handoff['g'][:16]and pc==handoff['g'][16]and flags==handoff['g'][17]and
                         before['fp']==handoff['fp']and before['h'][8:10]==handoff['h'][8:10],
                         'real restored post-effect frame is exact PC+2 CPUID architectural input')
                else:
                    prior=row.sub('prior','selected_builtin_prefix')
                    need(prior.number('kind')==5 and prior.number('phase')==7 and prior.number('enable_result',True)==prior.number('restore_result',True)==0 and
                         g[13]==prior.number('a')and g[12]==prior.number('d'),'ninth unowned RDTSC completed through original builtin fallback')
                allowed={0,2}if not slot%2 else{0,1,11}
                if slot%2:
                    seed[0]=5;seed[1]=pc;seed[11]=expected_flags
                    need(a[16]==5 and a[17]==pc&0xffffffff,'real source-write return and architectural RCX clobber feed CPUID')
                need(all(g[GREG[j]]==seed[j]for j in range(16)if j not in allowed)and flags==expected_flags,'complete unmodified seeded input fields/flags')
                fp=before['fp'];need(len(fp)>=576,'full actual FP capture')
                vectors=b''.join(fp[160+j*16:176+j*16]+fp[components[2][0]+j*16:components[2][0]+(j+1)*16]+fp[components[6][0]+j*32:components[6][0]+(j+1)*32]for j in range(16))+fp[components[7][0]:components[7][0]+1024]
                need(vectors==VECTOR and fp[components[5][0]:components[5][0]+64]==MASK,'all actual seeded ZMM/K bytes in complete before FP')
                captured.append(after)
        post.append(after)
    if ordinary or registered:need(not any(r.blob('terminal_source')+r.blob('terminal_data')),'nonfinite mode claims no fixed terminal copy')
    else:
        need(r.blob('terminal_source')==bytes.fromhex(image['source']),'entire original main source retained at terminal')
        terminal=r.blob('terminal_data')
        need(terminal==data_state(image,slots,8,True),'entire terminal data/stack has only exact literal setup and nine complete capture writes')
        need(terminal[7680:7680+21248]==stdout[20:],'actual whole terminal output data joins stdout')
        for actual,frame in zip(slots,captured,strict=True):
            need(Q(actual[2112:2240])==tuple(frame['g'][j]for j in GREG)and W(actual,2240)==frame['g'][17],
                 'actual live capture joins every committed CPUID register and full logical flags')
    if registered:
        stack=Q(r.blob('startup'));n=h[24];need(0<n<=256 and h[25]==1 and stack[0]==1 and stack[1]>0 and stack[2]==0 and not any(stack[n:]),'actual bounded complete startup words')
        at=3
        while at<n and stack[at]:at+=1
        need(at<n,'actual environment terminator');at+=1;aux=[]
        while at+1<n and stack[at]:aux.append((stack[at],stack[at+1],at));at+=2
        need(at+2==n and stack[at:at+2]==(0,0),'actual complete auxv and terminator')
        entries=[v for v in aux if v[0]==9];need(len(entries)==1 and entries[0][1]==h[14],'actual kernel AT_ENTRY equals actual main entry')
        inherited=post[0];main=oi.frame(r.sub('main_entry','oi_frame'),layout);before=oi.frame(samples[0].sub('before','oi_frame'),layout)
        want=inherited['g'][:16];want[13]=h[14];want[14]=1;want[9]=before['g'][15]+8*entries[0][2]
        flags=(inherited['g'][17]&~0xcd5)|0x44
        need(main['h'][1]==11 and main['g'][16]==main['addr']==main['g'][22]==h[14]and main['g'][19:21]==[21,14]and
             main['g'][:16]==want and main['g'][17]==flags|0x10000 and main['fp']==inherited['fp']and main['h'][8:10]==inherited['h'][8:10],
             'real CPUID/AT_ENTRY/RSP handoff and complete preserved architectural state')
    else:need(h[24:26]==(0,0)and not any(r.blob('main_entry')+r.blob('startup')),'no unclaimed startup/entry observation')
    if registered:prefix.update(registered_setup(r,layout,images,pid,oi,h[16],registration))
    else:need(not any(r.blob('setup')),'all setup observation bytes zero in every other lane')
    return dict(prefix,cpuid_samples=count,full_cpuid_frames=2*count,raw_nx_commits=count,cpuid_owner_count=0,
        first_interpreter_cpuid=int(not ordinary),first_main_cpuid=int(not ordinary and not registered),restored_pc2_cpuid=8 if not ordinary and not registered else 0,capacity_fallback=1 if not ordinary and not registered else 0)
