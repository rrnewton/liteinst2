"""Closed retained ordinary-program publication reader; never runs a process."""
import hashlib,struct
from page_selected import need

U64=(1<<64)-1
MASK=U64^sum(1<<(s-1)for s in(4,5,9,11,19,31))
LD_SHA='34c232018a619b0091e97add6805072d00db3250937fc049a1ef968cecfa99c9'
TRUE_SHA='b9b6ec37ac996b4152caca5a87e5ae23abb649bbc82dc6e1ca1d423d7bf4c171'
def q(b):need(len(b)%8==0,'whole u64 vector');return struct.unpack('<'+'Q'*(len(b)//8),b)
def elf(data):
    need(type(data)is bytes and len(data)>=64,'whole retained ELF');h=struct.unpack_from('<16sHHIQQQIHHHHHH',data)
    need(h[0][:7]==b'\x7fELF\2\1\1' and h[1:4]==(3,62,1)and h[8:10]==(64,56),'actual x86-64 ET_DYN')
    need(h[5]<=len(data)and h[10]*56<=len(data)-h[5],'whole program headers')
    loads=[struct.unpack_from('<IIQQQQQQ',data,h[5]+56*i)for i in range(h[10])]
    loads=[p for p in loads if p[0]==1]
    for p in loads:need(p[2]<=len(data)and p[5]<=len(data)-p[2]and p[5]<=p[6],'actual LOAD extent')
    return dict(entry=h[4],loads=loads,bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),data=data)
def image(main,interpreter):
    m,i=elf(main),elf(interpreter)
    need(m['sha256']==TRUE_SHA and i['sha256']==LD_SHA,'fixed ordinary true/system-interpreter fixture identities')
    need(read(i,0x1f010,8)==bytes.fromhex('4889e7e8680d0000')and
         read(i,0x1fd98,9)==bytes.fromhex('0f318025ad9f0100df'),'exact entry and downstream clock/AND literals')
    return {1:m,2:i}
def read(im,va,n):
    rows=[p for p in im['loads']if p[1]&1 and p[3]<=va and va+n<=p[3]+p[5]]
    need(len(rows)==1,'unique complete executable image range');p=rows[0]
    return im['data'][p[2]+va-p[3]:p[2]+va-p[3]+n]
def call(v,result=0):
    need(all(v.number(k)==1 for k in('started','returned','verified'))and
         v.number('reserved')==0 and v.number('result',True)==result,'complete actual callback/syscall prefix')
def frame(v,layout):
    h=q(v.blob('h'));need(h[0]==1 and h[6:8]==(layout['si_bytes'],layout['uc_bytes'])and not any(h[10:]),'complete real frame shape')
    si,uc,fp=v.blob('si'),v.blob('uc'),v.blob('fp');n=h[5];off=layout['offsets']
    need(len(si)==h[6]and len(uc)==h[7]and 512<=n<=len(fp)and not any(fp[n:]),'complete SI/UC/FP and zero unused FP')
    need(all(type(a)is int and 0<a<=U64-z for a,z in((h[2],len(si)),(h[3],len(uc)),(h[4],n)))and not h[4]&15,'real initialized pointer domains')
    if struct.unpack_from('<I',fp,464)[0]==0x46505853:
        need(struct.unpack_from('<I',fp,468)[0]==n and 576<=struct.unpack_from('<I',fp,480)[0]<=n-4 and
             struct.unpack_from('<I',fp,n-4)[0]==0x46505845,'complete actual signal xstate envelope')
    else:need(n==512,'actual legacy FP envelope')
    for a,x in((h[2],si),(h[3],uc),(h[4],fp[:n])):
        for b,y in((h[2],si),(h[3],uc),(h[4],fp[:n])):
            lo,hi=max(a,b),min(a+len(x),b+len(y))
            if lo<hi:need(x[lo-a:hi-a]==y[lo-b:hi-b],'all physical alias bytes agree')
    g=list(struct.unpack_from('<23Q',uc,off['greg']))
    need(struct.unpack_from('<Q',uc,off['fp_pointer'])[0]==h[4]and
         struct.unpack_from('<Q',uc,off['mask'])[0]==MASK,'actual FP pointer/application mask')
    need(struct.unpack_from('<i',si,off['si_signo'])[0]==h[1]and
         struct.unpack_from('<i',si,off['si_errno'])[0]==0 and
         struct.unpack_from('<i',si,off['si_code'])[0]==2,'genuine positive NX/UD/TRACE siginfo')
    return dict(h=h,si=si,uc=uc,fp=fp,g=g,addr=struct.unpack_from('<Q',si,off['si_addr'])[0])
def changed(before,after,layout,edits):
    """Only named physical GPR writes; complete local SI/UC/FP remain retained."""
    need(before['h']==after['h'],'same actual local frame pointers/extent/live selectors')
    want=bytearray(before['uc']);off=layout['offsets']['greg']
    for index,value in edits.items():struct.pack_into('<Q',want,off+8*index,value)
    # Project physical writes into each actual overlapping retained view.
    physical={before['h'][3]+at:value for at,(old,value)in enumerate(zip(before['uc'],want))if old!=value}
    for name,address,original in(('uc',before['h'][3],bytes(want)),('si',before['h'][2],before['si']),('fp',before['h'][4],before['fp'])):
        expected=bytearray(original)
        for at,value in physical.items():
            if address<=at<address+len(expected):expected[at-address]=value
        need(bytes(expected)==after[name],'every local '+name+' byte has only named committed GPR edits')
def owner_frame(v,f):
    need(list(q(v.blob('greg')))==f['g']and v.number('mask')==MASK and v.number('fp_address')==f['h'][4]and
         v.number('fp_bytes')==v.number('initialized')==f['h'][5]and v.blob('fp')==f['fp'],'actual owner full saved state joins genuine frame')

def maps(v,direct=False):
    need(v.number('fd',True)>=0 and v.number('last_read',True)==v.number('close_result',True)==0 and
         0<v.number('bytes')<262144 and 0<v.number('rows')<=2048 and
         all(v.number(k)==1 for k in ('opened','close_started','closed')),'complete actual maps acquisition')
    o=v.sub('observation','li2_maps_observation')
    need(o.number('acquisition_id')>0 and o.number('kind')in(0,1,2)and
         o.number('io_performed')==int(o.number('kind')!=2),'actual acquisition/reuse provenance')
    if direct:need(o.number('kind')==0 and o.number('handler_id')==0,'fresh direct publication observation')
def backing(v,size):
    need(v.number('retained_fd',True)>3 and v.number('seals',True)>=0 and v.number('seals')&15==15 and
         v.number('stat_result',True)==0 and v.number('seals_observed')==v.number('stat_observed')==1,'actual sealed descriptor observation')
    st=v.sub('stat','stat');need(st.number('st_dev')>0 and st.number('st_ino')>0 and
         st.number('st_size',True)==size and st.number('st_mode')&0o170000==0o100000,'actual immutable file identity/extent')

def check(data,layout,images,pid,old_record):
    V=old_record.View;r=V(data,layout,'oi_record');h=q(r.blob('h'))
    need(h[:6]==(0x31504c49534f324c,1,len(data),layout['uc_bytes'],layout['si_bytes'],1)and
         len(data)<16<<20 and h[6:9]==(0,0,0)and 1<=h[9]<=8 and h[10]==0 and 0<=h[11]<=h[9]and
         h[18:20]==(pid,pid)and h[23:25]==(1,1)and not any(h[25:]),'complete successful finite terminal and actual PID')
    biases={1:h[12],2:h[15]};need(h[13]==h[12]+images[1]['entry']and h[16]==h[15]+images[2]['entry']and
         h[14]==images[1]['bytes']and h[17]==images[2]['bytes']and all(x>0 and not x&4095 for x in biases.values()),'actual initial image biases/entries/source extents')
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
            if j<count:backing(v,images[a[2]]['bytes'])
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
    need(required_clock is not None and syscalls>=1,'actual first interpreter clock and actual initial-image syscall publications')
    c=r.sub('continuation','li2_tf_chain_slot');decoded=c.sub('decoded','li2_decoded');tf=c.sub('owner','li2_tf_owner');step=tf.sub('step','li2_step_owner')
    need(c.number('phase')==5 and c.number('fallback')==0 and c.number('origin')==1 and c.number('prepare_attempted')==0 and
         all(c.number(k)==1 for k in('prepare_complete','decode_attempted','decode_complete'))and
         all(c.number(k,True)==0 for k in('prepare_result','decode_result','classify_result'))and c.number('unexpected_frame_observed')==0,'actual completed downstream chain owner')
    need(decoded.number('pc')==h[15]+0x1fd9a and decoded.number('next_pc')==h[15]+0x1fda1 and decoded.number('length')==7 and
         decoded.blob('bytes')[:7]==bytes.fromhex('8025ad9f0100df'),'actual original PC+2 instruction executes')
    need(step.number('phase')==5 and step.number('first_error')==0 and step.number('trace_seen')==step.number('revoke_sync_started')==1 and
         step.number('revoke_sync',True)==0 and tf.number('continuation_started')==tf.number('continuation_complete')==1 and tf.number('continuation_result',True)==0 and
         tf.number('actual_post_pc')==h[15]+0x1fda1,'real TRACE and complete revoke/continuation')
    release=c.sub('release','li2_chain_release');need(release.number('started')==release.number('complete')==1 and release.number('result',True)==0,'downstream borrow closed')
    query=c.sub('query','li2_tf_continuation')
    need(query.number('pc')==h[15]+0x1fda1 and all(query.number(k)==1 for k in ('attempted','page_observed','complete'))and query.number('result',True)==0,'actual closed continuation query')
    request=step.sub('request','li2_step_request')
    need(request.number('page_count')==1 and all(struct.unpack('<2I',step.blob(k))==(1,0)for k in ('open_started','opened','revoke_started','revoked'))and
         not any(step.blob('open_result')+step.blob('revoke_result'))and step.number('open_sync',True)==0,'exact actual one-page open/revoke')
    fetch=c.sub('fetch','li2_chain_fetch');fp=fetch.sub('progress','li2_fetch_progress')
    need(fp.number('held')==fp.number('first_error')==0 and fetch.number('pid',True)==fetch.number('tid',True)==pid and fetch.number('identity_observed')==1,'closed actual continuation borrow')
    prior=frame(rows[required_clock].array('frames','oi_frame')[4],layout)
    before=step.sub('before','li2_step_frame');after=step.sub('after','li2_step_frame')
    need(list(q(before.blob('greg')))[:16]==prior['g'][:16]and before.blob('fp')==prior['fp']and before.number('mask')==MASK and
         q(before.blob('greg'))[16]==h[15]+0x1fd9a and request.number('original_flags')==prior['g'][17], 'actual clock handoff reaches original PC+2 with full architectural inputs')
    need(q(before.blob('greg'))[:16]==q(after.blob('greg'))[:16],'original AND preserves all sixteen GPRs')
    trace=frame(r.sub('trace','oi_frame'),layout);need(trace['h'][1]==5 and trace['g'][16]==tf.number('actual_post_pc'),'actual downstream TRACE frame')
    owner_frame(step.sub('after','li2_step_frame'),trace)
    need(step.sub('before','li2_step_frame').blob('fp')==step.sub('after','li2_step_frame').blob('fp'),'downstream AND preserves complete FP')
    return dict(owners=h[9],published=published,restored=restored,completed=returned,effect_started=started,effect_returned=returned,
        syscall_patches=syscalls,rdtsc_patches=clock,active_phase=0 if not h[11]else rows[h[11]-1].sub('owner','li2_oneshot_owner').sub('state','li2_oneshot_admission_state').number('phase'),
        interpreter_clock=1,continuation=1,ordered_owners=result,full_saved_frames=True,all_source_pages_restored=True)
