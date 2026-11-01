"""Literal native/schema15 context and memory relation for one orientation.

Only previously authenticated NX/TRACE chronology determines CR2 and TF edits.
Undefined arithmetic flags, every FP byte and the complete UC/SI remain exact.
The two orientations must still be joined by the distinct lifecycle provider.
"""
import struct,copy
PAGE,FP,TF,RF,MASK=4096,65536,0x100,0x10000,0xffffffffbffbfae7
GREG=(13,14,12,11,15,10,9,8,0,1,2,3,4,5,6,7)
POSITIONS=(((1,8),(9,12),(13,41),(43,48)),((1,4),(5,12),(13,33),(35,40)))

def need(ok,why):
    if not ok:raise ValueError(why)

def transformed(ref,event,redirect=None,cr2=None):
    g=list(ref['greg']);si=bytearray(ref['si']);signal=ref['header'][4]
    need(event in('original','closed','redirect','nx'),'one exact causal native/protected event relation')
    if event in('closed','redirect'):g[17]&=~TF
    if event=='redirect':
        need(type(redirect)is int and PAGE<=redirect<1<<47,'actual separately authenticated generated entry')
        g[16]=redirect
    if event=='nx':
        need(cr2 is None,'NX supplies its own actual instruction-fetch address')
        g[17]=(g[17]&~TF)|RF;g[19],g[20],g[22]=21,14,g[16]
        signal=11;struct.pack_into('<iii',si,0,11,0,2);struct.pack_into('<Q',si,16,g[16])
    elif cr2 is not None:
        need(type(cr2)is int and PAGE<=cr2<1<<47,'separately authenticated preceding source NX address')
        g[22]=cr2
    return tuple(g),bytes(si),signal

def context(actual,ref,event,*,machine,redirect=None,cr2=None):
    want,si,signal=transformed(ref,event,redirect,cr2)
    need(type(actual['greg'])is tuple and len(actual['greg'])==23 and actual['greg']==want,
         'all23 literal native/protected GREG including undefined flags and causal CR2')
    need(actual['sig']==signal and actual['si']==si,'all128 actual SI bytes with only proved causal event fields')
    need(type(actual['fp'])is bytes and len(actual['fp'])==FP and actual['fp']==ref['fp']and
         actual['fp_bytes']==ref['header'][9]and actual['mask']==MASK and
         (actual['fs'],actual['gs'])==tuple(machine[1:3]),'whole65536 native/protected FP, mask and actual TLS')
    uc,nuc=actual['uc'],ref['uc'];h=ref['header'];alt,cap=actual['altstack'];fp=actual['fp_address']
    need(len(uc)==968 and len(nuc)==1024 and nuc[968:]==bytes(56)and h[7]==968,
         'complete actual native/protected UC extents')
    need(cap==h[11]==524288 and 0<alt<(1<<47)-cap and alt%PAGE==0 and fp%16==0 and
         alt<=fp<=alt+cap-actual['fp_bytes']and h[10]<=h[8]<=h[10]+h[11]-h[9]and
         fp-alt==h[8]-h[10],'same actual kernel FP position within both authenticated altstacks')
    for offset,a,n in((16,alt,h[10]),(32,cap,h[11]),(224,fp,h[8])):
        need(struct.unpack_from('<Q',uc,offset)[0]==a and struct.unpack_from('<Q',nuc,offset)[0]==n,
             'actual UC altstack and FP pointer aliases')
    expected=bytearray(nuc[:968]);struct.pack_into('<Q',expected,16,alt);struct.pack_into('<Q',expected,224,fp)
    struct.pack_into('<23Q',expected,40,*want);expected[304:432]=si
    need(uc==bytes(expected),'all968 UC bytes with authenticated coordinates and literal causal event fields')

def predecessor(actual,ref,event,*,machine,cr2=None):
    want,_,_=transformed(ref,event,cr2=cr2)
    need(actual['greg']==want and actual['fp']==ref['fp']and actual['fp_bytes']==ref['header'][9]and
         actual['mask']==MASK and(actual['fs'],actual['gs'])==tuple(machine[1:3]),
         'all23 actual saved predecessor GREG/FP/mask/TLS without invented SI/UC')

def pair(native,gated,owner):
    mode=gated['mode'];need(type(mode)is int and mode in(0,1),'one actual companion orientation')
    need(native['lane']==0 and gated['lane']==1 and native['mode']==owner['mode']==mode and
         native['placement']==gated['placement']==owner['placement']and gated['placement']in(0,1),
         'same explicit orientation/placement and separate actual lanes')
    keys=('hardware','facts','seed','machine','source','data','stack','base','page','entry','predecessor','endpoint','before','after','live','final_data')
    need(all(native[k]==gated[k]for k in keys)and owner['source']==native['source'],
         'whole actual source/seed/hardware and literal initial/final GPR flags memory vectors')
    need(native['native_reference_complete']is True and native['application_complete']is True and
         native['actual_fault']is False and gated['application_complete']is True and
         gated['frames']==[]and gated['native_frames']==gated['native_instructions']==0,
         'complete actual native history and no fabricated maintained native observations')
    need((owner['schema_version'],owner['plan_version'],owner['fallback_policy'],owner['status'],owner['code'],owner['detail'])==(15,12,11,0,0,0)and
         owner['single_orientation_only']is True and owner['reversed_primary_order_validated']is False and
         owner['full_state_pair_validated']is False and owner['qualification_credit']is False and owner['performance_credit']is False,
         'distinct accepted owner source scope with no premature provider or performance credit')
    need((owner['cold_publications'],owner['warm_entries'],owner['generated_entries'],owner['generated_completed'],
          owner['dual_entries'],owner['completion_permits'],owner['original_branch_replays'],owner['ordinary_store_replays'],
          owner['interior_signals'],owner['companion_replacements'])==(3,1,4,4,1,5,4,1,0,1),
         'four actual lifetimes and one refused before-effect offer remain distinct')
    need((owner['lifetime_mode'],owner['registration_epoch'],owner['registration_calls'],owner['word_observed'])==(2,0,0,0),
         'actual held unregistered lifetime without invented registration word')
    frames=native['frames'];a=owner['attempts'];machine=native['machine'];root=native['base'];page=native['page']
    need(len(frames)==native['native_frames']==(51,43)[mode]and native['native_instructions']==(50,42)[mode]and
         len(a)==4 and [x['index']for x in a]==[0,1,2,4]and owner['orientation']==((12,11)if mode==0 else(11,12)),
         'complete original instruction histories and four chronological lifetime identities')
    need(frames[0]['greg'][16]==native['predecessor']and frames[1]['greg'][16]==native['entry'],
         'genuine initial NX and E9 predecessor execute in both histories')
    for index,(attempt,(lo,hi))in enumerate(zip(a,POSITIONS[mode],strict=True)):
        need((attempt['native_before'],attempt['native_after'])==(lo,hi)and
             attempt['actual_entry']['pc']==frames[lo]['greg'][16]and
             attempt['frontier_pc']==frames[hi]['greg'][16]and
             attempt['frontier_target']==attempt['target']==frames[hi+1]['greg'][16]and
             attempt['terminal_ordinal']==attempt['begin']+1 and
             attempt['next_trace_ordinal']==attempt['terminal_ordinal']+1,
             'whole actual source branch and next TRACE bound to literal native chronology')
        if index==0:
            cr2=native['predecessor'];predecessor(attempt['predecessor_before'],frames[0],'original',machine=machine)
        elif index<3:
            prior=a[index-1];cr2=prior['frontier_pc']
            need(lo==prior['native_after']+1 and attempt['begin']==prior['next_trace_ordinal'],
                 'consecutive source completion and next genuine original branch TRACE')
            predecessor(attempt['predecessor_before'],frames[lo-1],'nx',machine=machine)
        else:
            cr2=root+17;cancel=owner['cancellation']
            need(lo==cancel['native_after']and attempt['begin']==cancel['next_ordinal'],
                 'replacement starts only after the one actual ordinary store')
            predecessor(attempt['predecessor_before'],frames[lo-1],'closed',machine=machine,cr2=cr2)
        context(attempt['ingress'],frames[lo],'original',machine=machine,cr2=cr2)
        context(attempt['before'],frames[lo],'closed',machine=machine,cr2=cr2)
        context(attempt['returned'],frames[lo],'redirect',machine=machine,redirect=attempt['returned']['greg'][16],cr2=cr2)
        context(attempt['logical'],frames[hi],'nx',machine=machine)
        context(attempt['next_trace'],frames[hi+1],'original',machine=machine,cr2=attempt['frontier_pc'])
        need(attempt['before_memory']==dict(data=frames[lo]['data'],stack=frames[lo]['stack'])and
             attempt['after_memory']==dict(data=frames[hi]['data'],stack=frames[hi]['stack']),
             'whole actual8192 data and224 stack bytes at both native/generated boundaries')
        count=2 if index==2 else 1
        need(attempt['domain_members']==count and attempt['closed_pages']==17*count and
             attempt['completed']==attempt['anchor_released']==attempt['permit']==attempt['joint_complete']==1 and
             attempt['interior_signals']==0 and len(attempt['members'])==count and
             attempt['claim_members']==tuple(range(count)),
             'every actual member drained NX and receives its own one-use joint completion claim')
    cancel=owner['cancellation'];d=(42,34)[mode];c=d+1
    need((cancel['reason'],cancel['detail'],cancel['source_released'],cancel['generated_entries'],cancel['publications'],
          cancel['completion_permits'],cancel['ordinary_store_executed'],cancel['native_before'],cancel['native_after'])==
         (1,1,1,0,0,0,1,d,c)and cancel['ordinal']==a[2]['next_trace_ordinal']and
         cancel['next_ordinal']==cancel['ordinal']+1,
         'literal unsupported m16 miss cancels with no generated/publication/completion authority')
    for key,event,ref in(('ingress','original',frames[d]),('before','closed',frames[d]),
                          ('returned','original',frames[d]),('next','original',frames[c])):
        context(cancel[key],ref,event,machine=machine,cr2=root+17)
    wanted=bytearray(frames[d]['data']);struct.pack_into('<H',wanted,8,frames[d]['greg'][14]&65535)
    need(frames[c]['data']==bytes(wanted)and frames[c]['stack']==frames[d]['stack']and
         a[2]['after_memory']==dict(data=frames[d]['data'],stack=frames[d]['stack'])and
         a[3]['before_memory']==dict(data=frames[c]['data'],stack=frames[c]['stack']),
         'exact one ordinary store is observed between actual whole owner memory snapshots')
    warm=a[2];lo,hi=POSITIONS[mode][2]
    arms={(root+8,page+256),(page+266,root)}
    transfers=[(x['greg'][16],y['greg'][16])for x,y in zip(frames[lo:hi],frames[lo+1:hi+1],strict=True)
               if(x['greg'][16],y['greg'][16])in arms]
    need(len(transfers)==(4,3)[mode]and set(transfers)==arms and warm['members']==[a[0]['members'][0],a[1]['members'][0]],
         'actual native internal A/B transfers join both immutable directory members and zero interior signals')
    replacement=owner['replacement'];victim=next(x for x in a[:2]if x['slot']==a[3]['slot'])
    need(replacement==dict(slot=a[3]['slot'],old_generation=victim['generation'],new_generation=a[3]['generation'],
         old_build_serial=victim['build_serial'],new_build_serial=a[3]['build_serial'])and
         replacement['new_generation']==a[1]['generation']+1 and
         replacement['new_build_serial']==cancel['serial']+1 and a[3]['prior_generation_installed']==1,
         'actual replacement names the consumed old generation and distinct new complete publication')
    return dict(observed_policy12_lifecycle=1,case=mode,placement=gated['placement'],schema_version=15,
        status=0,native_instructions=native['native_instructions'],native_full_frames=len(frames),
        owner_full_context_pairs=24,saved_predecessor_GREG_FP_pairs=4,compared_GREG_per_frame=23,
        FP_bytes_per_frame=65536,UC_bytes_per_full_pair=968,SI_bytes_per_full_pair=128,
        source_bytes=8192,data_bytes_per_snapshot=8192,stack_bytes_per_snapshot=224,
        owner_memory_snapshots=8,native_memory_snapshots=len(frames),
        cold_policy12=2,cold_policy11_complete_no_envelope=1,warm_mixed_lifetimes=1,
        primary_policy=owner['orientation'][0],peer_policy=owner['orientation'][1],
        native_internal_transfers=len(transfers),measured_interior_signals=0,
        generated_entries=4,generated_completed=4,original_branch_replays=4,
        companion_replacements=1,held_cancellations=1,ordinary_store_replays=1,
        single_orientation_only=True,reversed_primary_order_validated=False,
        qualification_credit=False,performance_credit=False)

def controls(native,gated,owner):
    pair(native,gated,owner);tests=[]
    for index in range(4):
        for frame in('ingress','before','returned','logical','next_trace'):
            tests.extend((f'epoch{index}_{frame}_GREG{i}',('attempts',index,frame),'greg',i)for i in range(23))
            tests.extend((f'epoch{index}_{frame}_{key}{i}',('attempts',index,frame),key,i)for key,points in
                         (('fp',(0,160,512,65535)),('si',(0,16,127)),('uc',(0,8,28,40,224,296,432,967)))for i in points)
    for frame in('ingress','before','returned','next'):
        tests.extend((f'cancel_{frame}_GREG{i}',('cancellation',frame),'greg',i)for i in range(23))
        tests.extend((f'cancel_{frame}_{key}{i}',('cancellation',frame),key,i)for key,points in
                     (('fp',(0,160,512,65535)),('si',(0,16,127)),('uc',(0,8,28,40,224,296,432,967)))for i in points)
    for index in range(4):
        tests.extend((f'predecessor{index}_GREG{i}',('attempts',index,'predecessor_before'),'greg',i)for i in range(23))
        tests.extend((f'predecessor{index}_FP{i}',('attempts',index,'predecessor_before'),'fp',i)for i in(0,160,512,65535))
        for when in('before','after'):
            for key,point in(('data',0),('data',8),('data',8191),('stack',0),('stack',223)):
                tests.append((f'epoch{index}_{when}_{key}{point}',('attempts',index,when+'_memory'),key,point))
    counters=('status','generated_completed','completion_permits','interior_signals','ordinary_store_replays',
              'original_branch_replays','cold_publications','warm_entries','companion_replacements')
    for name in counters:tests.append(('counter_'+name,(),name,None))
    refused=[]
    for name,path,key,index in tests:
        changed=copy.deepcopy(owner);target=changed
        for part in path:target=target[part]
        if index is None:target[key]^=1
        else:
            v=list(target[key])if key=='greg'else bytearray(target[key]);v[index]^=1
            target[key]=tuple(v)if key=='greg'else bytes(v)
        need(changed!=owner,'causal supplied lifecycle pair mutation '+name)
        try:pair(native,gated,changed)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted supplied lifecycle pair mutation '+name)
    expected=24*38+4*27+4*2*5+len(counters)
    need(len(refused)==len(set(refused))==expected==1069,'all literal full-state lifecycle pair controls')
    return dict(refusals=refused,count=expected,native_operations=0,qualification_credit=False)
