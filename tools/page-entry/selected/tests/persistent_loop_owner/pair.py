"""Full original/protected focal state relation; no cache-lifecycle authority."""
import struct,copy
PAGE,FP,TF,RF,MASK=4096,65536,0x100,0x10000,0xffffffffbffbfae7
GREG=(13,14,12,11,15,10,9,8,0,1,2,3,4,5,6,7)

def need(ok,why):
    if not ok:raise ValueError(why)

def context(actual,ref,event,*,machine,redirect=None,cr2=None):
    """Only actual original TF removal, generated RIP, NX or causal CR2.

    Undefined flag bits are literal native observations, never masked. Each
    coordinate below was authenticated separately by both full raw readers.
    """
    want=list(ref['greg']);si=bytearray(ref['si']);signal=ref['header'][4]
    if event in('closed','redirect','read_fault'):want[17]&=~TF
    if event in('redirect','read_fault'):
        need(type(redirect)is int and redirect>0,'actual authenticated generated PC')
        want[16]=redirect
    elif event=='nx':
        want[17]=(want[17]&~TF)|RF;want[19],want[20],want[22]=21,14,want[16]
        signal=11;struct.pack_into('<iii',si,0,11,0,2);struct.pack_into('<Q',si,16,want[16])
    else:need(event in('original','closed'),'one exact original/protected event relation')
    if cr2 is not None:
        need(event=='original'and type(cr2)is int and cr2>0,'CR2 changes only after actual original branch NX')
        want[22]=cr2
    need(type(actual['greg'])is tuple and len(actual['greg'])==23 and actual['greg']==tuple(want),
         'all23 literal native/protected GREG including undefined flags and actual CR2')
    need(actual['sig']==signal and actual['si']==bytes(si),'all128 actual SI bytes with causal signal/PC only')
    need(type(actual['fp'])is bytes and len(actual['fp'])==FP and actual['fp']==ref['fp']and
         actual['fp_bytes']==ref['header'][9]and actual['mask']==MASK and
         (actual['fs'],actual['gs'])==tuple(machine[1:3]),'whole65536 native/protected FP, mask and actual TLS')
    uc,nuc=actual['uc'],ref['uc'];h=ref['header'];alt,cap=actual['altstack'];fp=actual['fp_address']
    need(len(uc)==968 and len(nuc)==1024 and nuc[968:]==bytes(56)and h[7]==968,
         'complete actual native/protected UC extents')
    need(cap==h[11]==524288 and 0<alt<(1<<47)-cap and alt%PAGE==0 and fp%16==0 and
         alt<=fp<=alt+cap-actual['fp_bytes']and h[10]<=h[8]<=h[10]+h[11]-h[9]and
         fp-alt==h[8]-h[10],'same authenticated kernel FP position within both actual altstacks')
    for offset,a,n in((16,alt,h[10]),(32,cap,h[11]),(224,fp,h[8])):
        need(struct.unpack_from('<Q',uc,offset)[0]==a and struct.unpack_from('<Q',nuc,offset)[0]==n,
             'actual UC altstack and FP pointer aliases')
    expected=bytearray(nuc[:968]);struct.pack_into('<Q',expected,16,alt);struct.pack_into('<Q',expected,224,fp)
    struct.pack_into('<23Q',expected,40,*want);expected[304:432]=si
    need(uc==bytes(expected),'all968 UC bytes with authenticated coordinates and exact causal event fields')


def pair(native,gated,owner):
    mode=gated['mode'];failed=mode>=5
    need(native['lane']==0 and gated['lane']==1 and native['mode']==owner['mode']==mode and 0<=mode<7 and
         native['placement']==gated['placement']==owner['placement'], 'same explicit case/placement and separate real native/maintained lanes')
    keys=('hardware','facts','seed','machine','source','data','stack','base','page','entry','predecessor','endpoint')
    need(all(native[k]==gated[k]for k in keys)and owner['source']==native['source'],
         'whole same-CPU hardware/source/seed/memory and exact genuine entry')
    need(native['native_reference_complete']is True and native['application_complete']is True and
         native['actual_fault']is failed and owner['plan_version']==12 and owner['fallback_policy']==11 and
         owner['focal_only']is True and all(owner[k]is False for k in('cold_warm_validated','mixed_policy_validated',
         'replacement_validated','held_cancellation_validated','qualification_credit','performance_credit')),
         'complete independent native observation with focal-only credit and no invented lifecycle authority')
    frames=native['frames'];a=owner['attempt'];machine=native['machine']
    need(len(frames)==native['native_frames']and frames[0]['greg'][16]==native['predecessor']and
         frames[1]['greg'][16]==native['entry'],'real predecessor and genuine first-entry native chronology')
    before=a['predecessor_before'];ref=frames[0]
    need(before['greg']==ref['greg']and before['fp']==ref['fp']and before['fp_bytes']==ref['header'][9]and
         before['mask']==MASK and(before['fs'],before['gs'])==tuple(machine[1:3]),
         'all actual saved predecessor GREG/FP/mask/TLS; no invented predecessor SI/UC capture')
    context(a['ingress'],frames[1],'original',machine=machine)
    context(a['before'],frames[1],'closed',machine=machine)
    context(a['returned'],frames[1],'redirect',machine=machine,redirect=a['returned']['greg'][16])
    need(a['before_memory']==a['after_memory']==dict(data=native['data'],stack=native['stack']),
         'whole readonly guest data and224 stack bytes before and after the actual generated lifetime')
    need(owner['cold_publications']==owner['generated_entries']==1 and owner['interior_signals']==0 and
         a['terminal_ordinal']==a['begin']+1,'exact one actual cold activation with no hidden interior handler')
    if failed:
        need((owner['status'],owner['code'],owner['detail'],owner['generated_completed'],owner['completion_permits'],
             owner['anchor_released'],owner['actual_signal'],owner['native_fault_signal'],owner['recovery_phase'])==
             (125,3304,11,0,0,0,11,11,0),'failed copied-read outcome remains125 with held source and no completion')
        need('suffix'not in gated and 'frames'not in gated and len(frames)==(3 if mode==5 else 4),
             'native full stopped-read history versus maintained authenticated prefix only')
        ref=frames[-1]
        need(ref['greg'][16]==native['base']+(18 if mode==5 else 56)and
             a['recovered']==dict(gpr=tuple(ref['greg'][i]for i in GREG),pc=ref['greg'][16],flags=ref['greg'][17]&~TF,phase=0),
             'whole original before-effect read recovery equals actual native fault state')
        context(a['after'],ref,'read_fault',machine=machine,redirect=a['after']['greg'][16])
        need(owner['cleanup_closed_pages']==a['closed_pages']and a['closed_pages']in(17,34)and owner['guest_effects']==0,
             'all actual installed code banks NX with no guest effect or false lease release')
        full=4;steps=native['native_instructions'];replays=0
    else:
        need((owner['status'],owner['code'],owner['detail'],owner['generated_completed'],owner['completion_permits'],
             owner['anchor_released'],owner['original_branch_replays'])==(0,0,0,1,1,1,1),
             'actual completed focal lifetime plus exactly one original branch replay')
        need(gated['application_complete']is True and gated['frames']==[]and gated['native_frames']==gated['native_instructions']==0 and
             all(native[k]==gated[k]for k in('before','after','live')),
             'complete literal terminal GPR/flags/vector/selector pair without fabricated maintained native frames')
        branch=frames[-3]['greg'][16];cut=frames[-2]['greg'][16]
        need(branch==native['base']+(12 if mode==1 else 86)and cut==native['base']+(-124 if mode==1 else 88)and
             a['frontier_member']==0 and a['frontier_pc']==branch and a['frontier_target']==cut,
             'actual source-derived selected external cut; no observed-next offer substitutes executed branch')
        context(a['logical'],frames[-3],'nx',machine=machine)
        context(a['next_trace'],frames[-2],'original',machine=machine,cr2=branch)
        need(a['next_trace_ordinal']==a['terminal_ordinal']+1 and a['closed_pages']==17 and
             a['domain_members']==a['anchor_released']==a['completed']==a['permit']==1,
             'one complete17-page drain followed by actual original branch TRACE')
        need((owner['lifetime_mode'],owner['registration_epoch'],owner['registration_calls'],owner['word_observed'])==(2,0,0,0),
             'actual held unregistered source/rseq lifetime without invented registration word')
        full=5;steps=native['native_instructions'];replays=1
    return dict(observed_policy12_focal=1,case=mode,placement=gated['placement'],plan_version=12,
        status=owner['status'],native_instructions=steps,native_full_frames=len(frames),owner_full_context_pairs=full,
        saved_predecessor_GREG_FP_pairs=1,compared_GREG_per_frame=23,FP_bytes_per_frame=65536,
        UC_bytes_per_full_pair=968,SI_bytes_per_full_pair=128,source_bytes=8192,data_bytes=8192,stack_bytes=224,
        cold_publications=1,generated_entries=1,generated_completed=int(not failed),
        original_branch_replays=replays,measured_interior_signals=0,read_fault_before_effect=int(failed),
        source_lease_released=int(not failed),focal_only=True,mixed_policy_validated=False,
        cold_warm_validated=False,replacement_validated=False,held_cancellation_validated=False,
        qualification_credit=False,performance_credit=False)


def controls(native,gated,owner):
    pair(native,gated,owner);failed=gated['mode']>=5
    frames=('ingress','before','returned','after')if failed else('ingress','before','returned','logical','next_trace')
    tests=[]
    for frame in frames:
        tests.extend((f'{frame}_GREG{i}',frame,'greg',i)for i in range(23))
        tests.extend((f'{frame}_{key}{i}',frame,key,i)for key,points in
                     (('fp',(0,160,512,65535)),('si',(0,16,127)),('uc',(0,8,28,40,224,296,432,967)))for i in points)
    names=('source','before_data','after_data','before_stack','after_stack','status','completed','held_source','interior',
           'genuine_entry','native_AF','native_OF','native_FP_tail','lifecycle_credit')
    tests.extend((n,None,None,None)for n in names);refused=[]
    for name,frame,key,index in tests:
        a=copy.deepcopy(owner);n=copy.deepcopy(native);g=copy.deepcopy(gated)
        if frame:
            target=a['attempt'][frame];v=list(target[key])if key=='greg'else bytearray(target[key]);v[index]^=1
            target[key]=tuple(v)if key=='greg'else bytes(v)
        elif name=='source':v=bytearray(a['source']);v[-1]^=1;a['source']=bytes(v)
        elif name in('before_data','after_data','before_stack','after_stack'):
            when,k=name.split('_');m=a['attempt'][when+'_memory'];v=bytearray(m[k]);v[0]^=1;m[k]=bytes(v)
        elif name=='status':a['status']^=1
        elif name=='completed':a['generated_completed']^=1
        elif name=='held_source':a['anchor_released']^=1
        elif name=='interior':a['interior_signals']^=1
        elif name=='genuine_entry':g['entry']^=1
        elif name in('native_AF','native_OF'):
            f=n['frames'][1];v=list(f['greg']);v[17]^=16 if name=='native_AF'else 2048;f['greg']=tuple(v)
        elif name=='native_FP_tail':f=n['frames'][1];v=bytearray(f['fp']);v[-1]^=1;f['fp']=bytes(v)
        else:a['mixed_policy_validated']=True
        try:pair(n,g,a)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted changed full policy14 pair '+name)
    expected=(4 if failed else 5)*38+14
    need(len(refused)==len(set(refused))==expected,'all exact supplied full-state pair controls')
    return dict(refusals=refused,count=expected,native_operations=0,qualification_credit=False)
