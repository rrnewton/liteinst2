"""Supplied-corruption controls for complete, actual paired-v2 application captures.

No fixture, expected output or native frame is synthesized. A caller must first
authenticate the real compiler/process/capture and seed prerequisites. This
module accepts that exact input and an explicitly supplied reader; it imports
no candidate code, launches nothing, and grants no owner or performance credit.
"""
import copy
import hashlib
import struct

PREFIX,SUFFIX,FRAME=18944,8569880,66784
FRAME_BASE=PREFIX+21528
GREG=(13,14,12,11,15,10,9,8,0,1,2,3,4,5,6,7)
HEADS=(0,4,8,12,18,23,26,28,32,35,37,40,43,46,48,52,56,59,61,63,65,67,71,75,79,81,83,86)
PATHS=(HEADS[:7]+HEADS[:10]+HEADS[:21]+HEADS+HEADS[:26]+HEADS[16:]+(88,),
       HEADS[:19]+HEADS[:4]+(-124,),HEADS[5:26]+HEADS[16:]+(88,),
       HEADS[17:]+(88,),HEADS[17:]+(88,),(),(52,))
PATHS=tuple((-5,)+path for path in PATHS)
COUNTS=(107,26,36,14,14,3,4)
TYPE_ERROR='typed complete paired success outcome'
ALIAS_ERROR='all physical SI UC FP aliases'


def need(ok,why):
    if not ok:raise ValueError(why)


def digest(raw):return hashlib.sha256(raw).hexdigest()


def changed(raw,positions):
    """Flip one bit at each distinct explicitly selected byte, never a no-op."""
    need(type(raw)is bytes and type(positions)is tuple and positions and
         len(set(positions))==len(positions)and all(type(i)is int and 0<=i<len(raw)for i in positions),
         'bounded distinct mutation positions')
    out=bytearray(raw)
    for i in positions:out[i]^=1
    value=bytes(out)
    need(digest(value)!=digest(raw),'actual changed whole stimulus')
    return value


def physical(raw,index,view,offset,bit=1):
    """Change all retained aliases of one real SI/UC/FP physical byte.

    This deliberately preserves overlap consistency, forcing the independent
    state/metadata predicate to reject the change rather than only an alias
    mismatch. Addresses and extents are read from the already accepted input.
    """
    at=FRAME_BASE+index*FRAME;h=struct.unpack_from('<12Q',raw,at)
    views=((h[5],at+96,128),(h[6],at+224,968),(h[8],at+1248,h[9]))
    need(type(view)is int and 0<=view<3 and type(offset)is int and 0<=offset<views[view][2]and
         type(bit)is int and bit in(1,8,16),'one bounded actual physical byte')
    address=views[view][0]+offset;out=bytearray(raw);positions=[]
    for base,start,size in views:
        if base<=address<base+size:positions.append(start+address-base)
    need(positions and len(set(positions))==len(positions),'distinct retained physical aliases')
    for pos in positions:out[pos]^=bit
    value=bytes(out);need(digest(value)!=digest(raw),'actual coherent physical mutation')
    return value


def native_controls(reader,raw,mode,placement,exit_status,image,pid,cpu,seed_reference):
    """Run only pure reader calls against supplied data; no acquisition/replay.

    A malformed stimulus must cause its named causal ValueError. An unrelated
    exception, missing input or reader crash is a failed control, never credit.
    Undefined AF/OF changes are also rejected once the unchanged next original
    instruction preserves them. Whole owner pairing is still unavailable.
    """
    baseline=reader.read(raw,0,mode,placement,exit_status,image,pid,cpu,seed_reference)
    need(baseline['native_reference_complete']is True and baseline['owner_validated']is False and
         baseline['mixed_policy_validated']is False and baseline['qualification_credit']is False and
         baseline['performance_credit']is False,'accepted native-only control base')
    need(len(raw)==PREFIX+SUFFIX and len(baseline['frames'])==COUNTS[mode], 'actual complete control population')
    original=digest(raw);names=[]

    def reject(name,value,why):
        need(type(name)is str and name not in names and type(value)is bytes and digest(value)!=original,
             'unique actual nonidentity control '+name)
        try:reader.read(value,0,mode,placement,exit_status,image,pid,cpu,seed_reference)
        except ValueError as error:need(str(error)==why,'exact causal rejection '+name+': '+str(error))
        else:raise ValueError('accepted supplied native corruption '+name)
        names.append(name)

    def flip(name,at,why):reject(name,changed(raw,(at,)),why)

    # Complete header population, including every reserved word. Hardware and
    # format fields have their original separate actual seed/CPUID authority.
    for word in range(64):
        if word==9:why='same-CPU qualified seed and complete format'
        elif word<14:why='exact paired source process CPU lane and placement'
        elif word in(14,15):why='actual bounded XCR0 geometry'
        elif word<27 or word==28:why='actual native signal geometry and hardware query success'
        elif word in(27,29):why='closed known enabled user-component and permission domain'
        else:why='whole paired source header and reserved words'
        flip('prefix_word_'+str(word),8*word,why)
    for row in range(67):
        flip('cpuid_identity_'+str(row),512+24*row,'exact CPUID query identities and order')
    flip('cpuid_full_result',512+24+8,'same-CPU qualified seed and complete format')
    for i in range(16):flip('seed_gpr_'+str(i),2120+8*i,'whole literal native seed data and stack')
    flip('seed_flags',2248,'whole literal native seed data and stack')
    for i in range(6):flip('seed_selector_'+str(i),2256+2*i,'whole literal native seed data and stack')
    flip('seed_reserved',2268,'complete live state and reserved tail')
    for i in range(8):flip('prefix_machine_'+str(i),2272+8*i,'complete native TLS mask and selectors')
    source_at=4022 if placement&1 else 512
    for name,offset in(('before',0),('first',source_at),('last_head',source_at+86),('second_page',4096),
                        ('last',8191),('cut_a',source_at-124),('cut_a_target',source_at-118),
                        ('cut_b',source_at+88),('cut_b_target',source_at+94),
                        ('predecessor',source_at-5),('predecessor_displacement',source_at-4)):
        flip('source_'+name,2336+offset,'whole actual paired source including E9 and both transparent cuts')
    for offset in(0,504,512,640,768,897,4096,4097,8191):
        flip('data_'+str(offset),10528+offset,'whole literal native seed data and stack')
    for offset in(0,127,128,223):flip('stack_'+str(offset),18720+offset,'whole literal native seed data and stack')

    for phase,start in(('before',256),('after',408)):
        why='whole actual entry and terminal selectors'if phase=='before'else'all terminal native GPRs and actual flags including undefined bits'
        for i in range(16):flip(phase+'_gpr_'+str(i),PREFIX+start+8*i,why)
        flip(phase+'_flags',PREFIX+start+128,why)
        for i in range(6):flip(phase+'_selector_'+str(i),PREFIX+start+136+2*i,'whole actual entry and terminal selectors')
        flip(phase+'_reserved',PREFIX+start+148,'complete live state and reserved tail')
    for phase,start in(('before',560),('after',624)):
        for i in range(8):flip(phase+'_machine_'+str(i),PREFIX+start+8*i,'whole native machine bracket')
    for phase,start in(('before',688),('after',2804)):
        for i in range(32):flip(phase+'_zmm_'+str(i),PREFIX+start+64*i+63,'whole actual native vector and x87 bracket')
        for i in range(8):flip(phase+'_mask_'+str(i),PREFIX+start+2048+8*i+7,'whole actual native vector and x87 bracket')
        for i in(2112,2114):flip(phase+'_x87_'+str(i),PREFIX+start+i,'whole actual native vector and x87 bracket')
    for name,start,size in(('source',4920,8192),('data',13112,8192),('stack',21304,224)):
        for off in(0,size//2,size-1):flip('after_'+name+'_'+str(off),PREFIX+start+off,'whole unchanged source data and stack')

    # Every actual frame participates; initial and final observations are not
    # treated as dispensable endpoints. Literal CF is defined in every event.
    for index in range(COUNTS[mode]):
        at=FRAME_BASE+index*FRAME
        flip('frame_'+str(index)+'_kind',at+8,'exact native frame identity and extent')
        flip('frame_'+str(index)+'_step',at+16,'exact native frame identity and extent')
        flip('frame_'+str(index)+'_pc',at+224+40+16*8,'all native PC selectors event and CR2 words')
        flip('frame_'+str(index)+'_gpr',at+224+40+GREG[index%16]*8,'all16 native GPR values and aliases')
        flip('frame_'+str(index)+'_flags',at+224+40+17*8,'all defined and propagated actual flags with causal TF RF')
        reject('frame_'+str(index)+'_SI',physical(raw,index,0,127),'whole actual native siginfo and causal address')
        reject('frame_'+str(index)+'_UC',physical(raw,index,1,232),'every non-event native ucontext byte preserved')
        reject('frame_'+str(index)+'_legacy',physical(raw,index,2,32),'every actual seeded legacy FP byte')
        flip('frame_'+str(index)+'_unusedFP',at+FRAME-1,'actual FP pointer and full unused native capacities')
    for i in range(16):flip('initial_gpr_'+str(i),FRAME_BASE+224+40+8*GREG[i],'all16 native GPR values and aliases')
    for i in(18,19,20,21,22):
        flip('initial_context_greg_'+str(i),FRAME_BASE+224+40+8*i,'all native PC selectors event and CR2 words')
    for name,at,why in(
        ('SI_alias',FRAME_BASE+96+16,ALIAS_ERROR),
        ('UC_tail',FRAME_BASE+224+968,'actual FP pointer and full unused native capacities'),
        ('UC_FP_pointer',FRAME_BASE+224+224,'actual FP pointer and full unused native capacities'),
        ('frame_UC_size',FRAME_BASE+56,'exact native frame identity and extent'),
        ('frame_FP_size',FRAME_BASE+72,'exact native frame identity and extent'),
        ('frame_alt_size',FRAME_BASE+88,'exact native frame identity and extent'),
        ('frame_FP_address',FRAME_BASE+64,ALIAS_ERROR)):
        flip(name,at,why)
    for name,view,off,why in(
        ('UC_flags',1,0,'actual native context header mask and altstack'),
        ('UC_link',1,8,'actual native context header mask and altstack'),
        ('UC_stack',1,16,'actual native context header mask and altstack'),
        ('UC_stack_pad',1,28,'actual native context header mask and altstack'),
        ('UC_mask',1,296,'actual native context header mask and altstack'),
        ('SI_signo',0,0,'whole actual native siginfo and causal address'),
        ('SI_errno',0,4,'whole actual native siginfo and causal address'),
        ('SI_code',0,8,'whole actual native siginfo and causal address'),
        ('SI_addr',0,16,'whole actual native siginfo and causal address'),
        ('FP_sw_magic',2,464,'whole standard Linux XSAVE envelope'),
        ('FP_sw_mask',2,472,'whole standard Linux XSAVE envelope'),
        ('FP_sw_reserved',2,484,'whole standard Linux XSAVE envelope'),
        ('FP_active',2,512,'whole active standard XSAVE header'),
        ('FP_compacted',2,520,'whole active standard XSAVE header'),
        ('FP_reserved',2,528,'whole active standard XSAVE header')):
        reject(name,physical(raw,0,view,off),why)
    hw=baseline['hardware'];extent=baseline['facts']['extent']
    for name,offset,why in(
        ('YMM',hw[5][3],'every actual YMM high byte'),
        ('ZMM',hw[9][3],'every actual ZMM high byte'),
        ('ZMM16',hw[10][3],'every actual high ZMM byte'),
        ('opmask',hw[8][3],'every actual mask register byte'),
        ('FP_trailer',extent,'whole standard Linux XSAVE envelope')):
        reject(name,physical(raw,0,2,offset),why)
    # AF/OF are not normalized in the retained result. One isolated actual bit
    # change must fail the immediate later flag-preserving instruction.
    undefined_controls=0
    for i,off in enumerate(PATHS[mode],1):
        if off in(32,48,59,79):
            value=physical(raw,i,1,40+17*8,16)
            reject('undefined_AF_propagation_'+str(i),value,'all defined and propagated actual flags with causal TF RF')
            undefined_controls+=1
        if off==48:
            # The low bit of this byte is TF, not OF: choose OF explicitly.
            value=physical(raw,i,1,40+17*8+1,8)
            reject('undefined_OF_propagation_'+str(i),value,'all defined and propagated actual flags with causal TF RF')
            undefined_controls+=1
    for i in range(32):flip('suffix_word_'+str(i),PREFIX+8*i,'complete native termination recovery counters cleanup and reserved words')
    flip('unused_frame_first',FRAME_BASE+COUNTS[mode]*FRAME,'all unused native frames are literal zero')
    flip('unused_frame_last',len(raw)-1,'all unused native frames are literal zero')
    reject('truncated',raw[:-1],TYPE_ERROR);reject('extra',raw+b'\0',TYPE_ERROR)

    args=[raw,0,mode,placement,exit_status,image,pid,cpu,seed_reference]
    for name,index,value in(('lane_bool',1,False),('lane_outside',1,2),('mode_bool',2,bool(mode)),('mode_outside',2,7),
            ('placement_bool',3,bool(placement)),('placement_outside',3,4),('exit125',4,125),
            ('exit_bool',4,False),('pid_bool',6,True),('pid_zero',6,0),('cpu_bool',7,bool(cpu)),('cpu_negative',7,-1)):
        need(type(value)is not type(args[index])or value!=args[index],'changed typed argument '+name)
        new=list(args);new[index]=value
        try:reader.read(*new)
        except ValueError as error:need(str(error)==TYPE_ERROR,'exact typed rejection '+name)
        else:raise ValueError('accepted supplied native argument '+name)
        names.append(name)

    # Distinct v2/lane/image authority must never relabel the native-v1 wire.
    value=bytearray(raw);struct.pack_into('<Q',value,8,1)
    reject('native_v1_version',bytes(value),'exact paired source process CPU lane and placement')
    new=list(args);new[1]=1
    try:reader.read(*new)
    except ValueError as error:need(str(error)==('maintained read faults cannot become application success'if mode>=5 else
        'exact paired source process CPU lane and placement'),'exact cross-lane rejection')
    else:raise ValueError('native output was relabelled maintained')
    names.append('lane_crosslabel')
    for key,value in(('profile','ln_native_v1'),('policy12_owner_verified',True)):
        wrong=dict(image);wrong[key]=value
        need(wrong!=image,'changed paired image '+key)
        try:reader.read(raw,0,mode,placement,exit_status,wrong,pid,cpu,seed_reference)
        except ValueError as error:need(str(error)=='paired-v2 ELF admission without owner credit','exact paired image refusal '+key)
        else:raise ValueError('accepted supplied paired image '+key)
        names.append('image_'+key)

    old_seed=seed_reference[4]
    for name,value in(('seed_raw_short',old_seed[:-1]),('seed_raw_long',old_seed+b'\0'))+tuple(
            ('seed_raw_snapshot_'+str(i),changed(old_seed,(at,)))for i,at in enumerate((3672,4184,4768,5280))):
        need(digest(value)!=digest(old_seed),'changed whole seed capture '+name)
        new=seed_reference[:4]+(value,)
        try:reader.read(raw,0,mode,placement,exit_status,image,pid,cpu,new)
        except ValueError as error:need(str(error)=='whole retained authenticated seed record','exact seed capture rejection '+name)
        else:raise ValueError('accepted supplied native seed '+name)
        names.append(name)

    metadata=metadata_controls(reader,image)
    try:reader.pair(baseline,baseline)
    except ValueError as error:need(str(error)=='policy14 owner capture and mixed-policy pairing are unimplemented',
                                   'explicit pending owner API')
    else:raise ValueError('native-only input gained owner comparison authority')
    need(digest(raw)==original,'original supplied capture remains unchanged')
    # This formula fixes every row above; no length-only acceptance or omission.
    need(len(names)==451+9*COUNTS[mode]+undefined_controls,'complete supplied native rejection population')
    return dict(status='passed',scope='supplied_native_reference_corruptions_only',count=len(names),refusals=names,
        layout_controls=metadata,layout_count=20,owner_pair_unavailable=True,raw_sha256=original,
        native_operations=0,owner_validated=False,mixed_policy_validated=False,qualification_credit=False,
        performance_credit=False)


def maintained_controls(reader,raw,mode,placement,exit_status,image,pid,cpu,seed_reference):
    """Corrupt an actual maintained success without inventing native observations.

    This is an application postcondition, not an owner or paired-state gate.
    The actual owner capture and all native-to-owner state joins remain required
    independently. Fault cases have no maintained success stream to accept here.
    """
    baseline=reader.read(raw,1,mode,placement,exit_status,image,pid,cpu,seed_reference)
    need(baseline['native_reference_complete']is False and baseline['application_complete']is True and
         baseline['frames']==[] and baseline['native_instructions']==baseline['native_frames']==0 and
         baseline['owner_validated']is baseline['mixed_policy_validated']is baseline['qualification_credit']is
         baseline['performance_credit']is False,'accepted maintained application-only control base')
    need(type(mode)is int and 0<=mode<5 and len(raw)==PREFIX+SUFFIX,'actual maintained success control population')
    original=digest(raw);names=[]

    def reject(name,value,why):
        need(type(name)is str and name not in names and type(value)is bytes and digest(value)!=original,
             'unique actual nonidentity control '+name)
        try:reader.read(value,1,mode,placement,exit_status,image,pid,cpu,seed_reference)
        except ValueError as error:need(str(error)==why,'exact causal rejection '+name+': '+str(error))
        else:raise ValueError('accepted supplied maintained application corruption '+name)
        names.append(name)

    def flip(name,at,why):reject(name,changed(raw,(at,)),why)

    # Complete header population, including every reserved word. Hardware and
    # format fields have their original separate actual seed/CPUID authority.
    for word in range(64):
        if word==9:why='same-CPU qualified seed and complete format'
        elif word<14:why='exact paired source process CPU lane and placement'
        elif word in(14,15):why='actual bounded XCR0 geometry'
        elif word<27 or word==28:why='actual native signal geometry and hardware query success'
        elif word in(27,29):why='closed known enabled user-component and permission domain'
        else:why='whole paired source header and reserved words'
        flip('prefix_word_'+str(word),8*word,why)
    for row in range(67):
        flip('cpuid_identity_'+str(row),512+24*row,'exact CPUID query identities and order')
    flip('cpuid_full_result',512+24+8,'same-CPU qualified seed and complete format')
    for i in range(16):flip('seed_gpr_'+str(i),2120+8*i,'whole literal native seed data and stack')
    flip('seed_flags',2248,'whole literal native seed data and stack')
    for i in range(6):flip('seed_selector_'+str(i),2256+2*i,'whole literal native seed data and stack')
    flip('seed_reserved',2268,'complete live state and reserved tail')
    for i in range(8):flip('prefix_machine_'+str(i),2272+8*i,'complete native TLS mask and selectors')
    source_at=4022 if placement&1 else 512
    for name,offset in(('before',0),('first',source_at),('last_head',source_at+86),('second_page',4096),
                        ('last',8191),('cut_a',source_at-124),('cut_a_target',source_at-118),
                        ('cut_b',source_at+88),('cut_b_target',source_at+94),
                        ('predecessor',source_at-5),('predecessor_displacement',source_at-4)):
        flip('source_'+name,2336+offset,'whole actual paired source including E9 and both transparent cuts')
    for offset in(0,504,512,640,768,897,4096,4097,8191):
        flip('data_'+str(offset),10528+offset,'whole literal native seed data and stack')
    for offset in(0,127,128,223):flip('stack_'+str(offset),18720+offset,'whole literal native seed data and stack')

    for phase,start in(('before',256),('after',408)):
        why='whole actual entry and terminal selectors'if phase=='before'else'whole maintained terminal GPR and literal defined flags'
        for i in range(16):flip(phase+'_gpr_'+str(i),PREFIX+start+8*i,why)
        flip(phase+'_flags',PREFIX+start+128,why)
        for i in range(6):flip(phase+'_selector_'+str(i),PREFIX+start+136+2*i,'whole actual entry and terminal selectors')
        flip(phase+'_reserved',PREFIX+start+148,'complete live state and reserved tail')
    for phase,start in(('before',560),('after',624)):
        for i in range(8):flip(phase+'_machine_'+str(i),PREFIX+start+8*i,'whole native machine bracket')
    for phase,start in(('before',688),('after',2804)):
        for i in range(32):flip(phase+'_zmm_'+str(i),PREFIX+start+64*i+63,'whole actual native vector and x87 bracket')
        for i in range(8):flip(phase+'_mask_'+str(i),PREFIX+start+2048+8*i+7,'whole actual native vector and x87 bracket')
        for i in(2112,2114):flip(phase+'_x87_'+str(i),PREFIX+start+i,'whole actual native vector and x87 bracket')
    for name,start,size in(('source',4920,8192),('data',13112,8192),('stack',21304,224)):
        for off in(0,size//2,size-1):flip('after_'+name+'_'+str(off),PREFIX+start+off,'whole unchanged source data and stack')

    for i in range(32):
        flip('suffix_word_'+str(i),PREFIX+8*i,'complete maintained cleanup with zero observed native counters')
    for i in range(128):
        flip('forged_native_frame_'+str(i),FRAME_BASE+i*FRAME,'maintained application cannot fabricate native frames')
    flip('forged_native_last_byte',len(raw)-1,'maintained application cannot fabricate native frames')
    reject('truncated',raw[:-1],TYPE_ERROR);reject('extra',raw+b'\0',TYPE_ERROR)
    args=[raw,1,mode,placement,exit_status,image,pid,cpu,seed_reference]
    for name,index,value in(('lane_bool',1,True),('lane_outside',1,2),('mode_bool',2,bool(mode)),('mode_outside',2,7),
            ('placement_bool',3,bool(placement)),('placement_outside',3,4),('exit125',4,125),
            ('exit_bool',4,False),('pid_bool',6,True),('pid_zero',6,0),('cpu_bool',7,bool(cpu)),('cpu_negative',7,-1)):
        need(type(value)is not type(args[index])or value!=args[index],'changed typed argument '+name)
        new=list(args);new[index]=value
        try:reader.read(*new)
        except ValueError as error:need(str(error)==TYPE_ERROR,'exact typed rejection '+name)
        else:raise ValueError('accepted supplied maintained application argument '+name)
        names.append(name)
    new=list(args);new[1]=0
    try:reader.read(*new)
    except ValueError as error:need(str(error)=='exact paired source process CPU lane and placement','exact cross-lane rejection')
    else:raise ValueError('maintained output was relabelled native')
    names.append('lane_crosslabel')
    value=bytearray(raw);struct.pack_into('<Q',value,8,1)
    reject('native_v1_version',bytes(value),'exact paired source process CPU lane and placement')
    for key,value in(('profile','ln_native_v1'),('policy12_owner_verified',True)):
        wrong=dict(image);wrong[key]=value
        need(wrong!=image,'changed paired image '+key)
        try:reader.read(raw,1,mode,placement,exit_status,wrong,pid,cpu,seed_reference)
        except ValueError as error:need(str(error)=='paired-v2 ELF admission without owner credit','exact paired image refusal '+key)
        else:raise ValueError('accepted supplied paired image '+key)
        names.append('image_'+key)
    old_seed=seed_reference[4]
    for name,value in(('seed_raw_short',old_seed[:-1]),('seed_raw_long',old_seed+b'\0'))+tuple(
            ('seed_raw_snapshot_'+str(i),changed(old_seed,(at,)))for i,at in enumerate((3672,4184,4768,5280))):
        need(digest(value)!=digest(old_seed),'changed whole seed capture '+name)
        new=seed_reference[:4]+(value,)
        try:reader.read(raw,1,mode,placement,exit_status,image,pid,cpu,new)
        except ValueError as error:need(str(error)=='whole retained authenticated seed record','exact seed capture rejection '+name)
        else:raise ValueError('accepted supplied maintained application seed '+name)
        names.append(name)
    for fault in(5,6):
        new=list(args);new[2]=fault
        try:reader.read(*new)
        except ValueError as error:need(str(error)=='maintained read faults cannot become application success','exact maintained fault-success refusal')
        else:raise ValueError('maintained fault was relabelled success')
        names.append('fault_success_'+str(fault))
    metadata=metadata_controls(reader,image)
    try:reader.pair(baseline,baseline)
    except ValueError as error:need(str(error)=='policy14 owner capture and mixed-policy pairing are unimplemented','explicit pending owner API')
    else:raise ValueError('application-only input gained owner comparison authority')
    need(digest(raw)==original and len(names)==532 and len(set(names))==532,'complete maintained application rejection population')
    return dict(status='passed',scope='supplied_maintained_application_corruptions_only',count=len(names),refusals=names,
        layout_controls=metadata,layout_count=20,owner_pair_unavailable=True,raw_sha256=original,
        native_operations=0,owner_validated=False,mixed_policy_validated=False,qualification_credit=False,performance_credit=False)


def controls(reader,raw,lane,mode,placement,exit_status,image,pid,cpu,seed_reference):
    need(type(lane)is int and lane in(0,1),'exact paired control lane')
    fn=native_controls if lane==0 else maintained_controls
    return fn(reader,raw,mode,placement,exit_status,image,pid,cpu,seed_reference)


def metadata_controls(reader,image):
    # Metadata controls use the actual compiled layout, never a fabricated
    # positive layout. All schema/mode/width/source comparisons remain exact.
    metadata=[]
    def bad_layout(name,mutate,why):
        value=copy.deepcopy(image['layout']);mutate(value)
        need(repr(value)!=repr(image['layout']),'changed complete typed layout '+name)
        try:reader.layout_join(value,image['symbols'],image['sizes'],image['headers'])
        except ValueError as error:need(str(error)==why,'exact metadata rejection '+name)
        else:raise ValueError('accepted supplied native layout '+name)
        metadata.append(name)
    def assign(value,path,new):
        for key in path[:-1]:value=value[key]
        value[path[-1]]=new
    for name,path,new in(
        ('record',('record',),'owner14'),('uc_size',('uc_bytes',),969),
        ('frame_size',('types','ua_frame','bytes'),66785),
        ('frame_array_size',('types','lp_suffix','fields','frame','bytes'),128*66784-1),
        ('source_offset',('types','lp_prefix','fields','source','offset'),2337),
        ('field_alignment',('types','ua_frame','fields','si','alignment'),True),
        ('greg_width',('uc','widths','greg'),176),('FP_pointer_offset',('uc','offsets','fp_pointer'),232),
        ('SI_size',('si','bytes'),120),('SI_addr',('si','offsets','addr'),24)):
        bad_layout(name,lambda x,p=path,v=new:assign(x,p,v),'all actual declared native types and kernel ABI')
    for object_name in('prefix','suffix'):
        for key,value in(('address',image['symbols'][object_name]+8),('bytes',image['sizes'][object_name]+8),
                           ('alignment',4),('tag','ua_frame'),('source','unbound/main.c')):
            bad_layout(object_name+'_'+key,lambda x,n=object_name,k=key,v=value:assign(x,('objects',n,k),v),
                       'actual wire ELF/DWARF/source object '+object_name)
    need(len(metadata)==20,'fixed additive compiled-layout refusal population')
    return metadata


def elf_controls(reader,raw,native_policy,layout,headers):
    """Reject actual ELF/source corruptions before any fixture launch.

    This validates reader gates only. It cannot replace compiler-M/link/ELF
    custody, the whole native-halo checker, or the bounded process supervisor.
    """
    image=reader.elf(raw,native_policy,layout,headers);original=digest(raw);names=[]
    h=struct.unpack_from('<16sHHIQQQIHHHHHH',raw)
    ph=[struct.unpack_from('<IIQQQQQQ',raw,h[5]+56*i)for i in range(h[10])]
    sections=[struct.unpack_from('<IIQQQQIIQQ',raw,h[6]+64*i)for i in range(h[12])]
    table=next(s for s in sections if s[1]==2);strings=sections[table[6]]
    string_bytes=raw[strings[4]:strings[4]+strings[5]];records={}
    for at in range(table[4],table[4]+table[5],24):
        n,info,other,section,value,size=struct.unpack_from('<IBBHQQ',raw,at)
        name=string_bytes[n:string_bytes.index(0,n)].decode('ascii')
        if name in image['symbols']:records[name]=(at,strings[4]+n)

    def offset(address,n=1):
        owners=[p for p in ph if p[0]==1 and p[3]<=address and n<=p[5]and address-p[3]<=p[5]-n]
        need(len(owners)==1,'actual admitted control file range');p=owners[0]
        return p[2]+address-p[3]

    def reject(name,value,why):
        need(name not in names and type(value)is bytes and digest(value)!=original,'unique changed ELF '+name)
        try:reader.elf(value,native_policy,layout,headers)
        except ValueError as error:need(str(error)==why,'exact ELF rejection '+name+': '+str(error))
        else:raise ValueError('accepted supplied native ELF corruption '+name)
        names.append(name)

    for name,at in(('magic',0),('class',4),('type',16),('machine',18)):
        reject(name,changed(raw,(at,)),'exact ET_EXEC x86-64 header')
    reject('short',raw[:63],'complete bounded ELF')
    load_index=next(i for i,p in enumerate(ph)if p[0]==1 and p[1]==6)
    reject('writable_executable',changed(raw,(h[5]+load_index*56+4,)),'complete non-WX loads and no TLS')
    for name in('lp_entry','lp_steps','lp_backwards','lp_cuts'):
        reject(name,changed(raw,(offset(image['symbols'][name]),)),'literal independent native case table '+name)
    for name in('lp_source_page','lp_base_offset','lp_predecessor_offset'):
        reject(name,changed(raw,(offset(image['symbols'][name]),)),'whole actual paired geometry table '+name)
    reject('template',changed(raw,(offset(image['symbols']['loop_native_template'])+143,)),
           'whole original144-byte nonexecuting loader reference')
    for name in('pure','helper'):
        reject(name+'_halo',changed(raw,(offset(image['symbols']['region_app_'+name]-4096),)),
               'whole actual high helper and CC halos')
    reject('vector_constants',changed(raw,(offset(image['symbols']['ua_vectors'])+2047,)),
           'whole nonexecuting vector/mask constants')
    reject('mask_constants',changed(raw,(offset(image['symbols']['ua_masks'])+63,)),
           'whole nonexecuting vector/mask constants')
    reject('symbol_missing',changed(raw,(records['lp_entry'][1],)),'all actual native fixture symbols')
    for name in('prefix','suffix'):
        reject(name+'_symbol_size',changed(raw,(records[name][0]+16,)),'whole native wire BSS object '+name)
    for suffix in('tunables_loop_paired_app/main.c','tunables_loop_paired_app/reference.c','tunables_loop_paired_app/fixture.h',
                   'tunables_loop_paired_app/machine.S','tunables_loop_paired_app/loop_bytes.S',
                   'persistent_direct_frontier_app/app.h','persistent_direct_frontier_app/pure.c',
                   'persistent_direct_frontier_app/entry.S'):
        path=next(p for p in headers if p.endswith('/tools/page-entry/selected/tests/'+suffix))
        wrong=copy.deepcopy(headers);wrong[path]['bytes']+=1
        need(wrong!=headers,'changed whole compiler dependency '+suffix)
        try:reader.elf(raw,native_policy,layout,wrong)
        except ValueError as error:need(str(error)=='whole fixture source dependency '+suffix,'exact source rejection '+suffix)
        else:raise ValueError('accepted supplied native compiler dependency '+suffix)
        names.append('source_'+suffix)
    need(len(names)==29 and len(set(names))==29 and digest(raw)==original,'complete actual ELF/source rejection population')
    return dict(status='passed',scope='supplied_native_ELF_source_corruptions_only',count=29,refusals=names,
        elf_sha256=original,native_operations=0,owner_validated=False,mixed_policy_validated=False,
        qualification_credit=False,performance_credit=False)
