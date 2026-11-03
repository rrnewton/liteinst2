"""Genuine CACHE8 guest effects: full ABA result or an exact native fault prefix.

The configured common reader retains its original ABC169 API. This module
supplies an explicit version2 model and never rewrites captured bytes.
"""
import hashlib
import struct
from functools import partial
from types import SimpleNamespace

KINDS=(2,3,4)
APP_MAGIC=0x314145384332494c
TAIL=512
STATE=0x800000
STEPS=(0,1,4,7,82,83,83,86,89,164,165,167)
FULL_STEPS=(0,1,4,7,82,83,111,114,117,192,193,195)
WINDOW=(0,7,14,21,28,35,42,52,57,62,67,72,74,81,91,101,106,111,
        113,120,130,137,144,151,158,165,172,179)


def need(ok,why):
    if not ok:raise ValueError(why)


def q(data,offset=0,count=1):return struct.unpack_from('<'+'Q'*count,data,offset)


def _kind(kind):
    need(type(kind)is int and kind in KINDS,'literal real-effect selector')
    return kind


def _reset_bytes(kind):
    """Literal test instructions, not an admission or instruction decoder."""
    body=bytearray();first=0x416000
    def rip(op,target,tail=b''):
        body.extend(op+struct.pack('<i',target-(first+len(body)+len(op)+4+len(tail)))+tail)
    if kind==2:
        for op,offset in ((b'\x48\x89\x05',0),(b'\x48\x89\x0d',8),(b'\x48\x89\x15',16),
                          (b'\x48\x89\x35',24),(b'\x48\x89\x3d',32),(b'\x4c\x89\x1d',40)):
            rip(op,STATE+offset)
        rip(b'\xc7\x05',STATE+64,struct.pack('<I',1))
        body.extend(bytes.fromhex('bf00204100be00100000ba01000000b80a0000000f05'))
        rip(b'\x48\x89\x05',STATE+48)
        rip(b'\xc7\x05',STATE+72,struct.pack('<I',1))
        rip(b'\xc7\x05',STATE+80,struct.pack('<I',1))
        body.extend(bytes.fromhex('ba05000000b80a0000000f05'))
        rip(b'\x48\x89\x05',STATE+56)
        rip(b'\xc7\x05',STATE+88,struct.pack('<I',1))
        for op,offset in ((b'\x48\x8b\x0d',8),(b'\x48\x8b\x15',16),(b'\x48\x8b\x35',24),
                          (b'\x48\x8b\x3d',32),(b'\x4c\x8b\x1d',40),(b'\x48\x8b\x05',0)):
            rip(op,STATE+offset)
        body.extend(bytes.fromhex('48c7c108000000'));rip(b'\xe9',0x410200)
    elif kind==3:body.extend(bytes.fromhex('c60425002441005a0f0b'))
    else:rip(b'\x48\x8b\x05',STATE+96);body.extend(bytes.fromhex('ffe0'))
    need(len(body)=={2:184,3:10,4:9}[kind],'literal complete effect-window encoding length')
    return bytes(body)


def _elf(common,kind,data,native_policy):
    _kind(kind)
    sites={'lc8e_state':STATE,'region_app_effect_end':0x416000+{2:184,3:10,4:9}[kind]}
    if kind==2:sites.update(region_app_effect_syscall0=0x416048,region_app_effect_syscall1=0x41606f)
    elif kind==3:sites['region_app_effect_write']=0x416000
    else:sites.update(region_app_effect_load=0x416000,region_app_effect_jump=0x416007)
    body=_reset_bytes(kind)
    def reset(symbols,sizes,memory,loads):
        need(all(symbols[name]==value for name,value in sites.items()) and sizes['lc8e_state']==256,
             'exact real effect sites and complete guest state object')
        need(symbols['region_app_reset']==0x416000 and sizes['region_app_reset']==len(body) and
             symbols['region_app_reset_jump']==0x416000+{2:179,3:8,4:7}[kind] and
             symbols['region_app_reset_end']==0x417000 and memory(0x416000,4096)[0][1]==5 and
             memory(0x416000,4096)[1]==body+b'\xcc'*(4096-len(body)),
             'whole actual effect reset page, every opcode and displacement')
        state=[p for p in loads if p[3]<=STATE<p[3]+p[6]]
        need(len(state)==1 and state[0][1]==6 and state[0][3]==STATE and state[0][5:7]==(0,4096),
             'one exact zero-file whole RW/NX original effect-state page')
    image=common.elf(data,native_policy,variant=dict(symbols=tuple(sites),reset=reset))
    image['effect']=dict(kind=kind,sites=sites,reset_bytes=body,total_instructions=195 if kind==2 else None)
    return image


def _model(common,kind,prefix):
    """Shared ABC semantics plus each of the28 actual guest window instructions."""
    pc=prefix['predecessor'];g=list(prefix['seed'][0]);flags=prefix['seed'][1]
    data,stack=prefix['data'],prefix['stack'];state=[0]*32
    out=[(pc,tuple(g),flags,data,stack)];states=[tuple(state)]
    while pc!=prefix['expected_exit_pc']:
        if pc==0x416000 and kind!=2:break
        if 0x416000<=pc<0x4160b8:
            off=pc-0x416000;need(kind==2 and off in WINDOW,'exact actual window instruction')
            i=WINDOW.index(off);next_pc=0x416000+(WINDOW[i+1]if i+1<len(WINDOW)else 184)
            if i<6:state[i]=g[(0,1,2,6,7,11)[i]]
            elif off in (42,81,91,120):state[{42:8,81:9,91:10,120:11}[off]]=1
            elif off==52:g[7]=0x412000
            elif off==57:g[6]=4096
            elif off in (62,101):g[2]=1 if off==62 else 5
            elif off in (67,106):g[0]=10
            elif off in (72,111):
                need(g[0]==10 and g[7]==0x412000 and g[6]==4096 and g[2]==(1 if off==72 else 5),
                     'both literal modeled guest mprotect calls')
                g[1]=next_pc;g[11]=flags;g[0]=0
            elif off in (74,113):state[6 if off==74 else 7]=g[0]
            elif off in (130,137,144,151,158,165):
                register,word={130:(1,1),137:(2,2),144:(6,3),151:(7,4),158:(11,5),165:(0,0)}[off]
                g[register]=state[word]
            elif off==172:g[1]=8
            elif off==179:next_pc=0x410200
            else:raise ValueError('unmodelled actual effect instruction')
            pc=next_pc
        else:pc,g,flags,data,stack=common.instruction(pc,g,flags,data,stack,prefix)
        out.append((pc,tuple(g),flags,data,stack));states.append(tuple(state))
        need(len(out)<=196,'finite exact real-effect model')
    need(len(out)==(196 if kind==2 else 84),'all195 instructions or exact83-instruction native prefix')
    need(out[83][0]==0x416000 and (kind!=2 or out[111][0]==0x410200),
         'actual effect window starts after83 and ends after111 instructions')
    return out,states


def _frame_spec(common,kind,prefix,index):
    model,_=_model(common,kind,prefix)
    complete_step=FULL_STEPS[index] if kind==2 else (0,1,4,7,82,83,83)[index]
    pc,g,flags,_,_=model[complete_step]
    fault=kind==3 and index==6;nx=index==0 or kind==2 and index==6
    signal=11 if nx or fault else 5;address=0x412400 if fault else pc
    cr2=address if signal==11 else (0x410200 if kind==2 and index>6 else prefix['predecessor'])
    return dict(signal=signal,pc=pc,greg=g,flags=flags|(common.RF if signal==11 else common.TF),
                address=address,cr2=cr2,exception=(7 if fault else 21,14)if signal==11 else(0,1))


def _variant(common,kind):
    return dict(kind=kind,profile=(2,167 if kind==2 else 83,STEPS),
                frame=partial(_frame_spec,common,kind))


def _prefix(common,kind,data,mode,native,image,pid,cpu,seed_reference,**unused):
    need(not unused or unused==dict(reference='cache8-effects'+str(kind)),'literal effect reference')
    return common._prefix(data,mode,native,image,pid,cpu,seed_reference,variant=_variant(common,kind))


def _tail(common,kind,data,result,native):
    need(len(data)==TAIL,'complete actual512-byte effect tail')
    h=q(data,0,32);state=q(data,256,32)
    stopped=0 if kind==2 else 1 if kind==3 else 2
    frames=12 if kind==2 else 7 if kind==3 else 6
    want=[0]*32;want[:5]=[APP_MAGIC,1,TAIL,kind,int(native)]
    if native:want[5:9]=[1,1,0,1]
    if native and kind==2:want[9:13]=[1,1,1,0]
    want[13:16]=[stopped,(167 if kind==2 else 83)if native else 0,frames if native else 0]
    if kind==3:want[16:18]=[11,0x412400]
    want[18:20]=[STATE,256]
    need(h==tuple(want),'exact real native window, syscall results and partial-completion tail')
    _,states=_model(common,kind,result)
    need(state==states[-1],'every actual effect-state byte equals the literal guest model')
    return dict(header=h,state=state,complete=kind==2,total_instructions=195 if kind==2 else None,
                native_tf_events=167 if native and kind==2 else 83 if native else 0)


def _read(common,kind,data,mode,native,exit_status,image,pid,cpu,seed_reference,**kwargs):
    _kind(kind);need(type(native)is bool and mode==0,'literal native or gated real-effect role')
    need(not kwargs or kwargs==dict(reference='cache8-effects'+str(kind)),'one exact real-effect reference')
    full=kind==2 or native
    need(type(data)is bytes and exit_status==(0 if full else 125) and
         len(data)==common.PREFIX+(common.SUFFIX+TAIL if full else 0),
         'literal complete or partial real-effect process outcome and whole output')
    if kind==2:
        result=common.read(data[:-TAIL],mode,native,exit_status,image,pid,cpu,seed_reference,
                           variant=_variant(common,kind))
    else:
        result=_prefix(common,kind,data[:common.PREFIX],mode,native,image,pid,cpu,seed_reference)
        if native:
            suffix=data[common.PREFIX:-TAIL];end=q(suffix,0,16);n=7 if kind==3 else 6;fault=int(kind==3)
            need(end==(common.MAGIC^1,2,0,1,0,0,0,n,83,fault,0,0,0,0,0,0) and
                 suffix[128:400]==bytes(272),'truthful native stop before application completion and registration')
            value=suffix[400:];h=q(value,0,16);before=common.live(value[128:280])
            selectors=struct.pack('<6H',0x33,0x2b,0,0,0,0)
            need(h==(1,0,n,83,fault,1,0,0,0,0,0,0,0,0,0,0) and
                 before==(result['seed'][0],result['seed'][1],selectors) and
                 value[280:432]==bytes(152) and q(value,432,8)==result['machine'] and
                 value[496:560]==bytes(64) and value[560:2676]==common.LIVE_SEED and
                 value[2676:4792]==bytes(common.LIVE),'whole real before-state with no invented after-state')
            model,_=_model(common,kind,result)
            need(value[4792:29368]==result['source'] and value[29368:29592]==result['stack'] and
                 value[29592:37784]==model[-1][3],'whole native partial source/stack/data at the actual stop')
            frames=[]
            for i in range(12):
                raw=value[37784+i*common.FRAME:37784+(i+1)*common.FRAME]
                if i>=n:need(raw==bytes(common.FRAME),'all unobserved native frames wholly zero')
                else:frames.append(common.reference_frame(raw,result,image,i,(0,1,4,7,82,83,83)[i],0,
                                                         spec=_frame_spec(common,kind,result,i)))
            need(all(f['fp']==frames[0]['fp']for f in frames),'whole actual partial native FP state conserved')
            result['observations']=[dict(before=before,after=None,live=common.LIVE_SEED,frames=frames,
                header=h,machine=result['machine'],data=model[-1][3],stack=result['stack'])]
            result['suffix']=dict(end=end);result['effects']=[]
    result['effect_kind']=kind;result['application_complete']=kind==2
    result['effect_tail']=_tail(common,kind,data[-TAIL:],result,native)if full else None
    return result


def _controls(common,kind,data,mode,native,exit_status,image,pid,cpu,seed_reference,**kwargs):
    need(native is True,'only actual native effect reference controls')
    _read(common,kind,data,mode,native,exit_status,image,pid,cpu,seed_reference,**kwargs)
    if kind==2:tests=list(common.control_sites())
    else:
        names=('version','CPU','hardware','seed_GPR','source','stack','data','registration_result',
               'publication_word','whole_live_vector','native_FP','A_to_B_flags','cold_C_entry_PC',
               'first_joint_exit_RAX','reset_entry_RCX','no_prefix_registration_before',
               'no_prefix_registration_after','peer_source_pair','peer_second_page','six_source_extent',
               'observed_peer_source','third_source_pair','third_second_page','observed_third_source','third_root_header')
        tests=[x for x in common.control_sites()if x[0]in names and x[0]!='whole_live_vector']
        tests.append(('actual_partial_live',common.PREFIX+400+560))
    at=len(data)-TAIL
    tests.extend((f'effect_tail_{i}',at+8*i)for i in (0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19))
    tests.extend((f'effect_state_{i}',at+256+8*i)for i in range(32))
    need(len(tests)==(97 if kind==2 else 77) and len({x[0]for x in tests})==len(tests),
         'fixed full native-effect corruption population')
    refused=[]
    for name,offset in tests:
        changed=bytearray(data);changed[offset]^=1
        try:_read(common,kind,bytes(changed),mode,native,exit_status,image,pid,cpu,seed_reference,**kwargs)
        except ValueError:refused.append(name)
        else:raise ValueError('actual native effect corruption accepted '+name)
    return dict(original_sha256=hashlib.sha256(data).hexdigest(),refusals=refused,native_operations=0)


def configured(common,kind):
    _kind(kind)
    return SimpleNamespace(PREFIX=common.PREFIX,SUFFIX=common.SUFFIX,FP=common.FP,MASK=common.MASK,
        TF=common.TF,RF=common.RF,GREG=common.GREG,FRAME=common.FRAME,kind=kind,
        elf=partial(_elf,common,kind),read=partial(_read,common,kind),
        controls=partial(_controls,common,kind),_prefix=partial(_prefix,common,kind),
        application_pair=common.application_pair,
        trace_model=lambda prefix:_model(common,kind,prefix)[0],
        model=partial(_model,common,kind))
