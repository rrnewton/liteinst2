"""Pure complete-frame commit expectations beneath separate authentic ingress checks.

The enclosing observer/reader must first authenticate actual NX or restored UD2,
source ownership/bytes, decoded input, kernel layout/FP extent and seed state.
These functions never turn a landing frame into an original-PC NX frame.
"""
import struct
from page_selected import need

U64=(1<<64)-1
GREG=(13,14,12,11,15,10,9,8,0,1,2,3,4,5,6,7)
PID,TID=0x4c320001,0x4c320002
CLOCK_BASE,AUX=0x1122334400000000,0xc001c0de


def word(data,offset):
    need(type(data)is bytes and 0<=offset<=len(data)-8,'complete actual scalar extent')
    return struct.unpack_from('<Q',data,offset)[0]


def state(before,after,fp_before,fp_after,uc_bytes,greg_offset,fp_offset,fp_bytes):
    need(type(before)is bytes and type(after)is bytes and len(before)==len(after)==2048 and
         type(uc_bytes)is int and 0<uc_bytes<=2048 and type(greg_offset)is int and
         0<=greg_offset and greg_offset+23*8<=uc_bytes and type(fp_offset)is int and
         0<=fp_offset<=uc_bytes-8,'actual full UC and authenticated layout bounds')
    need(before[uc_bytes:]==after[uc_bytes:]==bytes(2048-uc_bytes),'complete unused UC storage remains zero')
    need(type(fp_before)is bytes and type(fp_after)is bytes and len(fp_before)==len(fp_after)==65536 and
         type(fp_bytes)is int and 512<=fp_bytes<=65536 and fp_before==fp_after and
         not any(fp_before[fp_bytes:]),'complete initialized kernel FP/XSAVE and unused storage unchanged')
    need(word(before,fp_offset)==word(after,fp_offset)!=0,'actual unchanged FP pointer')
    return [word(before,greg_offset+8*i)for i in GREG]


def clock(before,after,fp_before,fp_after,layout,inputs,result,configured=True):
    g=state(before,after,fp_before,fp_after,**layout)
    # Input is [abi,kind,original_pc,next_pc,logical_flags,ordinal]. It is joined
    # to an authenticated decoded/handoff row by the enclosing ingress reader.
    need(type(inputs)is list and len(inputs)==6 and all(type(x)is int and 0<=x<=U64 for x in inputs),
         'exact retained scalar clock input')
    abi,kind,pc,next_pc,flags,ordinal=inputs
    need(abi==1 and kind in(5,6) and next_pc==pc+(2 if kind==5 else 3) and
         not flags&0x10100 and 1<=ordinal<=0xffffffff,'typed clock kind, continuation, flags and finite ordinal')
    need(type(result)is list and len(result)==3 and all(type(x)is int and 0<=x<=U64 for x in result),
         'complete actual clock result')
    value,aux,reserved=result
    need(not reserved and aux<1<<32 and (kind==6 or aux==0),'clock result fields')
    if configured:need(value==CLOCK_BASE+(ordinal<<8) and aux==(AUX if kind==6 else 0),'independent literal configured clock/AUX')
    else:need(value>0,'actual nonzero native clock, joined to raw sample by caller')
    expected=bytearray(before);off=layout['greg_offset']
    for slot,value in ((13,value&0xffffffff),(12,value>>32),(16,next_pc),(17,flags)):
        struct.pack_into('<Q',expected,off+slot*8,value)
    if kind==6:struct.pack_into('<Q',expected,off+14*8,aux)
    need(bytes(expected)==after,'complete clock UC equality except exact named destination/PC/flags writes')
    return dict(kind=kind,ordinal=ordinal,clock=result[0],aux=aux,nondestination_gprs=13 if kind==6 else 14,
                full_uc_bytes=layout['uc_bytes'],full_fp_bytes=layout['fp_bytes'])


def syscall(before,after,fp_before,fp_after,layout,inputs,result,actual_result,replaced):
    g=state(before,after,fp_before,fp_after,**layout)
    # ABI/reserved, pc/next/flags/number, six args, original RCX/R11.
    need(type(inputs)is list and len(inputs)==14 and all(type(x)is int and 0<=x<=U64 for x in inputs),
         'exact retained full scalar syscall input')
    abi,reserved,pc,next_pc,flags,number,*tail=inputs;args,rcx,r11=tail[:6],tail[6],tail[7]
    need(abi==1 and reserved==0 and next_pc==pc+2 and not flags&0x10100 and
         number==g[0] and args==[g[i]for i in(7,6,2,10,8,9)] and rcx==g[1] and r11==g[11],
         'all original syscall operands and original clobber registers match actual effect-entry frame')
    need(type(result)is list and len(result)==3 and all(type(x)is int and 0<=x<=U64 for x in result) and
         type(actual_result)is int and 0<=actual_result<=U64 and type(replaced)is bool,'exact syscall decision/result domains')
    action,padding,value=result
    need(padding==0 and action==int(replaced),'explicit native/replacement action')
    if replaced:
        need(number in(39,186) and value==(PID if number==39 else TID) and actual_result==value,
             'only independently tagged getpid/gettid replacement, never a native-entered claim')
    else:need(value==0,'native pass-through decision has no synthetic result')
    expected=bytearray(before);off=layout['greg_offset']
    for slot,value in ((13,actual_result),(14,next_pc),(3,flags),(16,next_pc),(17,flags)):
        struct.pack_into('<Q',expected,off+slot*8,value)
    need(bytes(expected)==after,'complete syscall UC equality except RAX/RCX/R11/PC/logical flags')
    return dict(number=number,replaced=replaced,result=actual_result,input_argument_count=6,
                full_uc_bytes=layout['uc_bytes'],full_fp_bytes=layout['fp_bytes'])


def failed_frame(before,terminal,fp_before,fp_terminal,layout,kind,next_pc,flags,syscall_preclobbered):
    state(before,terminal,fp_before,fp_terminal,**layout)
    need(kind in(5,6,7) and type(syscall_preclobbered)is bool and not flags&0x10100,
         'named actual failure route')
    expected=bytearray(before)
    if syscall_preclobbered:
        need(kind==7,'only old syscall dispatch has the pre-dispatch clobber prefix')
        for slot,value in ((14,next_pc),(3,flags),(16,next_pc),(17,flags)):
            struct.pack_into('<Q',expected,layout['greg_offset']+slot*8,value)
    need(bytes(expected)==terminal,'complete retained failed outer UC, including the precise old syscall partial clobbers')
    return dict(application_continued=False,callback_completion=False,syscall_preclobbered=syscall_preclobbered)
