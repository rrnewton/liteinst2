"""Data-only clock query component/application oracle; no runtime invocation.

The supplied pin in the component earns no kernel-registration credit. Its
unchanged provider canonical() compares the complete qualified architectural
XSAVE domain. Production registration/dispatch are separate application rows.
"""
import hashlib,struct
from page_selected import need
U=(1<<64)-1
MAGIC=0x31534552474b4c43
APP=0x3150504152474b43
GREG=(13,14,12,11,15,10,9,8,0,1,2,3,4,5,6,7)
FP=65536
UC=2048
LANE=128+384+4*FP+2*UC+1024+8192+16384
SIZE=640+2*LANE

def component(data,mode,original):
    need(type(data)is bytes and len(data)==SIZE and mode in range(5),'complete finite component wire')
    at=0
    def take(n):
        nonlocal at
        v=data[at:at+n];at+=n;need(len(v)==n,'complete component field');return v
    h=struct.unpack('<64Q',take(512));parts=[struct.unpack('<4I',take(16))for _ in range(8)]
    need(h[:3]==(MAGIC,1,mode) and h[3]%4096==4094 and h[4]>0 and h[4]%4096==0 and
         h[6]==h[5]&0x2e7 and h[6]&3==3 and 0<h[7]<=UC and h[8]+23*8<=h[7] and
         h[9]+8<=h[7] and h[10]+8<=h[7] and h[11]==U^sum(1<<(s-1)for s in(9,11,19)) and
         h[12]>0 and h[12]%32==8 and h[13]>0 and h[14]==2 and not any(h[15:]),'literal header/profile/initialized remainder')
    lanes=[];expected_result=(0,0,-22,-22,-14)[mode]&U
    destination=0 if mode in(1,3)else h[4]
    for index in range(2):
        q=struct.unpack('<16Q',take(128));pre=struct.unpack('<24Q',take(192));post=struct.unpack('<24Q',take(192))
        prefp,postfp,kb,ka=[take(FP)for _ in range(4)];ub,ua=take(UC),take(UC)
        sb,sa=take(512),take(512);ob,oa=take(4096),take(4096);cb,ca=take(8192),take(8192)
        need(q[:5]==(index,expected_result,index,index,destination) and q[8]==0 and not any(q[13:]),'actual native/component outcome and issue population')
        expected=[0xa112233445566700+i*0x01010101010101 for i in range(16)]+[0xad7]
        expected[0]=229;expected[4]=pre[4];expected[6]=destination;expected[7]=U if mode in(2,3)else 4
        need(pre[:17]==tuple(expected) and pre[4]>256 and pre[4]%4096==0 and pre[23]>>48==0,'literal seeded GPR/flags and stack')
        expected[0]=expected_result;expected[1]=h[3]+2;expected[11]=pre[16]
        need(post[:17]==tuple(expected) and pre[18:24]==post[18:24] and pre[20:22]==post[20:22]==(0,0),
             'complete resumed syscall algebra and actual FS/GS/selectors')
        need(pre[17]&h[5]&~h[6]==post[17]&h[5]&~h[6]==0,'no unknown active extended-state component')
        qualified=original.canonical(prefp,h[6],parts)
        need(original.canonical(postfp,h[6],parts)==qualified,'unchanged original complete qualified XSAVE comparator')
        need(sb==sa==bytes((19+i*29)&255 for i in range(512)) and cb==ca and cb[4094:4096]==b'\x0f\x05' and
             cb[:4094]==bytes(4094) and cb[4096:4102]==b'\xff\x25\x00\x00\x00\x00' and
             int.from_bytes(cb[4102:4110],'little')>0 and cb[4110:]==bytes(8192-4110),
             'complete stack and both actual source pages unchanged')
        need(ob==b'\xa5'*4096,'complete independent output-page seed')
        if mode==0:
            sec,nsec=struct.unpack('<qq',oa[:16]);need(sec>=0 and 0<=nsec<10**9 and (sec or nsec)and oa[16:]==ob[16:],
                'real normalized positive resolution and exact16-byte write set')
        else:need(oa==ob,'NULL/error leaves whole destination page unchanged')
        if index:
            need(512<=q[5]==q[6]<=FP and q[7]>0 and q[9:13]==(1,int(bool(destination)),destination,destination+16 if destination else 0),
                 'actual supplied-pin guard exact optional span counters')
            need(kb==ka and kb[q[5]:]==bytes(FP-q[5]) and original.canonical(kb,h[6],parts)==qualified,
                 'complete actual kernel FP before/after and independent pre-state equality')
            need(ub[h[7]:]==ua[h[7]:]==bytes(UC-h[7]) and struct.unpack_from('<Q',ub,h[9])[0]==q[7] and
                 struct.unpack_from('<Q',ua,h[9])[0]==q[7] and struct.unpack_from('<Q',ub,h[10])[0]==h[11],
                 'actual initialized whole UC/FP owner and signal mask')
            g=struct.unpack_from('<23Q',ub,h[8]);need(tuple(g[i]for i in GREG)==pre[:16] and g[16]==h[3] and
                 g[17]==pre[16]|0x10000 and g[19:21]==(21,14),'genuine NX frame and every original register')
            wanted=bytearray(ub)
            for slot,value in((13,expected_result),(14,h[3]+2),(3,pre[16]),(16,h[3]+2),(17,pre[16])):
                struct.pack_into('<Q',wanted,h[8]+slot*8,value)
            need(bytes(wanted)==ua,'complete frame differs only by explicit syscall result/nextPC/flags semantics')
        else:need(not any(q[5:])and kb==ka==bytes(FP)and ub==ua==bytes(UC),'native lane has no fabricated signal observation')
        lanes.append((pre,post,qualified,sb,oa,cb))
    need(at==len(data) and lanes[0]==lanes[1],'same-address independent native and guarded component full equality')
    return dict(case=mode,pairs=1,actual_kernel_queries=2,kernel_fp_bytes=q[5],qualified_xstate_bytes=len(qualified),
        gpr_words=17,output_bytes=4096,stack_bytes=512,source_bytes=8192,component_pin_supplied=True,kernel_registration_credit=False)

def application(data,mode,pid):
    need(type(data)is bytes and len(data)==4224 and mode in range(5),'complete normal-loader output')
    h=struct.unpack('<16Q',data[:128]);page=data[128:]
    need(h[:6]==(APP,1,mode,U if mode in(2,3)else 4,(0,0,-22,-22,-14)[mode]&U,4096)and
         0<h[6]<=U-32 and h[6]%32==0 and h[7]==0 and h[8]==pid and not any(h[9:]),
         'literal query result and actual process/default-rseq address')
    if mode==0:
        sec,nsec=struct.unpack('<qq',page[:16]);need(sec>=0 and 0<=nsec<10**9 and(sec or nsec)and page[16:]==b'\xa5'*4080,'actual resolution exact write set')
    else:need(page==b'\xa5'*4096,'whole no-write output')
    return dict(case=mode,result=(0,0,-22,-22,-14)[mode],address=h[6],pid=pid,page=page)

def pair(native,gated):
    need(native['case']==gated['case']and native['result']==gated['result']and native['page']==gated['page'],
         'exact native/gated result and complete output-page equality; actual PIDs/addresses stay distinct')
    return dict(case=native['case'],result=native['result'],page_sha256=hashlib.sha256(native['page']).hexdigest(),output_bytes=4096)

def component_controls(data,mode,original):
    component(data,mode,original);changes=(('native_result',640+8),('guard_result',640+LANE+8),
        ('post_gpr',640+128+192+24),('guard_fp',640+LANE+128+384+FP),
        ('guard_frame',640+LANE+128+384+4*FP+UC+40+8*11),('output_tail',len(data)-16384-1))
    for name,offset in changes:
        altered=bytearray(data);altered[offset]^=1
        try:component(bytes(altered),mode,original)
        except (ValueError,original.Mismatch):pass
        else:raise ValueError('copied component corruption accepted '+name)
    return len(changes)
