"""Authenticated standard-XSAVE envelope join; never canonicalizes state bytes."""
import hashlib,struct
KNOWN=(1<<0)|(1<<1)|(1<<2)|(1<<5)|(1<<6)|(1<<7)|(1<<9)
SIZES={2:256,5:64,6:512,7:1024,9:8}
MAGIC=0x315446584232494c
FORMAT_BYTES=3536
def need(ok,why):
    if not ok:raise ValueError(why)
def q(b,at=0):return struct.unpack_from('<Q',b,at)[0]
def u32(b,at):return struct.unpack_from('<I',b,at)[0]
def profile(cpuid,xcr0,supported,permitted,cpu,node):
    need(type(cpu)is int and cpu>=0 and type(node)is int and node>=0 and all(type(x)is int and 0<=x<1<<64 for x in(xcr0,supported,permitted)),
         'actual CPU/XCR0/permission scalar types')
    need(len(cpuid)==67 and all(type(r)in(tuple,list)and len(r)==6 and all(type(x)is int and 0<=x<1<<32 for x in r)for r in cpuid),
         'all actual CPUID words retained')
    cp=tuple(tuple(r)for r in cpuid)
    need(tuple(r[:2]for r in cp)==((0,0),(1,0),(7,0))+tuple((13,i)for i in range(64)),
         'exact CPUID query identities and order')
    need(cp[0][2]>=13 and cp[1][4]&0x0c000000==0x0c000000,'actual XSAVE/OSXSAVE capability')
    user=cp[3][2]|cp[3][5]<<32
    need(user&3==3 and not user&~KNOWN and user==xcr0==supported==permitted,
         'closed known enabled user-component and permission domain')
    need(user&0xe0 in(0,0xe0)and(not user&0xe0 or user&7==7)and
         not user&(cp[4][4]|cp[4][5]<<32),'architecturally dependent user feature groups and separate supervisor state')
    extent=cp[3][3]
    need(576<=extent==cp[3][4]<65536,'complete current/max standard extent')
    ranges=[]
    for bit in range(2,64):
        r=cp[3+bit]
        if user>>bit&1:
            size,offset,flags,reserved=r[2:]
            need(bit in SIZES and size==SIZES[bit] and offset>=576 and size<=extent-offset and
                 not flags&~2 and reserved==0,'actual standard user-component descriptor')
            ranges.append((offset,offset+size,bit))
    ranges.sort()
    need(all(a[1]<=b[0]for a,b in zip(ranges,ranges[1:])) and
         max([576]+[r[1]for r in ranges])==extent,'complete nonoverlapping standard component extent')
    return dict(cpu=cpu,node=node,mask=user,extent=extent,components=tuple(ranges),cpuid=cp,
                xcr0=xcr0,supported=supported,permitted=permitted)

def pair(nt,signal,facts,boundary):
    need(type(nt)is bytes and type(signal)is bytes,'raw complete envelopes required')
    extent,mask=facts['extent'],facts['mask']
    need(len(nt)==extent and len(signal)==extent+4,'exact independently established extents')
    need(q(nt,464)==mask and not any(nt[472:512]),'actual NT OS mask and software padding')
    need((u32(signal,464),u32(signal,468),q(signal,472),u32(signal,480))==
         (0x46505853,extent+4,mask,extent)and not any(signal[484:512])and
         u32(signal,extent)==0x46505845,'complete actual Linux signal envelope')
    need(q(nt,520)==q(signal,520)==0 and not any(nt[528:576])and not any(signal[528:576]),
         'uncompacted standard XSAVE and reserved header bytes')
    need(q(nt,512)==q(signal,512)and not q(nt,512)&~mask,'all actual active components within the authenticated layout')
    for begin,end,bit in facts['components']:
        need(576<=begin<end<=len(nt)and end<=len(signal)-4,'every enabled component physically present')
    # This original predicate compares every architectural byte, including all
    # inactive payload, FIP/FDP, MXCSR and XSTATE_BV. It is not replaced here.
    boundary.fp_payload(nt,signal)

def measurement(raw,checker,boundary):
    result=checker.inspect(raw)
    need(result.get('capture_complete')is True and result.get('cross_mode_semantic_agreement')is False,
         'accepted actual same-subject probe without borrowed comparison credit')
    h=struct.unpack_from('<64Q',raw);hw=struct.unpack_from('<32Q',raw,512)
    cp=[struct.unpack_from('<6I',raw,768+24*i)for i in range(67)]
    facts=profile(cp,hw[4],hw[7],hw[9],hw[2],hw[3])
    need(hw[2]==hw[11]==h[43]and hw[3]==hw[12]==h[44]and
         hw[7]==h[40]and hw[9]==h[41],'same actual CPU and permission observations across delivery')
    nt=raw[2720:2720+h[14]];signal=raw[70432:70432+h[34]]
    pair(nt,signal,facts,boundary)
    return facts,dict(scope='one_actual_same_subject_standard_xsave_format',nt_bytes=len(nt),signal_bytes=len(signal),
        mask=facts['mask'],active=q(nt,512),architectural_ranges_equal=True,
        raw_sha256=hashlib.sha256(raw).hexdigest(),general_host_guarantee=False)

def trailer(raw,layout,expected):
    need(type(raw)is bytes and len(raw)==FORMAT_BYTES,'complete separate format evidence trailer')
    need(set(layout)=={'b2_format_record','b2_format_sample'},'actual emitted format DWARF types')
    rt,st=layout['b2_format_record'],layout['b2_format_sample']
    need(rt=={'bytes':3536,'fields':{'h':{'offset':0,'bytes':64},'sample':{'offset':64,'bytes':3472}}}and
         st=={'bytes':1736,'fields':{'h':{'offset':0,'bytes':128},'cpuid':{'offset':128,'bytes':1608}}},
         'complete actual emitted format layout')
    need(struct.unpack_from('<8Q',raw)==(MAGIC,1,FORMAT_BYTES,2,0,0,0,0),'two complete independently retained format samples')
    observed=[]
    for index in range(2):
        at=64+1736*index;h=struct.unpack_from('<16Q',raw,at)
        need(h[0:5]==(index,1,1,0,0)and h[7]==1 and h[9]==h[11]==h[13]==0 and
             h[5]==h[14]and h[6]==h[15],'actual complete pre/post CPU, XGETBV and permission calls')
        cp=[struct.unpack_from('<6I',raw,at+128+24*i)for i in range(67)]
        value=profile(cp,h[8],h[10],h[12],h[5],h[6])
        need(value==expected,'fresh same-CPU complete format facts match the prerequisite probe')
        observed.append(value)
    need(observed[0]==observed[1],'actual C format facts unchanged through the complete finite run')
    return observed[0]

class Boundary:
    """Add authority guards, then invoke the unchanged complete comparator."""
    def __init__(self,original,facts):self.original,self.facts=original,facts
    def __getattr__(self,name):return getattr(self.original,name)
    def compare(self,ref,actual,layout):
        need(type(actual)is list and len(actual)==len(ref['rows']),'complete selected format joins')
        for row,got in zip(ref['rows'],actual):
            for phase in('before','after'):
                snap=self.original.snapshot(got[phase],layout)
                pair(row[phase]['xstate'],snap['fp'],self.facts,self.original)
        return self.original.compare(ref,actual,layout)
    def final_entry(self,ref,raw,layout):
        snap=self.original.snapshot(raw,layout)
        pair(ref['rows'][-1]['after']['xstate'],snap['fp'],self.facts,self.original)
        return self.original.final_entry(ref,raw,layout)
