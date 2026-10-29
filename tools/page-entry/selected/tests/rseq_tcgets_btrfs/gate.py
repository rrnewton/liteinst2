"""Actual gate/owner/query prefixes, with injected values explicitly separated."""
import re,struct
from page_selected import need
U64=(1<<64)-1
BTRFS=0x9123683e
PROC=0x9fa0
NAMES=('phase initialized invalidated first_error query_attempted query_returned mount_opened mount_eof '
       'mount_close_started mount_closed mount_complete first_detail invalidated_number query_number '
       'query_result mount_fd mount_close_result result attempts permitted issued returned completed queries '
       'mount_bytes mount_rows mount_matches registration_epoch syscall_check').split()
ID=('device','inode','mount_id','major','minor','mode','flags')
COUNTS=('attempts','permitted','issued','returned','completed')

def signed(n):return n-(1<<64)if n>>63 else n

def mountinfo(raw,wanted):
    need(type(wanted)is int and 0<wanted<1<<31 and 0<len(raw)<=256*1024 and raw.endswith(b'\n'),'complete mountinfo and ordinary mount ID')
    ids=[];matches=0
    for line in raw[:-1].split(b'\n'):
        need(len(ids)<2048 and all(33<=x<=126 or x==32 for x in line) and b'  'not in line,'bounded canonical mount row')
        need(not re.search(rb'\\(?!040|011|012|134)',line),'only kernel mount escapes')
        v=line.split(b' ');need(len(v)>=10 and v.count(b'-')==1,'exact mount separator')
        sep=v.index(b'-');need(sep>=6 and len(v)==sep+4,'complete mount fields')
        def number(x,cap):
            need(re.fullmatch(rb'0|[1-9][0-9]*',x)is not None and int(x)<cap,'canonical bounded mount integer');return int(x)
        mid=number(v[0],1<<31);parent=number(v[1],1<<31);dev=v[2].split(b':')
        need(mid>0 and parent>0 and mid not in ids and len(dev)==2 and v[3].startswith(b'/')and v[4].startswith(b'/'),'complete unique mount identity/root/path')
        for x in dev:number(x,1<<32)
        def options(x):need(re.fullmatch(rb'r[ow](?:,[^, ]+)*',x)is not None,'complete mount options')
        options(v[5]);options(v[-1]);tags=[]
        for item in v[6:sep]:
            if item==b'unbindable':tag=item
            else:
                parts=item.split(b':');need(len(parts)==2 and parts[0]in(b'shared',b'master',b'propagate_from')and number(parts[1],1<<31)>0,'known exact mount propagation tag');tag=parts[0]
            need(tag not in tags,'unique propagation tag');tags.append(tag)
        ids.append(mid)
        if mid==wanted:need(v[sep+1]==b'btrfs','actual mount-ID btrfs filesystem');matches+=1
    need(matches==1,'exactly one actual btrfs mount-ID join')
    return ids


def check(r,data,h,image,pid,capture,injected):
    """Read actual binary state; never infer a raw call from permission alone."""
    c=image['case'];I=r.integer;F=r.field;st='li2_tcgets_state';ot='li2_rseq_state'
    size=r.types[st]['bytes'];owner_size=r.types[ot]['bytes']
    rawstates=F(data,r.rt,'stages');rawowners=F(data,r.rt,'owners')
    stages=[rawstates[i*size:(i+1)*size]for i in range(7)]
    owners=[rawowners[i*owner_size:(i+1)*owner_size]for i in range(7)]
    def state(b):return {k:I(b,st,k)for k in NAMES}
    def ident(b,name):return tuple(I(F(b,st,name),'li2_tcgets_identity',k)for k in ID)
    def typed(b,t,k):return I(b,t,k)
    parent=capture['identity'];authority=(parent['device'],parent['inode'],capture['mount_id'],
        capture['major'],capture['minor'],parent['mode'],parent['flags'])
    init_failure=c>=16
    success=c<7 and not injected
    actual_issued=success or injected==15
    present=(1,0,0,0,0,0,1)if init_failure else(1,1,int(success or injected==15),int(actual_issued),int(actual_issued),int(success),1)
    need(tuple(h[24:31])==present and h[31]==0,'exact attempted/permitted/issued/returned/validated/terminal stage inventory')
    for i,b in enumerate(stages):
        if not present[i]:need(not any(b+owners[i]),'unreached stages contain no invented snapshots')
    end=state(stages[6]);start=state(stages[0])
    need(start['attempts']==start['permitted']==start['issued']==start['returned']==start['completed']==0,
         'launch identity established before any application ioctl')
    need(start['initialized']==int(not init_failure)and start['phase']==(8 if init_failure else 2)and
         start['first_error']==(1207 if init_failure else 0)and start['first_detail']==(2 if init_failure else 0),
         'exact original initialization success or failed gate prefix')
    if not init_failure:need(ident(stages[0],'launch')==authority,'actual launch FD matches trusted parent construction')
    need(end['initialized']==int(not init_failure)and end['invalidated']==int(c in(7,8))and
         end['invalidated_number']==(3 if c in(7,8)else 0)and end['phase']==(7 if success else 8)and
         end['first_error']==(0 if success else 1207),'exact gate phase/invalidation and preserved old unsupported outcome')
    expected_counts=(1,1,1,1,1)if success else(1,1,1,1,0)if injected==15 else(1,0,0,0,0)if injected else(0,0,0,0,0)
    need(tuple(end[k]for k in COUNTS)==expected_counts,'actual gate counts distinguish permit/raw return/result validation')
    need(end['first_detail']==(0 if success else 10 if injected==15 else 6 if injected else 2 if init_failure else 5),
         'exact refusal stage; no unobserved forwarding claim')
    need(end['result']==((-25)&U64 if success else 0),'actual result accepted only after unchanged raw ioctl')
    need((h[32],*h[33:39])==(((-25)&U64,*image['args'])if actual_issued else(0,)*7)and h[39]==0,
         'original actual syscall result and all six original inputs retained independently of supplied result')
    if not init_failure:
        need(ident(stages[6],'launch')==authority,'launch identity remains exact after application calls')
        for i in (1,2,3,4,5,6):
            if not present[i]:continue
            b=owners[i]
            need(tuple(I(b,ot,k)for k in('initialized','registered','held','phase','pid','tid','address','page','length','signature','epoch'))==
                 (1,1,1,3,pid,pid,0x300001040,0x300001000,32,0x53053053,1),
                 'actual ACTIVE held registration/pin/singleton before every gate stage')
            need(I(b,ot,'tls_attempted')==I(b,ot,'tls_complete')==1 and I(b,ot,'fs_result')==I(b,ot,'gs_result')==0 and
                 I(b,ot,'fs_base')==0x200407000+2048 and I(b,ot,'gs_base')==0x200407000+2304,
                 'fresh actual completed TLS authority')
            need(I(b,ot,'first_error')==(1207 if i==6 and not success else 0)and
                 I(b,ot,'first_detail')==(16 if i==6 and not success else 0),'old owner retains exact unsupported failure')
    if success or injected:
        need(end['registration_epoch']==1 and end['syscall_check']>0 and
             tuple(struct.unpack('<6Q',F(stages[6],st,'args')))==tuple(image['args']),
             'actual gate check joins complete original six-argument identity')
        pin=F(stages[6],st,'data');pt='li2_rseq_data';op=F(owners[6],ot,'data')
        fields=('address','page','allocation','generation','offset','pid','tid')
        iv=tuple(I(pin,pt,k)for k in fields)
        need(iv==tuple(I(op,pt,k)for k in fields)and iv[:2]==(0x300001040,0x300001000)and iv[2]>0 and iv[3]>0 and
             iv[4]%4096==0 and iv[5:]==(pid,pid)and
             all(I(pin,pt,k)==1 for k in('attempted','complete'))and I(pin,pt,'error')==I(pin,pt,'detail')==0,
             'new gate observes same complete actual allocation/generation/offset as old held owner')
        if success or injected==15:need(ident(stages[6],'current')==authority,'actual revalidated current FD equals launch and parent')
    if success:
        expected=((4,(1,1,0,0,0)),(5,(1,1,1,0,0)),(5,(1,1,1,0,0)),(7,(1,1,1,1,1)))
        for i,(phase,counts)in zip((2,3,4,5),expected):
            s=state(stages[i]);need(s['phase']==phase and tuple(s[k]for k in COUNTS)==counts and
                s['first_error']==0,'actual ordered permit/issue/return-validation progression')
    queries=[struct.unpack_from('<10Q',F(data,r.rt,'query'),80*i)for i in range(h[19])]
    need(0<h[19]<=256 and not any(F(data,r.rt,'query')[h[19]*80:])and
         [q[0]for q in queries]==list(range(1,len(queries)+1))and end['queries']==len(queries),
         'complete actual bounded query sequence without fabricated/omitted calls')
    symbols=r.layout['gate_symbols'];need(set(symbols)=={'tcgets','tcgets_empty','tcgets_mount_path'}and all(type(v)is int and v>0 for v in symbols.values()),'actual complete ELF gate symbols')
    bias=h[42]-symbols['tcgets'];need(bias>0 and bias%4096==0,'actual gate object and ELF load-bias join')
    pointer=lambda name:h[42]+r.types[st]['fields'][name]['offset']
    for row in queries:
        ordinal,n,a,b,cc,d,e,f,result,phase=row
        need(phase in(1,3),'query belongs to binding or checking, never fabricated ioctl')
        if n==5:need((a==1 and b==pointer('stat')or a!=1 and b==pointer('proc_stat'))and (cc,d,e,f)==(0,0,0,0),'actual fstat buffer domain')
        elif n==72:need((a,b,cc,d,e,f)==(1,3,0,0,0,0),'actual F_GETFL query')
        elif n==138:need((a==1 and b==pointer('filesystem')or a!=1 and b==pointer('proc_filesystem'))and (cc,d,e,f)==(0,0,0,0),'actual fstatfs buffer domain')
        elif n==332:need((a,b,cc,d,e,f)==(1,bias+symbols['tcgets_empty'],0x1000,0x1103,pointer('statx'),0),'actual ordinary-MNT_ID statx query')
        elif n==257:need((a,b,cc,d,e,f)==(((-100)&U64),bias+symbols['tcgets_mount_path'],0xa0000,0,0,0),'actual procfs path and normal open flags')
        elif n==0:need(a<1<<31 and pointer('mountinfo')<=b<pointer('mountinfo')+256*1024 and cc==pointer('mountinfo')+256*1024-b and (d,e,f)==(0,0,0),'actual complete bounded mountinfo read')
        elif n==3:need(a<1<<31 and (b,cc,d,e,f)==(0,0,0,0,0),'actual mount descriptor close')
        else:need(False,'no unknown actual query or substituted raw ioctl')
    groups=[[x for x in queries if x[9]==phase]for phase in(1,3)]
    need(queries==groups[0]+groups[1] and len(groups[0])==start['queries'],'actual complete initialization precedes current check')
    for group in groups:
        for x in group:
            if x[1]in(5,138,332,3):need(x[8]==0,'original actual native identity/close query succeeded before any supplied fault')
            if x[1]==72:need(x[8]==parent['flags'],'actual original F_GETFL equals trusted capture construction')
    for group,b in((groups[0],stages[0]),(groups[1],stages[6])):
        if not group:continue
        sb=F(b,st,'stat')
        if not injected or group[0][9]==1:
            need((I(sb,'stat','st_dev'),I(sb,'stat','st_ino'),I(sb,'stat','st_mode'))==
                 (parent['device'],parent['inode'],parent['mode']),'actual complete fstat identity joins parent even on required type refusal')
    if init_failure:
        need([x[1]for x in groups[0]]==([5,72]if c==16 else[5,72,138]if c==19 else[5])and not groups[1],
             'exact initial O_PATH/type/filesystem refusal before application entry')
        if c==19:
            need(all(x[2]==1 for x in groups[0])and
                 all(I(F(b,st,'filesystem'),'statfs','f_type')==capture['filesystem_type']==0x01021994 for b in(stages[0],stages[6])),
                 'actual same-FD SHMEM result joins parent at both initial-refusal snapshots')
    elif not success and not injected:need(not groups[1],'rejected FD/request/invalidation performs no revalidation query')
    elif injected in(1,2,3,4,5,6,8,9,16):
        expected={1:[5],2:[5,72],3:[5,72,138],4:[5,72,138,332],5:[5,72,138,332],6:[5,72,138,332],
                  8:[5,72,138,332,257],9:[5,72,138,332,257,5,138,0,3],16:[5]}[injected]
        need([x[1]for x in groups[1]]==expected,'exact stopped actual query prefix for the supplied fault')
    if injected in(7,10,11,12,13,14):
        # These controls reach the complete actual acquisition. Parser inputs
        # are read from the pre-injection copy, never the supplied mutation.
        b=F(data,r.rt,'injection_before')[:size]if injected>=11 else stages[6]
        group=groups[1];nums=[x[1]for x in group]
        need(nums[:7]==[5,72,138,332,257,5,138]and len(nums)>=10 and nums[-1]==3 and
             all(n==0 for n in nums[7:-1]),'complete actual acquisition before late supplied refusal')
        fd=group[4][8];need(0<=fd<1<<31 and all(x[2]==fd for x in group[5:])and
             group[-2][8]==group[-1][8]==0,'actual EOF/close remain successful before late injection')
        total=0
        for x in group[7:-1]:
            need(x[3]==pointer('mountinfo')+total and 0<=x[8]<=256*1024-total,'all actual late-control read extents');total+=x[8]
        need(total==I(b,st,'mount_bytes')and I(b,st,'mount_eof')==1,
             'complete original acquisition retained independently of parser/close mutation')
        mountinfo(F(b,st,'mountinfo')[:total],capture['mount_id'])
    for group,b,required in ((groups[0],stages[0],not init_failure),(groups[1],stages[5]if success else stages[6],success or injected==15)):
        if not required:continue
        s=state(b);nums=[x[1]for x in group]
        identity=ident(b,'launch'if group[0][9]==1 else'current');sb=F(b,st,'stat');sx=F(b,st,'statx');fb=F(b,st,'filesystem')
        need(identity==authority and (I(sb,'stat','st_dev'),I(sb,'stat','st_ino'),I(sb,'stat','st_mode'))==
             (identity[0],identity[1],identity[5])and I(fb,'statfs','f_type')==BTRFS and
             I(sx,'statx','stx_mask')&0x1103==0x1103 and not I(sx,'statx','stx_mask')&0x4000 and
             tuple(I(sx,'statx',k)for k in('stx_ino','stx_mode','stx_dev_major','stx_dev_minor','stx_mnt_id'))==
             (identity[1],identity[5],identity[3],identity[4],identity[2]),
             'actual stat/statx/BTRFS buffers prove the complete identity behind each accepted acquisition')
        need(I(F(b,st,'proc_stat'),'stat','st_mode')&0xf000==0x8000 and I(F(b,st,'proc_filesystem'),'statfs','f_type')==PROC,
             'actual complete mount source is a regular procfs object')
        need(nums[:7]==[5,72,138,332,257,5,138]and len(nums)>=10 and nums[-1]==3 and all(n==0 for n in nums[7:-1]),'complete actual FD and procfs query ordering')
        fd=group[4][8];need(0<=fd<1<<31 and all(x[2]==fd for x in group[5:])and group[-2][8]==0 and group[-1][8]==0,'actual open/read EOF/close descriptor/result join')
        total=0
        for x in group[7:-1]:
            need(x[3]==pointer('mountinfo')+total and 0<=x[8]<=256*1024-total,'actual ordered read extents');total+=x[8]
        need(total==s['mount_bytes']and all(s[k]==1 for k in('mount_opened','mount_eof','mount_close_started','mount_closed','mount_complete'))and s['mount_fd']==fd and s['mount_close_result']==0,'complete actual mount acquisition, no partial-read acceptance')
        mount=F(b,st,'mountinfo')[:total];ids=mountinfo(mount,ident(b,'launch'if group[0][9]==1 else'current')[2])
        need(s['mount_rows']==len(ids)and s['mount_matches']==1 and list(struct.unpack_from('<'+'Q'*len(ids),F(b,st,'mount_ids')))==ids,'full parsed mount-ID list joins actual complete bytes')
    return dict(initialized=end['initialized'],invalidated=end['invalidated'],attempted=end['attempts'],permitted=end['permitted'],
                issued=end['issued'],returned=end['returned'],result_validated=end['completed'],queries=end['queries'],injected=injected,
                failure_code=end['first_error'],failure_detail=end['first_detail'])


def injections(r,data,h,image,selector):
    F=r.field;I=r.integer;st='li2_tcgets_state';size=r.types[st]['bytes']
    records=F(data,r.rt,'injection');before=F(data,r.rt,'injection_before');after=F(data,r.rt,'injection_after')
    count=0 if not selector else 2 if selector==7 else 1
    need(h[20]==count and not any(records[count*64:]+before[count*size:]+after[count*size:]),
         'exact finite supplied-control count and completely empty unused rows')
    queries=[struct.unpack_from('<10Q',F(data,r.rt,'query'),80*i)for i in range(h[19])]
    for i in range(count):
        row=struct.unpack_from('<8Q',records,64*i);b=before[i*size:(i+1)*size];a=after[i*size:(i+1)*size];e=bytearray(b)
        need(row[0]==selector and row[6:]==(1,0)and I(b,st,'phase')==(5 if selector==15 else 3),
             'complete supplied control after original actual result with exact gate phase')
        def scalar(t,key,value,base=0):
            f=r.types[t]['fields'][key];e[base+f['offset']:base+f['offset']+f['bytes']]=(value&((1<<(8*f['bytes']))-1)).to_bytes(f['bytes'],'little')
        def member(parent,t,key,value):scalar(t,key,value,r.types[st]['fields'][parent]['offset'])
        if selector<=10 or selector==16:
            n={1:5,2:72,3:138,4:332,5:332,6:332,7:5 if i==0 else 332,8:257,9:0,10:3,16:5}[selector]
            need(row[1:3]==(1,n)and 0<row[5]<=len(queries)and queries[row[5]-1][1]==n and
                 queries[row[5]-1][8]==row[3]and I(b,st,'query_result')==row[3]and
                 I(b,st,'query_attempted')==I(b,st,'query_returned')==1,'actual original query/capture exists before injected result')
            actual=signed(row[3]);supplied=(-5 if selector in(1,8,9,10)else actual|0x200000 if selector==2 else actual)
            need(row[4]==supplied&U64 and (actual>0 if selector in(2,8,9)else actual==0),
                 'supplied query error is distinct from the successful actual native query')
            scalar(st,'query_result',supplied)
            if selector==3:
                need(I(F(b,st,'filesystem'),'statfs','f_type')==BTRFS,'actual original btrfs result');member('filesystem','statfs','f_type',PROC)
            if selector==4:member('statx','statx','stx_mask',I(F(b,st,'statx'),'statx','stx_mask')&~0x1000)
            if selector in(5,7):
                parent,t,key=('stat','stat','st_ino')if selector==7 and i==0 else('statx','statx','stx_ino')
                member(parent,t,key,I(F(b,st,parent),t,key)+1)
            if selector==6:member('statx','statx','stx_mnt_id',0)
            if selector==16:
                mode=I(F(b,st,'stat'),'stat','st_mode');need(mode&0xf000==0x8000,'actual original regular file mode');member('stat','stat','st_mode',(mode&~0xf000)|0x4000)
        elif selector<=14:
            need(row[1:3]==(2,0)and row[3]==I(F(b,st,'current'),'li2_tcgets_identity','mount_id')and row[3]>0 and
                 row[4]==(0 if selector==14 else row[3])and row[5]==I(b,st,'queries')and
                 all(I(b,st,k)==1 for k in('mount_opened','mount_eof','mount_close_started','mount_closed')),
                 'parser control begins only after a complete actual retained mount read/close')
            n=I(b,st,'mount_bytes');raw=F(b,st,'mountinfo');mountinfo(raw[:n],row[3])
            offset=r.types[st]['fields']['mountinfo']['offset']
            if selector==11:e[offset+n-1]=32
            if selector==12:
                line=raw[:raw.index(b'\n')+1];need(n+len(line)<=len(raw),'bounded actual duplicate-line control')
                e[offset+n:offset+n+len(line)]=line;scalar(st,'mount_bytes',n+len(line))
            if selector==13:
                at=0;locations=[]
                for line in raw[:n].splitlines(keepends=True):
                    if int(line.split(b' ',1)[0])==row[3]:locations.append(at+line.index(b' - btrfs ')+3)
                    at+=len(line)
                need(len(locations)==1,'one original actual btrfs match before injected type');e[offset+locations[0]]=ord('x')
        else:
            need(selector==15 and row[1:5]==(3,16,(-25)&U64,0)and row[5]==I(b,st,'queries')and
                 h[32]==((-25)&U64),'actual raw ENOTTY remains distinct from supplied result0')
        need(bytes(e)==a,'complete before/after injection bytes differ only by the declared finite supplied change')
