"""Distinct raw user-DWARF profile reader; old scalar/kernel readers unchanged.

Raw event identities and exec/exit chronology are checked before invoking the
pinned perf/libdw unwinder. Every script header must join one raw sample. Only
actual bridge mappings resolve to function intervals; other frames stay unknown.
"""
import collections,csv,hashlib,json,re,struct
from bisect import bisect_left,bisect_right
from pathlib import Path
from page_cost_profile_read import need,elf,same_bridge


class ActiveMaps:
    """Disjoint working view; each fragment retains its full original record."""
    def __init__(self):
        self.starts=[];self.intervals=[]

    def update(self,m):
        lo=m['address'];hi=lo+m['bytes']
        need(0<=lo<hi<1<<64,'complete active mapping interval')
        i=bisect_left(self.starts,lo)
        if i and self.intervals[i-1][1]>lo:i-=1
        j=bisect_left(self.starts,hi);part=[]
        if i<j and self.intervals[i][0]<lo:
            a,_,old=self.intervals[i];part.append((a,lo,old))
        part.append((lo,hi,m))
        if i<j and self.intervals[j-1][1]>hi:
            _,z,old=self.intervals[j-1];part.append((hi,z,old))
        need(all(a<b for a,b,_ in part)and all(part[k-1][1]<=part[k][0]for k in range(1,len(part)))and
             (not i or self.intervals[i-1][1]<=part[0][0])and
             (j==len(self.intervals)or part[-1][1]<=self.intervals[j][0]),'nonoverlapping actual mapping view')
        self.intervals[i:j]=part;self.starts[i:j]=[x[0]for x in part]
        need(len(self.intervals)<=65536,'bounded actual mapping interval population')

    def find(self,ip):
        i=bisect_right(self.starts,ip)-1
        return self.intervals[i][2]if i>=0 and ip<self.intervals[i][1]else None


def mapping_index_check():
    """Pure oracle against append-only latest-covering history, not runtime credit."""
    high=(1<<64)-0x10000
    cases=[
        ('adjacent_and_holes',[(1,100,20,1000),(1,140,20,2000),(1,120,20,3000)]),
        ('split_and_nested',[(1,100,100,500),(1,120,60,900),(1,130,10,1700),(1,135,20,2100)]),
        ('replace_many',[(1,100,20,0),(1,130,20,100),(1,160,20,200),(1,90,100,400),(1,90,100,800)]),
        ('partial_left_right',[(1,100,100,1000),(1,90,40,2000),(1,175,40,3000),(1,125,55,4000)]),
        ('same_boundaries',[(1,100,100,0),(1,100,60,1000),(1,140,60,2000),(1,100,100,3000)]),
        ('high_addresses',[(1,high,0x1000,0x7000),(1,high+3,0x800,0x9000),(1,high+0xfff,0x1000,0xb000)]),
        ('comm_exec_pid_scope',[(1,100,100,0),(2,100,100,1000),(1,None),(1,130,20,2000),(2,None),(1,None),(2,100,100,4000)]),
        ('bounded_replacement_history',[(1,4096,4096,i*4096)for i in range(256)]),
    ]
    operations=queries=splits=0
    for name,events in cases:
        indices={1:ActiveMaps(),2:ActiveMaps()};history={1:[],2:[]};probes={0,(1<<64)-1}
        for serial,event in enumerate(events):
            pid=event[0];operations+=1
            if event[1]is None:
                indices[pid]=ActiveMaps();history[pid]=[]
            else:
                _,lo,n,offset=event;m=dict(address=lo,bytes=n,offset=offset,pid=pid,serial=serial)
                history[pid].append(m);indices[pid].update(m)
                for x in (lo-1,lo,lo+1,lo+n//2,lo+n-1,lo+n,lo+n+1):
                    if 0<=x<1<<64:probes.add(x)
            for who in (1,2):
                index=indices[who];last=0
                need(len(index.starts)==len(index.intervals),'oracle parallel index population')
                for k,(lo,hi,m)in enumerate(index.intervals):
                    need(last<=lo<hi and index.starts[k]==lo and m['address']<=lo and
                         hi<=m['address']+m['bytes'],'oracle ordered disjoint original fragments')
                    last=hi;splits+=int(lo!=m['address']or hi!=m['address']+m['bytes'])
                for ip in sorted(probes):
                    want=next((m for m in reversed(history[who])if m['address']<=ip<m['address']+m['bytes']),None)
                    got=index.find(ip);queries+=1
                    need(got is want,'oracle exact latest original record '+name)
                    if got is not None:
                        need(got['offset']+ip-got['address']==want['offset']+ip-want['address'],
                             'oracle original file offset survives clipping')
    # Independent explicit split expectation catches accidental rebasing even
    # if a reference implementation were changed with the working index.
    x=ActiveMaps();a=dict(address=100,bytes=100,offset=1000);b=dict(address=130,bytes=20,offset=9000)
    x.update(a);x.update(b)
    need(x.intervals==[(100,130,a),(130,150,b),(150,200,a)]and
         x.find(150)is a and x.find(199)is a and x.find(200)is None and
         x.find(150)['offset']+150-x.find(150)['address']==1050,'explicit split keeps source offset')
    need(splits>0 and queries>0,'nonempty split and lookup oracle')
    return dict(status='passed',cases=len(cases),operations=operations,queries=queries,
        observed_fragments=splits,explicit_split_cases=1,native_operations=0)


def mode_user(misc):
    return misc&7==2 and misc&~(7|(1<<14))==0


def dwarf_payload(b,pos,mode,mask):
    need(mode==2 and pos+8<=len(b),'complete actual user callchain count')
    n=struct.unpack_from('<Q',b,pos)[0];pos+=8
    need(n<=128 and pos+8*n<=len(b),'bounded actual user callchain words')
    words=struct.unpack_from('<'+'Q'*n,b,pos);pos+=8*n
    need(not words or words[0]==(1<<64)-512,'only leading PERF_CONTEXT_USER')
    need(all(0<pc<(1<<64)-4095 for pc in words[1:]),'actual user callchain addresses')
    need(pos+8<=len(b),'complete user register ABI')
    abi=struct.unpack_from('<Q',b,pos)[0];pos+=8
    need(abi in(0,2),'absent or native x86-64 user registers')
    count=mask.bit_count() if abi else 0
    need(pos+8*count+8<=len(b),'complete user register values and stack extent')
    values=struct.unpack_from('<'+'Q'*count,b,pos);pos+=8*count
    size=struct.unpack_from('<Q',b,pos)[0];pos+=8
    need(size in(0,4096) and pos+size+(8 if size else 0)==len(b),'complete bounded requested user stack')
    dynamic=struct.unpack_from('<Q',b,pos+size)[0]if size else 0
    need(dynamic<=size and (abi!=0 or size==0),'actual available stack bytes')
    return dict(register_abi=abi,register_mask=mask,registers=list(values),stack_bytes=size,
        available_stack_bytes=dynamic,stack_sha256=hashlib.sha256(b[pos:pos+size]).hexdigest(),
        raw_callchain=list(words),unwind_complete=False)


def summarize(path, bridge, target_pid, cpu, directory, release_ns, exit_ready_ns, *, bridge_identity=None):
    """Whole exec-to-exit envelope; event loss or truncation never hidden."""
    data=path.read_bytes(); need(104<=len(data)<=128<<20,'bounded retained perf file')
    need(data[:8]==b'PERFILE2','native little-endian perf.data header')
    header,entry,attrs,attr_bytes,start,size=struct.unpack_from('<6Q',data,8)
    need(header==104 and entry==160 and attr_bytes==2*entry and attrs>=header and
         attrs+attr_bytes<=start and start+size<=len(data),
         'one current CPU_CLOCK with exact DUMMY sideband file layout')
    # Event ID sections are part of each perf_file_attr, not the sample payload.
    ids={};id_positions={};attributes=[];ranges=[];paired=attr_bytes==2*entry
    for index,at in enumerate(range(attrs,attrs+attr_bytes,entry)):
        raw=data[at:at+144]
        typ,attrsize,config,freq,sample_type=struct.unpack_from('<IIQQQ',raw)
        flags=struct.unpack_from('<Q',raw,40)[0]
        regs=struct.unpack_from('<Q',raw,80)[0]
        stack=struct.unpack_from('<I',raw,88)[0]
        need(typ==1 and attrsize==144 and freq==99 and config==(0 if index==0 else 9),
             'exact 99Hz software CPU_CLOCK/DUMMY pair')
        need(flags & ((1<<10)|(1<<18)|(1<<25)) == ((1<<10)|(1<<18)|(1<<25)) and
             struct.unpack_from('<i',raw,92)[0]==1,
             'frequency, whole sideband, MONOTONIC and bounded known attribute flags')
        need(struct.unpack_from('<Q',raw,32)[0]==20 and raw[48:80]==bytes(32) and
             raw[96:108]==bytes(12) and raw[110:144]==bytes(34) and
             struct.unpack_from('<H',raw,108)[0]<=127, 'no unrequested attribute extensions or branch/interrupt sampling')
        if index==0:
            # Bit22 suppresses redundant kernel-collected user FP chains; it
            # cannot suppress the separately required REG_USER/STACK_USER data.
            # Both states are fully parsed; neither changes the user denominator.
            need(sample_type==0x131a7 and flags&~(1<<22)==0x2240463 and
                 regs==0xff0fff and stack==4096,
                 'user-only 4096-byte DWARF/IP/TID/time/CPU/period/identifier sample with BP/SP/IP')
        else:
            need(sample_type==0x10187 and regs==stack==0 and flags==0x463963763,
                 'exact non-DWARF DUMMY sideband with data MMAP2 and COMM_EXEC')
        off,n=struct.unpack_from('<QQ',data,at+entry-16)
        need(header<=off<=attrs and 0<n<=attrs-off and n%8==0 and
             all(off+n<=lo or hi<=off for lo,hi in ranges), 'bounded disjoint event ID sections')
        values=struct.unpack_from('<'+'Q'*(n//8),data,off);ranges.append((off,off+n))
        need(all(v>0 and v not in ids for v in values) and len(set(values))==len(values),
             'nonzero unique IDs within and across the exact event attributes')
        ids.update({v:index for v in values});id_positions.update({v:i for i,v in enumerate(values)});attributes.append(dict(config=config,sample_type=sample_type,ids=len(values),raw_hex=raw.hex(),regs=regs,stack=stack))
    sample_type=attributes[0]['sample_type']
    # Feature payloads are not attribution authority, but every declared extent
    # must be inside the retained file and outside the event/feature tables.
    flags=struct.unpack_from('<4Q',data,72);features=sum(x.bit_count()for x in flags)
    at=start+size;limit=at+16*features
    need(limit<=len(data), 'complete bounded feature section table')
    extents=[]
    for i in range(features):
        off,n=struct.unpack_from('<QQ',data,at+16*i)
        need(limit<=off<=len(data) and n<=len(data)-off and
             all(off+n<=lo or hi<=off for lo,hi in extents), 'bounded disjoint feature payload')
        extents.append((off,off+n))
    need(sample_type==0x131a7, 'one exact user-DWARF sample payload')
    side=[(bit,name)for bit,name in ((2,'tid'),(4,'time'),(64,'id'),(512,'stream'),(128,'cpu'),(65536,'identifier'))if sample_type&bit]
    indexed={};initial=True;initial_records=0;last_event_time=0;metadata=collections.Counter()
    def suffix(b):
        at=len(b)-8*len(side);need(at>=8,'complete sideband identity');result={}
        for bit,name in side:
            result[name]=struct.unpack_from('<II'if bit in(2,128)else'<Q',b,at);at+=8
        return result,len(b)-8*len(side)
    def event_identity(b,kind,misc):
        nonlocal initial_records,last_event_time
        sid,end=suffix(b)
        if all(x==0 for value in sid.values() for x in value):
            need(initial and kind in(1,10,17,3) and not(kind==3 and misc&(1<<13)),
                 'zero identity is only initial synthetic mapping/comm/ksymbol metadata')
            initial_records+=1;return sid,end
        event_id=sid['identifier'][0]
        need(event_id in ids,'DWARF sideband IDENTIFIER belongs to a declared event')
        if kind in(1,3,4,7,10,17):need(ids[event_id]==1,'runtime sideband belongs only to exact non-callchain DUMMY')
        need(event_id in indexed and sid['cpu']==(indexed[event_id][1],0),
             'sideband CPU agrees with complete actual ID_INDEX')
        need(sid['time'][0]>=last_event_time,'ordered runtime sideband within the one-CPU stream')
        last_event_time=sid['time'][0]
        need(sid['cpu'][1]==0, 'zero reserved sideband CPU word')
        return sid,end
    def string(b,first,end,why):
        need(first<end and b'\0'in b[first:end], why)
        tail=b[first:end];stop=tail.index(0)
        need(tail[stop:]==bytes(len(tail)-stop), 'complete zero padding after metadata string')
        return tail[:stop].decode('utf-8','surrogateescape')
    def cpu_map(b):
        need(len(b)==8 and b[:4]==b'\x02\0\0\0', 'exact bounded range CPU-map encoding')
        first,last=struct.unpack_from('<HH',b,4)
        need(first<=last and cpu in range(first,last+1), 'reserved CPU is in actual recorded CPU range')
        values=set(range(first,last+1))
        need(indexed and values=={v[1]for v in indexed.values()}, 'CPU map covers exactly the ID_INDEX CPUs')
    def metadata_record(kind,b,misc):
        nonlocal initial
        need(misc==0, 'userspace perf metadata has no kernel event flags')
        metadata[str(kind)]+=1
        if kind==69:
            need(initial and not indexed and len(b)>=16, 'one initial ID_INDEX record')
            n=struct.unpack_from('<Q',b,8)[0]
            need(n==len(ids) and len(b)==16+32*n, 'complete ID_INDEX population')
            for at in range(16,len(b),32):
                ident,index,processor,tid=struct.unpack_from('<4Q',b,at)
                need(ident in ids and ident not in indexed and index==id_positions[ident] and
                     processor<1<<31 and tid==target_pid, 'each ID_INDEX entry joins actual event, CPU and attached thread')
                indexed[ident]=(ids[ident],processor,tid)
            need(len(set(indexed.values()))==len(indexed), 'one event ID per actual event/CPU/thread')
        elif kind==73:
            need(initial and len(b)==40 and struct.unpack_from('<QQ',b,8)==(1,target_pid),
                 'one complete attached-thread map')
            string(b,24,40,'bounded thread-map name')
        elif kind==74:
            need(initial and len(b)==16, 'complete initial CPU map');cpu_map(b[8:])
        elif kind==78:
            need(initial and len(b)>=24, 'complete initial event update')
            typ,ident=struct.unpack_from('<QQ',b,8)
            need(ident in ids, 'event update uses a declared event ID')
            if typ==0:
                need(ids[ident]==0 and len(b)==48 and string(b,24,48,'event unit')=='msec', 'exact CPU_CLOCK unit update')
            elif typ==1:
                need(ids[ident]==0 and len(b)==48 and struct.unpack_from('<d',b,24)[0]==1e-6 and b[32:]==bytes(16),
                     'exact CPU_CLOCK display scale, not a sample weight conversion')
            elif typ==3:need(len(b)==32,'complete event CPU map');cpu_map(b[24:])
            else:need(False,'unsupported event update type')
        elif kind==82:
            need(initial and len(b)==8 and (not paired or len(indexed)==len(ids)), 'one complete initial metadata boundary')
            initial=False
        else:need(kind==68 and len(b)==8, 'complete FINISHED_ROUND marker')
    obj=elf(bridge)
    if bridge_identity is not None:same_bridge(bridge_identity,obj['provenance'])
    (directory/'bridge-identity.json').write_text(json.dumps(obj['provenance'],sort_keys=True)+'\n')
    maps={};rows=[];counts=collections.Counter();lost=0;throttles=0
    at=start;last_time=0;execs=[];exits=[];exit_suffixes=[];mappings=[]
    while at<start+size:
        need(at+8<=start+size,'complete event header');kind,misc,length=struct.unpack_from('<IHH',data,at)
        need(length>=8 and at+length<=start+size,'complete event extent')
        b=data[at:at+length];at+=length;counts[str(kind)]+=1
        if kind in(69,73,74,78,82,68):
            metadata_record(kind,b,misc)
        elif kind in(1,10):
            sid,end=event_identity(b,kind,misc);fixed=72 if kind==10 else 40
            name=string(b,fixed,end,'MMAP complete name/identity')
            pid,tid,address,n,offset=struct.unpack_from('<IIQQQ',b,8)
            need(sid['tid']==(0,0) or pid==tid==target_pid and sid['tid']==(pid,tid),
                 'runtime mapping body joins attached thread; initial synthetic identities remain explicit')
            need(n>0 and address+n<1<<64,'MMAP address interval')
            m=dict(pid=pid,tid=tid,time_ns=sid['time'][0],record_offset=at-length,address=address,bytes=n,offset=offset,name=name,
                   build_id=None,device=None,inode=None,prot=None)
            if kind==10:
                m['prot']=struct.unpack_from('<I',b,64)[0]
                if misc&(1<<14):
                    z=b[40];need(1<=z<=20 and b[41:44]==bytes(3) and b[44+z:64]==bytes(20-z),'MMAP2 complete build-id extent/reserved bytes');m['build_id']=b[44:44+z].hex()
                else:
                    major,minor,inode=struct.unpack_from('<IIQ',b,40);m.update(device=[major,minor],inode=inode)
            if pid not in maps:maps[pid]=ActiveMaps()
            maps[pid].update(m);mappings.append(m)
        elif kind==3:
            sid,end=event_identity(b,kind,misc);string(b,16,end,'complete COMM name')
            pid,tid=struct.unpack_from('<II',b,8)
            need(sid['tid']==(0,0) or pid==tid==target_pid and sid['tid']==(pid,tid),
                 'runtime COMM body joins attached thread and sideband identity')
            if misc&(1<<13):
                maps[pid]=ActiveMaps()
                mappings.append(dict(reset_pid=pid,time_ns=sid['time'][0],record_offset=at-length))
                if pid==tid==target_pid:
                    need(sid['tid']==(pid,tid),'COMM_EXEC actual target identity');execs.append(sid['time'][0])
        elif kind in(4,7):
            sid,end=event_identity(b,kind,misc);need(end==32,'complete task record');pid,ppid,tid,ptid,stamp=struct.unpack_from('<IIIIQ',b,8)
            need(kind==4 and pid==tid==target_pid and sid['tid']==(pid,tid),
                 'exact attached-thread EXIT only; no unbound child scope')
            exits.append(stamp);exit_suffixes.append(sid['time'][0])
        elif kind==2:
            sid,end=event_identity(b,kind,misc);need(end==24 and struct.unpack_from('<Q',b,8)[0]in ids,'complete LOST record and actual event ID');lost+=struct.unpack_from('<Q',b,16)[0]
        elif kind==13:
            sid,end=event_identity(b,kind,misc);need(end==16,'complete LOST_SAMPLES record');lost+=struct.unpack_from('<Q',b,8)[0]
        elif kind in(5,6):
            sid,end=event_identity(b,kind,misc)
            need(end==32 and struct.unpack_from('<Q',b,16)[0]in ids,'complete throttle record and actual event ID')
            throttles+=1
        elif kind==17:
            sid,end=event_identity(b,kind,misc)
            need(end>=25,'complete KSYMBOL fixed fields')
            address,n,typ,flags=struct.unpack_from('<QIHH',b,8)
            need(n>0 and address+n<1<<64 and typ in(1,2) and flags&~1==0,'bounded kernel symbol metadata')
            string(b,24,end,'complete kernel symbol name')
        elif kind==9:
            pos=8;v={}
            for bit,name in ((65536,'identifier'),(1,'ip'),(2,'tid'),(4,'time'),(8,'addr'),(64,'id'),(512,'stream'),(128,'cpu'),(256,'period')):
                if sample_type&bit:
                    need(pos+8<=len(b),'sample field extent');v[name]=struct.unpack_from('<II'if bit in(2,128)else'<Q',b,pos);pos+=8
            chain=dwarf_payload(b,pos,misc&7,attributes[0]['regs']);pos=len(b)
            need(pos==len(b) and v['cpu']==(cpu,0),'complete sample on reserved CPU')
            ident=v['identifier'][0]
            need(ident in ids and ids[ident]==0,'DWARF sample IDENTIFIER belongs only to CPU_CLOCK')
            need(ident in indexed and indexed[ident][1]==cpu and not initial,
                 'DWARF sample joins complete ID_INDEX and initial boundary')
            need(v['tid']==(target_pid,target_pid) and indexed[ident][2]==target_pid,
                 'DWARF sample PID/TID equals the actual attached ID_INDEX thread')
            need(v['period'][0]>0, 'positive actual CPU_CLOCK period')
            pid,tid=v['tid'];ip=v['ip'][0];stamp=v['time'][0];mode=misc&7
            need(stamp>=last_time and stamp>=last_event_time and mode_user(misc),
                 'ordered user-only single-CPU samples');last_time=last_event_time=stamp
            reason='other_pid'if pid!=target_pid else'kernel'if mode==1 else'no_recorded_mapping'if mode==2 else'other_cpumode'
            m=maps[pid].find(ip)if pid in maps else None
            symbol='';fileoff=None;value=None;candidate=False;candidate_fileoff=None
            if pid==target_pid and mode==2 and m:
                reason='other_mapping'
                if m['name']==obj['path'] and m['prot']is not None and m['prot']&4:
                    candidate=True;candidate_fileoff=m['offset']+ip-m['address'];reason='bridge_identity_unresolved'
                    identity=(m['build_id']is not None and m['build_id']in obj['build_ids'])or(
                        m['build_id']is None and m['device']==obj['mmap_device'] and m['inode']==obj['inode'])
                    if identity:
                        fileoff=candidate_fileoff
                        loads=[p for p in obj['loads']if p[0]==1 and p[1]&1 and p[2]<=fileoff<p[2]+p[5]]
                        need(len(loads)==1,'authenticated bridge offset in one executable file-backed PT_LOAD')
                        value=loads[0][3]+fileoff-loads[0][2];matches=[s for s in obj['symbols']if s[0]<=value<s[1]]
                        if len({(s[0],s[1])for s in matches})==1:
                            symbol='|'.join(sorted({s[2]for s in matches}));reason='authenticated_bridge_symbol'
                        else:reason='bridge_symbol_unknown_or_ambiguous'
            rows.append(dict(pid=pid,tid=tid,time=stamp,ip=ip,cpumode=mode,reason=reason,symbol=symbol,
                file_offset=fileoff,elf_address=value,bridge_path_candidate=candidate,candidate_file_offset=candidate_fileoff,period=v['period'][0]))
            rows[-1].update(dwarf=chain,maps_upto=len(mappings),cpu=cpu,record_offset=at-length)
        else:need(False,'unsupported perf record type '+str(kind))
    need(not paired or (not initial and len(indexed)==len(ids)), 'complete exact two-event metadata')
    need(execs and len(exits)==1 and release_ns<=execs[0]<=execs[-1]<exits[0]<=exit_ready_ns and execs==sorted(execs),
         'actual same-PID exec-to-EXIT envelope inside release/wait boundary')
    need(len(exit_suffixes)==1 and execs[-1]<exit_suffixes[0]<=exit_ready_ns,
         'separately retained EXIT sample-ID timestamp lies inside the actual observed exit boundary')
    for row in rows:row['in_target_exec_window']=execs[0]<=row['time']<=exits[0]
    (directory/'samples.json').write_text(json.dumps(rows,sort_keys=True)+'\n')
    (directory/'maps.json').write_text(json.dumps(mappings,sort_keys=True)+'\n')
    grouped=collections.Counter((r['in_target_exec_window'],r['cpumode'],r['reason'],r['symbol'])for r in rows)
    with (directory/'samples.csv').open('x',newline='')as f:
        w=csv.writer(f);w.writerow(['in_exec_window','cpumode','reason','symbol','samples'])
        for key,n in sorted(grouped.items()):w.writerow([*key,n])
    return dict(samples=len(rows),target_samples=sum(r['pid']==target_pid for r in rows),
        kernel_samples=sum(r['pid']==target_pid and r['cpumode']==1 for r in rows),
        user_samples=sum(r['pid']==target_pid and r['cpumode']==2 for r in rows),
        authenticated_bridge_samples=sum(r['reason']=='authenticated_bridge_symbol'for r in rows),
        bridge_path_candidates=sum(r['bridge_path_candidate']for r in rows),lost_samples=lost,throttle_records=throttles,
        event_counts=dict(counts),event_attributes=attributes,initial_synthetic_records=initial_records,
        metadata_counts=dict(metadata),exec_timestamps_ns=execs,exit_timestamp_ns=exits[0],exit_suffix_timestamp_ns=exit_suffixes[0],sampled_period_total=sum(r['period']for r in rows),
        first_sample_ns=rows[0]['time']if rows else None,last_sample_ns=rows[-1]['time']if rows else None,
        full_exec_exit_envelope=True,loss_free=lost==0 and throttles==0,
        bridge={k:obj[k]for k in('sha256','bytes','build_ids','device','mmap_device','inode')},qualification=False,
        scope='User-only 99Hz DWARF observation. Actual leaf samples are authoritative; unwound frames are bounded observations, not proved complete. No kernel-time, successful-target, timing or qualification credit.')


def script_argv(perf,data,symfs):
    # The private symfs has only the exact observed bridge, never a host cache.
    # No inline expansion, synthesized events, filtering or lost-record hiding.
    return [str(perf),'script','--ns','--no-demangle','--no-inline','--max-stack=64',
            '--symfs='+str(symfs),'-i',str(data),'-F','pid,tid,cpu,time,event,period,ip,sym']


def stacks(text,rows):
    """Every displayed sample joins the raw time/period; symbols are ignored."""
    need(len(text)<=16<<20,'bounded complete perf script output')
    header=re.compile(r'\s*(\d+)\s*/\s*(\d+)\s+\[(\d+)\]\s+(\d+)\.(\d{9}):\s+(\d+)\s+cpu-clock:u:\s*(.*)')
    frame=re.compile(r'\s*([0-9a-fA-F]{1,16})(?:\s+[^\r\n]*)?')
    answer=[];current=None
    for line in text.decode('utf-8','strict').splitlines():
        if not line.strip():continue
        need(len(line)<=16384,'bounded script line')
        found=header.fullmatch(line)
        if found:
            index=len(answer);need(index<len(rows),'no extra unwound sample')
            stamp=int(found[4])*1_000_000_000+int(found[5]);period=int(found[6])
            need((int(found[1]),int(found[2]),int(found[3]),stamp,period)==
                 (rows[index]['pid'],rows[index]['tid'],rows[index]['cpu'],rows[index]['time'],rows[index]['period']),
                 'one ordered DWARF output joins exact raw timestamp and period')
            current=[];answer.append(current);line=found[7]
            if not line:continue
        need(current is not None,'no unbound unwound frame')
        found=frame.fullmatch(line)
        need(found is not None and len(current)<64,'only bounded raw unwind addresses, no unparsed output')
        current.append(int(found[1],16))
    need(len(answer)==len(rows),'every raw sample retained in perf output')
    return answer


def attribute(directory,bridge,script_output,target_pid):
    """Period-weighted leaf and observed complete-display path partitions."""
    rows=json.loads((directory/'samples.json').read_bytes())
    mappings=json.loads((directory/'maps.json').read_bytes())
    chains=stacks(script_output,rows);obj=elf(bridge)
    active=ActiveMaps();cursor=0;functions=collections.Counter();paths=collections.Counter()
    function_n=collections.Counter();path_n=collections.Counter();states=collections.Counter()
    total=weight=unknown=unknown_weight=0;details=[]
    def update(m):
        nonlocal active
        if 'reset_pid'in m:
            if m['reset_pid']==target_pid:active=ActiveMaps()
            return
        if m['pid']!=target_pid:return
        active.update(m)
    def resolve(ip):
        if not 0<ip<1<<47:return 'unknown:non_user_address'
        m=active.find(ip)
        if m is None:return 'unknown:no_recorded_mapping'
        if m['name']!=obj['path']:return 'unknown:other_mapping'
        if m['prot']is None or not m['prot']&4:return 'unknown:nonexecutable_bridge_mapping'
        identified=(m['build_id']in obj['build_ids']if m['build_id']is not None else
                    m['device']==obj['mmap_device'] and m['inode']==obj['inode'])
        if not identified:return 'unknown:bridge_identity'
        off=m['offset']+ip-m['address']
        loads=[p for p in obj['loads']if p[0]==1 and p[1]&1 and p[2]<=off<p[2]+p[5]]
        need(len(loads)==1,'authenticated live bridge offset belongs to one executable PT_LOAD')
        va=loads[0][3]+off-loads[0][2];found=[s for s in obj['symbols']if s[0]<=va<s[1]]
        if len({(s[0],s[1])for s in found})!=1:return 'unknown:bridge_symbol_interval'
        lo,hi=next(iter({(s[0],s[1])for s in found}))
        return 'bridge:'+hex(lo)+'-'+hex(hi)+':'+'|'.join(sorted({s[2]for s in found}))
    for row,chain in zip(rows,chains,strict=True):
        while cursor<row['maps_upto']:
            m=mappings[cursor]
            need(m['record_offset']<row['record_offset'] and m['time_ns']<=row['time'],
                 'each caller uses only actual mappings preceding this sample in time and event order')
            update(m);cursor+=1
        if not row['in_target_exec_window']:continue
        need(row['pid']==row['tid']==target_pid and row['cpumode']==2,'actual attached user population')
        total+=1;period=row['period'];weight+=period;leaf=resolve(row['ip'])
        functions[leaf]+=period;function_n[leaf]+=1
        unknown+=leaf.startswith('unknown:');unknown_weight+=period*leaf.startswith('unknown:')
        labels=tuple(resolve(ip)for ip in chain)
        state=('empty'if not chain else'head_mismatch'if chain[0]!=row['ip']else
               'leaf_only'if len(chain)==1 else'depth_limit'if len(chain)==64 else'bounded_observed_frames')
        states[state]+=1
        # A mismatching chain never replaces the authoritative sampled leaf.
        key=(state,leaf,*labels);paths[key]+=period;path_n[key]+=1
        details.append(dict(time_ns=row['time'],period=period,leaf=leaf,frames=list(labels),
                            state=state,unwind_complete=False))
    need(total>0 and sum(function_n.values())==sum(path_n.values())==total and
         sum(functions.values())==sum(paths.values())==weight,'conserve every actual user sample/period')
    def table(weights,counts):
        return [dict(key=list(k)if isinstance(k,tuple)else k,samples=counts[k],period=v)
                for k,v in sorted(weights.items(),key=lambda x:(-x[1],x[0]))]
    result=dict(samples=total,period=weight,unknown_leaf_samples=unknown,unknown_leaf_period=unknown_weight,
        unwind_states=dict(states),functions=table(functions,function_n),paths=table(paths,path_n),
        unwind_complete=False,scope='Period-weighted sampled user CPU only, with unknowns in the denominator. '
        'Bridge function intervals use exact recorded mappings and pinned ELF bytes. Raw return addresses are not '
        'adjusted. Each displayed path is one bounded libdw observation, never an assertion of stack completeness; '
        'a truncated or mismatching path remains visible. No kernel, wall-time, whole-program or speedup attribution.')
    for name,value in (('attribution.json',result),('unwound.json',details)):
        blob=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
        need(len(blob)<=16<<20,'bounded complete private attribution table')
        (directory/name).write_bytes(blob)
    return result
