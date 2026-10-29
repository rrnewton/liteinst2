"""Strict CPU_CLOCK perf.data reader with its exact optional DUMMY sideband."""
import collections, csv, hashlib, json, os, struct
from pathlib import Path

def need(v, why):
    if not v: raise ValueError(why)

def elf(path):
    b=path.read_bytes(); h=struct.unpack_from('<16sHHIQQQIHHHHHH',b)
    need(h[0][:6]==b'\x7fELF\x02\x01' and h[2]==62 and h[9]==56 and h[11]==64,
         'actual ELF64 x86-64 tables')
    def region(at,n):
        need(0<=at<=len(b) and 0<=n<=len(b)-at,'bounded ELF extent');return b[at:at+n]
    ph=[struct.unpack('<IIQQQQQQ',region(h[5]+i*56,56)) for i in range(h[10])]
    sh=[struct.unpack('<IIQQQQIIQQ',region(h[6]+i*64,64)) for i in range(h[12])]
    symbols=[]; ids=[]
    for s in sh:
        if s[1] in (2,11):
            need(s[9]==24 and s[5]%24==0 and s[6]<len(sh),'symbol table layout')
            names=region(sh[s[6]][4],sh[s[6]][5])
            for at in range(s[4],s[4]+s[5],24):
                name,info,other,section,value,size=struct.unpack('<IBBHQQ',region(at,24))
                if info&15 not in (2,10) or not section or not size:continue
                need(name<len(names) and b'\0' in names[name:],'symbol name extent')
                symbols.append((value,value+size,names[name:].split(b'\0',1)[0].decode('utf-8','strict')))
        if s[1]==7:
            at,end=s[4],s[4]+s[5]
            while at+12<=end:
                n,z,t=struct.unpack('<III',region(at,12));at+=12
                name=region(at,n);at+=(n+3)&~3;desc=region(at,z);at+=(z+3)&~3
                need(at<=end,'ELF note extent')
                if name==b'GNU\0' and t==3:ids.append(desc.hex())
    st=path.stat()
    return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest(),path=str(path),
        device=[os.major(st.st_dev),os.minor(st.st_dev)],inode=st.st_ino,
        build_ids=ids,loads=ph,symbols=sorted(set(symbols)))

def summarize(path, bridge, target_pid, cpu, directory, release_ns, exit_ready_ns):
    """Whole exec-to-exit envelope; event loss or truncation never hidden."""
    data=path.read_bytes(); need(104<=len(data)<=128<<20,'bounded retained perf file')
    need(data[:8]==b'PERFILE2','native little-endian perf.data header')
    header,entry,attrs,attr_bytes,start,size=struct.unpack_from('<6Q',data,8)
    need(104<=header<=len(data) and entry>=112 and attr_bytes in(entry,2*entry) and
         attrs>=header and attrs+attr_bytes<=start and start+size<=len(data),
         'one CPU_CLOCK event with at most its exact DUMMY sideband companion')
    # Event ID sections are part of each perf_file_attr, not the sample payload.
    ids={};id_positions={};attributes=[];ranges=[];paired=attr_bytes==2*entry
    for index,at in enumerate(range(attrs,attrs+attr_bytes,entry)):
        typ,attrsize,config,freq,sample_type=struct.unpack_from('<IIQQQ',data,at)
        flags=struct.unpack_from('<Q',data,at+40)[0]
        need(96<=attrsize<=entry-16 and typ==1 and freq==99 and flags&(1<<10) and
             flags&(1<<18) and flags&(1<<25) and struct.unpack_from('<i',data,at+92)[0]==1,
             'bounded 99Hz software event with MONOTONIC and full sideband identity')
        need(config==(0 if index==0 else 9), 'exact CPU_CLOCK followed only by non-sampling DUMMY')
        if index==0:need(not flags&((1<<4)|(1<<5)), 'CPU_CLOCK includes both user and kernel samples')
        if paired:
            need(entry==160 and attrsize==144 and sample_type==0x1c7 and
                 flags==(0x2040403 if index==0 else 0x463943763) and
                 struct.unpack_from('<Q',data,at+32)[0]==20 and
                 data[at+48:at+92]==bytes(44) and data[at+96:at+144]==bytes(48),
                 'exact observed CPU_CLOCK/DUMMY attributes; no new sampling event or payload')
        off,n=struct.unpack_from('<QQ',data,at+entry-16)
        need(header<=off<=attrs and 0<n<=attrs-off and n%8==0 and
             all(off+n<=lo or hi<=off for lo,hi in ranges), 'bounded disjoint event ID sections')
        values=struct.unpack_from('<'+'Q'*(n//8),data,off);ranges.append((off,off+n))
        need(all(v>0 and v not in ids for v in values) and len(set(values))==len(values),
             'nonzero unique IDs within and across the exact event attributes')
        ids.update({v:index for v in values});id_positions.update({v:i for i,v in enumerate(values)});attributes.append(dict(config=config,sample_type=sample_type,ids=len(values)))
    sample_type=attributes[0]['sample_type']
    need(all(a['sample_type']==sample_type for a in attributes), 'same explicit ID suffix layout for both events')
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
    allowed=1|2|4|8|64|128|256|512|65536
    need(sample_type&~allowed==0 and sample_type&(1|2|4|128|256)==(1|2|4|128|256),
         'exact supported scalar IP/TID/time/CPU/period sample layout')
    side=[(bit,name)for bit,name in ((2,'tid'),(4,'time'),(64,'id'),(512,'stream'),(128,'cpu'),(65536,'identifier'))if sample_type&bit]
    indexed={};initial=True;initial_records=0;metadata=collections.Counter()
    def suffix(b):
        at=len(b)-8*len(side);need(at>=8,'complete sideband identity');result={}
        for bit,name in side:
            result[name]=struct.unpack_from('<II'if bit in(2,128)else'<Q',b,at);at+=8
        return result,len(b)-8*len(side)
    def event_identity(b,kind,misc):
        nonlocal initial_records
        sid,end=suffix(b)
        if all(x==0 for value in sid.values() for x in value):
            need(initial and kind in(1,10,17,3) and not(kind==3 and misc&(1<<13)),
                 'zero identity is only initial synthetic mapping/comm/ksymbol metadata')
            initial_records+=1;return sid,end
        if sample_type&64:
            event_id=sid['id'][0]
            need(event_id in ids, 'actual sideband ID belongs to a declared event')
            if paired and kind in(1,3,4,7,10,17):
                need(ids[event_id]==1, 'runtime mapping/task sideband belongs only to DUMMY')
            if 'identifier'in sid:need(sid['identifier']==sid['id'], 'duplicate sideband identifier agrees')
            if event_id in indexed:
                need(sid['cpu']==(indexed[event_id][1],0), 'sideband CPU agrees with exact ID_INDEX')
        else:need(not paired, 'paired routing requires explicit PERF_SAMPLE_ID')
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
    obj=elf(bridge);maps={};rows=[];counts=collections.Counter();lost=0;throttles=0
    at=start;last_time=0;execs=[];exits=[];mappings=[]
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
            need(n>0 and address+n<1<<64,'MMAP address interval')
            m=dict(pid=pid,address=address,bytes=n,offset=offset,name=name,
                   build_id=None,device=None,inode=None,prot=None)
            if kind==10:
                m['prot']=struct.unpack_from('<I',b,64)[0]
                if misc&(1<<14):
                    z=b[40];need(1<=z<=20 and b[41:44]==bytes(3) and b[44+z:64]==bytes(20-z),'MMAP2 complete build-id extent/reserved bytes');m['build_id']=b[44:44+z].hex()
                else:
                    major,minor,inode=struct.unpack_from('<IIQ',b,40);m.update(device=[major,minor],inode=inode)
            maps.setdefault(pid,[]).append(m);mappings.append(m)
        elif kind==3:
            sid,end=event_identity(b,kind,misc);string(b,16,end,'complete COMM name')
            pid,tid=struct.unpack_from('<II',b,8)
            if misc&(1<<13):
                maps[pid]=[]
                if pid==tid==target_pid:
                    need(sid['tid']==(pid,tid),'COMM_EXEC actual target identity');execs.append(sid['time'][0])
        elif kind in(4,7):
            sid,end=event_identity(b,kind,misc);need(end==32,'complete task record');pid,ppid,tid,ptid,stamp=struct.unpack_from('<IIIIQ',b,8)
            if kind==7:maps[pid]=list(maps.get(ppid,[]))
            elif pid==tid==target_pid:exits.append(stamp)
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
            need(pos==len(b) and v['cpu']==(cpu,0),'complete sample on reserved CPU')
            if sample_type&64:
                ident=v['id'][0]
                need(ident in ids and ids[ident]==0, 'CPU sample belongs only to CPU_CLOCK, never DUMMY or unknown ID')
                if paired:need(ident in indexed and indexed[ident][1]==cpu and not initial,'CPU sample joins complete ID_INDEX and initial boundary')
                if 'identifier'in v:need(v['identifier']==v['id'], 'duplicate sample identifier agrees')
            else:need(not paired, 'paired sample routing requires explicit ID')
            need(v['period'][0]>0, 'positive actual CPU_CLOCK period')
            pid,tid=v['tid'];ip=v['ip'][0];stamp=v['time'][0];mode=misc&7
            need(stamp>=last_time,'single-CPU sample order');last_time=stamp
            reason='other_pid'if pid!=target_pid else'kernel'if mode==1 else'no_recorded_mapping'if mode==2 else'other_cpumode'
            m=next((m for m in reversed(maps.get(pid,[]))if m['address']<=ip<m['address']+m['bytes']),None)
            symbol='';fileoff=None;value=None;candidate=False;candidate_fileoff=None
            if pid==target_pid and mode==2 and m:
                reason='other_mapping'
                if m['name']==obj['path'] and m['prot']is not None and m['prot']&4:
                    candidate=True;candidate_fileoff=m['offset']+ip-m['address'];reason='bridge_identity_unresolved'
                    identity=(m['build_id']is not None and m['build_id']in obj['build_ids'])or(
                        m['build_id']is None and m['device']==obj['device'] and m['inode']==obj['inode'])
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
        else:need(False,'unsupported perf record type '+str(kind))
    need(not paired or (not initial and len(indexed)==len(ids)), 'complete exact two-event metadata')
    need(execs and len(exits)==1 and release_ns<=execs[0]<=execs[-1]<exits[0]<=exit_ready_ns and execs==sorted(execs),
         'actual same-PID exec-to-EXIT envelope inside release/wait boundary')
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
        metadata_counts=dict(metadata),exec_timestamps_ns=execs,exit_timestamp_ns=exits[0],sampled_period_total=sum(r['period']for r in rows),
        first_sample_ns=rows[0]['time']if rows else None,last_sample_ns=rows[-1]['time']if rows else None,
        full_exec_exit_envelope=True,loss_free=lost==0 and throttles==0,
        bridge={k:obj[k]for k in('sha256','bytes','build_ids')},qualification=False,
        scope='99Hz statistical user/kernel CPU samples across the actual exec-to-exit envelope. Pre-exec wrapper samples retained separately; unknown mapping identities remain unknown. No baseline timing, whole-time attribution, callgraph or performance credit.')
