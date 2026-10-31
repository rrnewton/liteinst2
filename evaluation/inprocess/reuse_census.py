"""Strict private post-reap census decoder; no admission/performance credit."""
import collections
import fcntl
import os
import stat
import struct

MAGIC=0x315355534e454352
BYTES=8<<20
CAPS=(256,8192,4096,128,16384)
SIZES=(4352,64,320,4096,256)
OFFSETS=(4096,1118208,1642496,2953216,3477504)

def need(ok,message):
    if not ok:raise ValueError(message)

def descriptor(fd,nonce,parent):
    need(type(fd)is int and fd>2 and type(nonce)is int and 0<nonce<1<<64 and type(parent)is int and parent>0,'typed census descriptor identity')
    st=os.fstat(fd)
    need(stat.S_ISREG(st.st_mode)and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==0 and st.st_size==BYTES and
         fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE==os.O_RDWR and os.get_inheritable(fd)and
         fcntl.fcntl(fd,fcntl.F_GET_SEALS)==6,'actual initial census descriptor/seals')
    initial=(MAGIC,1,BYTES,4096,nonce,parent,st.st_dev,st.st_ino)
    data=os.pread(fd,BYTES+1,0)
    need(len(data)==BYTES and data[:64]==struct.pack('<8Q',*initial)and not any(data[64:]),'complete initial census header/zero backing')
    return dict(fd=fd,nonce=nonce,parent=parent,device=st.st_dev,inode=st.st_ino,bytes=BYTES,initial_seals=6)

def read(data,initial,pid,seals):
    need(type(data)is bytes and len(data)==BYTES and len(initial)==8 and seals==23 and type(pid)is int and pid>0,'whole post-reap sealed census')
    h=struct.unpack_from('<512Q',data)
    need(h[:8]==tuple(initial)and h[8:12]==(pid,pid,6,23)and 4096<=h[12]<(1<<47)-BYTES+1 and h[12]%4096==0 and h[13:16]==(1,1,1),'exact census attachment identity')
    need(h[16]<=22 and h[22]in(0,1)and h[24:30]==(*CAPS,2)and not any(h[30:]),'typed census error/capacity/header')
    n=h[17:22];need(all(v<=cap for v,cap in zip(n,CAPS,strict=True))and h[23]<=n[4],'bounded census counts')
    view=memoryview(data);parts=[];uncommitted=0
    for off,size,cap,count in zip(OFFSETS,SIZES,CAPS,n,strict=True):
        parts.append([view[off+i*size:off+(i+1)*size]for i in range(count)])
        # A killed writer may be inside exactly the next dictionary entry.
        skip=int(count<cap and (h[22]or h[16])) if size!=256 else 0
        if skip and any(view[off+count*size:off+(count+1)*size]):uncommitted+=1
        need(not any(view[off+(count+skip)*size:off+cap*size]),'zero unused census section beyond at most one interrupted append')
    need(uncommitted<=1,'single writer can leave only one unpublished dictionary entry')
    need(not any(view[7671808:]),'whole census reserved tail zero')
    pages=[]
    for b in parts[0]:
        m=struct.unpack_from('<32Q',b)
        need(m[0]>=4096 and m[0]<(1<<47)and not m[0]%4096 and m[1]>0 and m[2]>0 and m[9]<=m[0]<m[10]and
             m[10]-m[0]>=4096 and m[15]<(1<<31)and not m[17]and m[22:24]==(1,1)and not any(m[24:]),'complete exact source-page identity')
        pages.append((m,b[256:]))
    need(len({m for m,_ in pages})==len(pages),'unique exact source-page identities')
    keys=[]
    for b in parts[1]:
        k=struct.unpack('<8Q',b);pc,a,z,mode,epoch,address,length,signature=k
        need(0<a<=n[0]and 0<z<=n[0]and a!=z and pages[a-1][0][0]<pages[z-1][0][0]and
             any(0<=pc-pages[q-1][0][0]<=4096-15 for q in(a,z)),'source key complete pages and original entry')
        need((mode==2 and address==length==signature==0)or(mode==1 and epoch>0 and length==32 and address%32==0 and 0<address<(1<<47)-31),'exact source-key lifetime mode')
        keys.append(k)
    need(len(set(keys))==len(keys),'unique exact interned request keys')
    registries=[]
    for b in parts[3]:
        v=struct.unpack('<512Q',b);count=v[0]
        need(count<=128 and not any(v[1+2*count:])and all(0<a<z<=1<<47 for a,z in zip(v[1:1+2*count:2],v[2:1+2*count:2],strict=True)),'whole ordered protected registry')
        registries.append(v)
    need(len(set(registries))==len(registries),'unique complete protected registries')
    graphs=[]
    for b in parts[2]:
        v=struct.unpack_from('<8Q',b);heads=struct.unpack_from('<128H',b,64)
        need(0<v[0]<=n[1]and 0<v[1]<=n[3]and v[2]in(0,1)and 0<v[3]<=128 and v[4]>0 and v[5]>0 and
             all(4096<=x<1<<47 and x%4096==0 for x in v[6:])and not any(heads[v[3]:]),'complete publication graph metadata')
        key=keys[v[0]-1];addresses=[]
        for offset in heads[:v[3]]:
            need(offset<8192,'bounded publication source-page/head offset')
            addresses.append(pages[key[1+offset//4096]-1][0][0]+offset%4096)
        need(addresses[0]==key[0]and len(set(addresses))==len(addresses),'exact root and distinct certified head catalog')
        graphs.append(dict(words=v,heads=tuple(addresses)))
    attempts=[];finished=0
    for i,b in enumerate(parts[4]):
        v=struct.unpack('<32Q',b);mask=v[31]
        need(mask in(0,1,3,7,15,23,31)and (i==n[4]-1 or mask in(23,31)),'single unfinished final census transaction')
        if not mask:
            need(i==n[4]-1,'only reserved last attempt may lack selection commit');attempts.append(None);continue
        need(v[0]==i+1 and v[1]>=4096 and v[1]<1<<47 and v[2]<2 and v[3]<2 and v[4]&255 in(0,1,2)and not v[4]>>22 and
             ((v[4]>>16)&63)&~((v[4]>>8)&63)==0 and v[5]<=n[2]and v[8]>0,'complete selected attempt fields')
        if mask&2:need(0<v[9]<=n[1]and 0<v[10]<=n[3]and v[11]>0 and keys[v[9]-1][0]==v[1],'source commit binds this actual entry')
        if mask&4:
            need(1<=v[17]<=4 and v[21]in tuple((1<<j)-1 for j in range(1,11))and not v[22]&~v[21]and
                 (v[21]==v[22]==1023 if v[17]in(1,2)else v[22]==v[21]>>1),'only actually reached short-circuit predicates')
            if v[17]==3:need(0<(v[18]&0xffffffff)<18 and v[18]>>32 in(1,2),'exact classified plan refusal')
            else:need(v[18:21]==(0,0,0),'no invented miss for a successful plan/hit')
        if mask&8:
            need(v[17]!=3 and 0<v[23]<=n[2]and v[24]<=n[2]and v[26]>0,'actual completed bind identity')
            g=graphs[v[23]-1]['words'];need(g[5]==v[26],'bound generation matches publication catalog')
            if v[17]==4:need(g[:3]==(v[9],v[10],v[3])and g[4]==v[11]and v[24:26]==v[5:7],'actual cold publication and selected victim')
            else:
                need(v[23]==v[5]and v[26]==v[6]and not any(v[24:26]),'actual warm bind never invents retirement')
                oldkey=keys[g[0]-1];request=keys[v[9]-1]
                need(g[1:3]==(v[10],v[3])and oldkey[1:]==request[1:]and
                     (oldkey[0]==v[1]if v[17]==1 else oldkey[0]!=v[1]and v[1]in graphs[v[23]-1]['heads']),
                     'warm source/lifetime/registry/bank and root versus certified-head identity')
        if mask&16:
            finished+=1
            need(v[28]==v[11]and ((mask==23 and v[17]==3 and v[27]==1 and v[29:31]==(0,0))or
                 (mask==31 and v[27]==2 and v[30]&255 in(1,2)and v[30]>>8 in(0,1,2))),'exact cancelled/completed transaction')
            if mask==31:
                members=v[30]&255;peer=v[30]>>8
                need((members==1 and peer==2 and v[29]==0)or(members==2 and peer<2 and peer!=v[2]and 0<v[29]<=n[2]),'actual whole completion member touches')
        attempts.append(v)
    need(h[23]<=finished<=h[23]+1,'finish count may lag only its last committed row')
    result=_replay(attempts,keys,graphs)
    result.update(schema=1,bytes=BYTES,counts=dict(zip(('pages','keys','graphs','registries','attempts'),n,strict=True)),
        recorder_error=h[16],interrupted_writer=bool(h[22]),finished=finished,complete_census=h[16]==h[22]==0 and h[23]==finished and all(v is not None and v[31]in(23,31)for v in attempts),
        scope='committed killed-prefix diagnostic only',qualification_credit=False,performance_credit=False)
    return result

def _replay(attempts,keys,graphs):
    slots=[None,None];eight=[None]*8;eight_unknown=None;totals=collections.Counter();misses=collections.Counter();failure_keys=set();history={};evicted=set();last_success={};sequence=0;tree=[0]*(CAPS[4]+1);distinct=0;distances=collections.Counter()
    def add(index,delta):
        while index<len(tree):tree[index]+=delta;index+=index&-index
    def prefix(index):
        value=0
        while index:value+=tree[index];index-=index&-index
        return value
    def choose(cache,pc,seen,passed,actual=False):
        roots=[i for i,g in enumerate(cache)if g is not None and keys[graphs[g[0]-1]['words'][0]-1][0]==pc]
        need(len(roots)<=1,'PC-only root match remains unique')
        if roots:
            if actual:need(seen==1 and passed==1,'actual root advisory evaluated alone')
            return roots[0],1
        visited=0
        for i,g in enumerate(cache):
            if g is None:continue
            found=pc in graphs[g[0]-1]['heads']
            if actual:
                visited|=1<<(4+i)
                need(seen&(1<<(4+i))and bool(passed&(1<<(4+i)))==found,'actual certified-head lookup observation')
                if found:
                    visited|=1<<(1+i)
                    need(seen&(1<<(1+i)),'matching actual head has observed source-pair advisory')
                    if passed&(1<<(1+i)):
                        need(seen==visited,'no unevaluated selector observations');return i,2
            elif found:
                # Different placement/source-pair authority is not reconstructed.
                return None,None
        if actual:need(seen==visited|8 and passed&8,'actual cold source-pair advisory with no unevaluated predicates')
        empty=next((i for i,g in enumerate(cache)if g is None),None)
        return (empty if empty is not None else min(range(len(cache)),key=lambda i:cache[i][1])),0
    for v in attempts:
        if v is None:break
        i=v[0];pc=v[1];mask=v[31];seen=(v[4]>>8)&63;passed=(v[4]>>16)&63;kind=v[4]&255
        selected,selection=choose(slots,pc,seen,passed,True)
        need((selected,selection)==(v[2],kind),'replayed original PC-first two-slot selection')
        old=slots[selected]
        need((old[0]if old else 0)==v[5]and(old[1]if old else 0)==v[7],'replayed selected graph and actual last completion')
        if old:need(graphs[old[0]-1]['words'][5]==v[6],'replayed old generation')
        else:need(v[6]==v[7]==0,'empty selected slot has no generation or completion')
        totals['selected']+=1
        if eight_unknown is None:
            candidate,reason=choose(eight,pc,seen,passed)
            if candidate is None or candidate!=selected or reason!=selection:
                eight_unknown=dict(attempt=i,reason='unobserved alternative source/placement/root or completion state; all later LRU unknown')
        if not mask&4:break
        plan=v[17];totals[{1:'root_hits',2:'internal_hits',3:'cold_refusals',4:'cold_valid'}[plan]]+=1
        if plan in(3,4)and kind==1:totals['cold_on_selected_root']+=1
        if plan==3:
            miss=tuple(v[18:21]);misses[str(v[18]&0xffffffff)]+=1;fk=(v[9],v[10],v[2],v[3],miss)
            totals['repeat_exact_refusals']+=fk in failure_keys;failure_keys.add(fk)
        if not mask&8:
            if mask&16:totals['cancelled']+=1
            continue
        if plan==4:
            identity=(v[9],v[10]);previous=history.get(identity)
            if previous is not None:
                totals['repeat_exact_publications']+=1
                if previous in evicted:totals['recompiled_after_recorded_eviction']+=1
            if v[24]:evicted.add(v[24]);totals['retirements']+=1
            history[identity]=v[23];totals['publications']+=1
        identity=(graphs[v[23]-1]['words'][0],graphs[v[23]-1]['words'][1])
        if identity in last_success:
            previous=last_success[identity];distance=distinct-prefix(previous)
            distances['0-1'if distance<2 else'2-7'if distance<8 else'8+']+=1
            add(previous,-1)
        else:distinct+=1
        sequence+=1;last_success[identity]=sequence;add(sequence,1)
        # Replacement occurs at actual bind; last_completed is assigned only
        # by the later complete receipt, never by a refused build.
        slots[selected]=(v[23],old[1]if old else 0)
        if eight_unknown is None:eight[selected]=slots[selected]
        if mask&16:
            if v[27]==2:
                slots[selected]=(v[23],v[28]);totals['completed']+=1
                if v[29]:
                    peer=v[30]>>8;need(slots[peer]is not None and slots[peer][0]==v[29],'actual peer completion touches its retained graph')
                    slots[peer]=(v[29],v[28]);totals['peer_touches']+=1
                if eight_unknown is None:
                    # A different eight-member peer choice is not established by
                    # a two-slot trace, even if its primary entry matched.
                    if any(eight[j]!=slots[j]for j in range(2))and any(x is not None for x in eight[2:]):
                        eight_unknown=dict(attempt=i,reason='unobserved counterfactual peer choice; all later LRU unknown')
                    else:eight[:2]=slots[:]
            else:totals['cancelled']+=1
    return dict(actual_two_replay='exact_committed_prefix',events=dict(totals),miss_reasons=dict(misses),
        distinct_successful_key_distance=dict(distances),
        eight=dict(status='unknown'if eight_unknown else'prefix_identical_only',first_unknown=eight_unknown,
                   admission_prediction=False,future_state_known=eight_unknown is None))
