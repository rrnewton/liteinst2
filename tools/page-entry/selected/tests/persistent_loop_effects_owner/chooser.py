"""Independent, bounded, whole-byte loop-envelope reconstruction.

Source bytes are the input. Captured candidate/descriptor fields are compared
only after reconstruction, never used to discover the graph. Unknown source
grammar raises CoverageError; it cannot become a completed NO_ENVELOPE result.
This descriptive checker grants no ownership, source lease or execution right.
"""
import importlib.util
import struct
from pathlib import Path

_s=importlib.util.spec_from_file_location('loop_history_source_decode',
    Path(__file__).with_name('source_decode12.py'))
decoder=importlib.util.module_from_spec(_s);_s.loader.exec_module(decoder)
need=decoder.need
HEADS,BOUNDARIES,PAGE,SIZE=128,8,4096,83320
OK,NO_ENVELOPE,DISCOVERY_LIMIT=0,1,3602
UNSUPPORTED,FETCH_END,JUMP=1,2,3
PREFIX,INTERIOR,UNREACHABLE,NO_EXIT,EXIT_LIMIT,LINK_LIMIT=1,2,3,4,5,6


class Limit(Exception):
    pass


def candidate(first,end,latch):
    return dict(first=first,end=end,latch=latch,result=PREFIX,heads=0,
                exits=0,links=0,backwards=0,stores=0,source_bytes=0,reserved=0)


def candidate_bytes(c):
    return struct.pack('<3Q8I',*(c[k]for k in('first','end','latch','result',
        'heads','exits','links','backwards','stores','source_bytes','reserved')))


def shape_bytes(s):
    return(candidate_bytes(s['choice'])+
        b''.join(struct.pack('<Q8I',*h)for h in s['head'])+bytes((128-len(s['head']))*40)+
        b''.join(struct.pack('<Q2I',*a)for a in s['exit'])+bytes((8-len(s['exit']))*16)+
        b''.join(struct.pack('<4I',*a)for a in s['link'])+bytes((8-len(s['link']))*16))


def choose(pages,source,entry):
    need(type(pages)is tuple and len(pages)==2 and
         all(type(x)is int and 0<=x<(1<<47)and not x%PAGE and x+PAGE<=1<<47 for x in pages)
         and pages[0]<pages[1] and type(source)is bytes and len(source)==8192 and
         type(entry)is int and any(p<=entry<p+PAGE for p in pages),
         'actual ordered two-page source and genuine original chooser root')
    nodes=[];by_pc={};candidates=[];selected=None;eligible=0;stop=stop_pc=0
    def window(pc):
        out=bytearray()
        for address in range(pc,pc+15):
            index=next((i for i,p in enumerate(pages)if p<=address<p+PAGE),None)
            if index is None:break
            out.append(source[index*PAGE+address-pages[index]])
        return bytes(out)
    def fetch(pc):
        if pc in by_pc:return by_pc[pc]
        raw=window(pc)
        if not raw:return None
        if len(nodes)==HEADS:raise Limit()
        # Only an independently complete source description is cached.
        item=decoder.decode(pc,raw);index=len(nodes)
        need(len(item['whole'])==488 and item['pc']==pc and
             0<item['length']<=len(raw)and item['next_pc']==pc+item['length'],
             'complete independent source descriptor and NONE/store theorem')
        by_pc[pc]=index;nodes.append(item);return index
    def prefix(first):
        pc=first
        while pc<entry:
            i=fetch(pc)
            if i is None:return False
            d=nodes[i]
            if not d['kind'] or d['flow']==2 or d['next_pc']>entry:return False
            pc=d['next_pc']
        return pc==entry
    def interval(c):
        s=dict(choice=dict(c),head=[],exit=[],link=[]);q=s['choice']
        linear=[];pc=c['first']
        while pc<c['end']:
            i=fetch(pc)
            if i is None:return s
            d=nodes[i]
            if not d['kind'] or d['next_pc']>c['end']:return s
            if len(linear)==HEADS:raise Limit()
            linear.append(i);pc=d['next_pc']
        addresses={nodes[i]['pc']:j for j,i in enumerate(linear)}
        if pc!=c['end'] or not linear or entry not in addresses:return s
        q['heads']=len(linear);edges=[]
        for i in linear:
            d=nodes[i];flow=d['flow'];q['stores']+=d['kind']==2
            q['source_bytes']+=d['length']
            targets=(d['next_pc'],)if flow==0 else(d['target'],d['next_pc'])if flow==1 else(d['target'],)
            row=[]
            for arm,target in enumerate(targets):
                if c['first']<=target<c['end']:
                    if target not in addresses:q['result']=INTERIOR;return s
                    token=addresses[target]
                    q['backwards']+=flow!=0 and arm==0 and target<=d['pc']
                else:
                    if flow==0:return s
                    token=None;q['exits']+=1
                row.append((token,target))
            edges.append(row)
        if not q['exits']:q['result']=NO_EXIT;return s
        if q['exits']>BOUNDARIES:q['result']=EXIT_LIMIT;return s
        order=[addresses[entry]];rank={order[0]:0}
        for i in order:
            for target,_ in edges[i]:
                if target is not None and target not in rank:
                    rank[target]=len(order);order.append(target)
        if len(order)!=len(linear):q['result']=UNREACHABLE;return s
        for at,i in enumerate(order):
            d=nodes[linear[i]];h=[d['pc'],linear[i],d['kind'],d['flow'],len(edges[i]),0,0,0,0]
            s['head'].append(h)
            for arm,(target,pc)in enumerate(edges[i]):
                if target is None:
                    h[7]|=1<<arm;h[5+arm]=HEADS+len(s['exit'])
                    s['exit'].append((pc,at,arm))
                else:
                    k=rank[target];h[5+arm]=k
                    if at//64!=k//64:
                        if q['exits']+q['links']==BOUNDARIES:
                            q['result']=LINK_LIMIT;return s
                        s['link'].append((at,arm,k,0));q['links']+=1
        need(len(s['exit'])==q['exits'],'independently counted exact external arm roster')
        q['result']=OK;return s
    def rank(c):return(c['exits']+c['links'],-c['backwards'],c['heads'],c['first'],c['end'])
    result=NO_ENVELOPE
    try:
        spine=[];pc=entry
        while True:
            i=fetch(pc)
            if i is None:stop,stop_pc=FETCH_END,pc;break
            spine.append(i);d=nodes[i]
            if not d['kind']:stop,stop_pc=d['stop'],pc;break
            if d['flow']==2:stop,stop_pc=JUMP,pc;break
            pc=d['next_pc']
        for i in spine:
            d=nodes[i]
            if not d['kind']or d['kind']==2 or d['flow']==0 or d['target']>entry:continue
            if len(candidates)==HEADS:raise Limit()
            c=candidate(d['target'],d['next_pc'],d['pc']);candidates.append(c)
            if not prefix(c['first']):continue
            s=interval(c);candidates[-1]=s['choice']
            if s['choice']['result']!=OK:continue
            if selected is None or rank(s['choice'])<rank(selected['choice']):selected=s
            eligible+=1
        result=OK if eligible else NO_ENVELOPE
    except Limit:
        result=DISCOVERY_LIMIT;selected=None
    need(result==OK or selected is None,'no selected authority escapes incomplete discovery')
    header=struct.pack('<4I4Q4I',12,SIZE,int(result==OK),result,*pages,entry,stop_pc,
                       stop,len(nodes),len(candidates),eligible)
    raw=(header+source+b''.join(d['whole']for d in nodes)+bytes((128-len(nodes))*488)+
         b''.join(candidate_bytes(c)for c in candidates)+bytes((128-len(candidates))*56)+
         (shape_bytes(selected)if selected is not None else bytes(5432)))
    need(len(raw)==SIZE,'independent complete witness extent and unused tails')
    return dict(raw=raw,result=result,ready=result==OK,pages=pages,entry=entry,source=source,
        nodes=tuple(nodes),candidates=tuple(candidates),eligible=eligible,selected=selected,
        stop=stop,stop_pc=stop_pc)


def validate(raw,pages,source,entry,expected_result=None):
    need(type(raw)is bytes and len(raw)==SIZE,'whole actual source-bound chooser witness')
    rebuilt=choose(pages,source,entry)
    need(raw==rebuilt['raw'],'whole independent source/descriptor/candidate/winner/BFS reconstruction')
    if expected_result is not None:
        need(rebuilt['result']==expected_result,'exact complete chooser outcome; no fallback on error')
    return rebuilt
