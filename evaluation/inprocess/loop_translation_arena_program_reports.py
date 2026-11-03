"""Actual bounded node ownership over every original real-program validator.

Eight active bindings and dormant immutable nodes are distinct. These terminal
observations grant no admission authority and infer no unobserved guest events.
"""
import json
from functools import partial
from types import SimpleNamespace
from page_selected import need
from loop_ro_oracle_reports import row
import loop_cache8_program_reports as cache8
import loop_group_descriptor_program_reports as program
import loop_group_descriptor_reports as descriptor

PREFIX=b'LI2_LOOP_ARENA_PROGRAM '
NODE_PREFIXES=tuple(('LI2_LOOP_ARENA_NODES'+str(i)+' ').encode()for i in range(3))
FIELDS=('version','status','failure_code','nodes','slots','initialized','poisoned',
    'topology_epoch','next_binding','detached','rebound','rebound_peers','cold_nodes',
    'evicted','epoch_invalidations','stale_refusals','physical_checks',
    'writer_next_binding','rebind_mask')+tuple(
    'slot'+str(i)+'_'+name for i in range(8)for name in ('node','binding'))
NODE_NAMES=('generation','claim','completed_serial','active_slot','root','build_serial',
    'issued','closed','reusable','node_epoch','issued_epoch','prepared_serial','prepared_binding')
NODE_FIELDS=tuple(('version','status','failure_code')+tuple(
    'node'+str(i)+'_'+name for i in range(4*chunk,4*(chunk+1))for name in NODE_NAMES)
    for chunk in range(3))
CONTROL_COUNT=633
DEFAULT=(cache8.prior,cache8.certificate,cache8.rx,row,cache8,program,descriptor)
prior=cache8.prior


def _schema(node_count):
    need(type(node_count)is int and node_count in(12,128),'exact separately bound arena node capacity')
    if node_count==12:return NODE_PREFIXES,NODE_FIELDS,1,CONTROL_COUNT
    prefixes=tuple(('LI2_LOOP_ARENA_NODES'+str(i)+' ').encode()for i in range(32))
    fields=tuple(('version','status','failure_code')+tuple(
        'node'+str(i)+'_'+name for i in range(4*chunk,4*(chunk+1))for name in NODE_NAMES)
        for chunk in range(32))
    return prefixes,fields,2,5650


def split(stderr,parse=row,*,node_count=12):
    node_prefixes,node_fields,version,_=_schema(node_count)
    row_count=1+node_count//4
    need(type(stderr)is bytes and stderr.endswith(b'\n'),'whole actual arena program terminal')
    lines=stderr[:-1].split(b'\n');prefixes=(PREFIX,)+node_prefixes
    positions=[];values=[]
    need(len(FIELDS)==35 and tuple(map(len,node_fields))==(55,)*(node_count//4),
         'complete summary and all twelve actual node fields'if node_count==12 else
         'complete summary and all128 actual node fields')
    for prefix,fields in zip(prefixes,(FIELDS,)+node_fields,strict=True):
        found=[i for i,line in enumerate(lines)if line.startswith(prefix)]
        need(len(found)==1,'one complete actual arena summary or node row')
        positions.append(found[0])
        values.append(parse(lines[found[0]],prefix,fields)if node_count==12 else
                      parse(lines[found[0]],prefix,fields,version=version))
    first=positions[0]
    need(first>0 and positions==list(range(first,first+row_count)) and first==len(lines)-row_count-3 and
         lines[first-1].startswith(b'LI2_PERSISTENT_UNREGISTERED ') and
         lines[first+row_count].startswith(cache8.PREFIX) and
         lines[first+row_count+1].startswith(cache8.TRANSIT_PREFIX) and lines[first+row_count+2].startswith(cache8.RX_PREFIX),
         'four arena rows at the exact producer boundary before unchanged CACHE8 and RX rows'if node_count==12 else
         '33 arena rows at the exact producer boundary before unchanged CACHE8 and RX rows')
    need(all(value['status']==value['failure_code']==0 for value in values),
         'all four actual arena rows report successful complete programs'if node_count==12 else
         'all33 actual arena rows report successful complete programs')
    nodes=tuple({name:values[1+i//4]['node'+str(i)+'_'+name]for name in NODE_NAMES}for i in range(node_count))
    return values[0],nodes,b'\n'.join(lines[:first]+lines[first+row_count:])+b'\n',first,values


def retained(arena,nodes,counts,actual,d,s,*,node_count=12):
    """Fresh program theorem from all node identities and actual call sites."""
    _schema(node_count)
    if node_count==128:need(len(nodes)==128,'every actual immutable node is present in the capacity theorem')
    need((arena['nodes'],arena['slots'],arena['initialized'],arena['topology_epoch'])==(node_count,8,1,1) and
         arena['poisoned']in(0,1) and arena['rebind_mask']==arena['stale_refusals']==0,
         'exact initialized twelve-node topology and no outstanding fresh preparation or invented stale count'if node_count==12 else
         'exact initialized128-node topology and no outstanding fresh preparation or invented stale count')
    bindings=tuple(arena['slot'+str(i)+'_binding']for i in range(8))
    active=tuple(arena['slot'+str(i)+'_node']for i in range(8))
    need(len(set(active))==8 and all(n<node_count for n in active) and
         len(set(bindings))==8 and all(0<b<=arena['next_binding']for b in bindings) and
         max(bindings)==arena['next_binding']==arena['writer_next_binding'] and
         arena['next_binding']>=8 and arena['detached']<=arena['next_binding']-8,
         'eight unique current node bindings and the actual protected monotone binding identity')
    generations=tuple(n['generation']for n in nodes);installed=sum(g>0 for g in generations)
    need(all(0<=g<=d['publications']for g in generations) and
         len({g for g in generations if g})==installed and max(generations)==d['publications'] and
         d['retirements']==d['publications']-installed and arena['cold_nodes']==d['publications'],
         'all twelve immutable generations account for every actual publication and retirement'if node_count==12 else
         'all128 immutable generations account for every actual publication and retirement')
    for i,n in enumerate(nodes):
        need(n['active_slot']==(active.index(i)if i in active else 8) and
             n['node_epoch']>0 and n['prepared_serial']==n['prepared_binding']==0,
             'actual node-to-binding inverse and no unused current preparation at successful exit')
        need(all(n[name]in(0,1)for name in ('claim','issued','closed','reusable')),
             'literal node claim, issuance, closure and reuse values')
        if n['generation']:
            need(n['issued']==1 and n['claim']+n['closed']==1 and
                 (n['active_slot']<8 or n['closed']==1) and
                 0<n['build_serial']<=n['completed_serial']<=d['serial'] and
                 0<n['root']<1<<47 and 0<n['issued_epoch']<=n['node_epoch'] and
                 n['reusable']==int(n['closed']==1 and n['issued_epoch']==n['node_epoch']),
                 'installed nodes retain exact completed claims or consumed dormant closure and exposure state')
        else:
            need(all(n[name]==0 for name in NODE_NAMES if name not in ('active_slot','node_epoch')),
                 'uninstalled nodes have no fabricated publication, completion or issued proof')
    need(sum(n['node_epoch']-1 for n in nodes)==arena['epoch_invalidations'],
         'every counted node exposure advances exactly one real node epoch')
    need(all(counts['slot'+str(i)+'_'+name]==nodes[node][other]
             for i,node in enumerate(active)for name,other in
             (('generation','generation'),('permit','claim'),('completed_serial','completed_serial'))) and
         all(counts['slot'+str(i)+'_'+name]==d['slot'+str(i)+'_'+name]
             for i in range(2)for name in ('generation','permit','completed_serial')),
         'all eight actual slot observations and original two slots join the exact node owner')
    need(0<=d['selected_slot']<8,'actual selected arena binding')
    selected=nodes[active[d['selected_slot']]]
    need(d['generation']==selected['generation'] and d['permit']==selected['claim'] and
         d['build_serial']==selected['build_serial'],
         'selected original owner names the same immutable node generation, claim and build')
    bound=tuple(counts['bound'+str(i)]for i in range(9))
    entered=tuple(counts['entered'+str(i)]for i in range(9))
    completed=tuple(counts['completed'+str(i)]for i in range(9))
    need(bound==entered==completed and bound[0]==0 and
         sum(entered)==d['entries']==d['completed'] and
         d['dual_entries']==entered[2] and d['dual_completed']==completed[2],
         'all successful arena bindings enter and complete at their unchanged active member count')
    total=sum(i*entered[i]for i in range(1,9));peers=sum((i-1)*entered[i]for i in range(1,9))
    need(actual['entries']==total and actual['quiet_releases']==sum(completed) and
         counts['accepted']==peers and counts['attach_attempts']==peers+counts['source_declines'],
         'actual weighted active-member entries, completed groups and bounded peer proposal partition')
    closed=sum(n['closed']for n in nodes)
    need(arena['detached']==arena['rebound']+arena['rebound_peers']+arena['evicted']+closed and
         arena['physical_checks']==arena['rebound']+arena['rebound_peers'] and
         d['permit_claims']+arena['rebound']+arena['rebound_peers']+arena['evicted']==
             d['hits']+s['hits']+d['retirements']+peers+arena['detached'],
         'real detach claims, dormant primary/peer consumption and retired closed-node conservation')
    need(counts['cold_calls']==d['cold_attempts'] and
         counts['compact_build_calls']==counts['compact_validate_calls']==d['publications'],
         'the original cold and compact API calls account for every successful publication')


def _pipeline(arena,nodes,deps,*,node_count=12):
    _schema(node_count)
    original,ro,rx,parse,shared,group,descriptor=deps
    certificate=SimpleNamespace(check=partial(ro.check,physical_checks=arena['physical_checks']),
        controls=partial(ro.controls,physical_checks=arena['physical_checks']))
    terminal=shared.configured(original,certificate,rx,parse,counts_version=2,
        retained_check=partial(retained,arena,nodes,node_count=node_count))
    return group.configured(terminal,descriptor,parse)


def check(stdout,stderr,args,kind,mode,*,dependencies=None,node_count=12):
    deps=DEFAULT if dependencies is None else dependencies
    arena,nodes,ordinary,_,_=split(stderr,deps[3],node_count=node_count)
    result=_pipeline(arena,nodes,deps,node_count=node_count).check(stdout,ordinary,args,kind,mode)
    need(not result['descriptor']['poisoned'] or arena['poisoned']==1,
         'actual descriptor poison also retires arena reuse through the shared owner path')
    result.update(arena=arena,arena_nodes=list(nodes),
        profile='persistent-loop-translation-arena-program-v1'if node_count==12 else 'persistent-loop-translation-arena-program-v2',
        arena_count_scope='Actual twelve-node publication, detach, rebind, exposure and active-binding observations. No absent events, internal iterations or performance inferred.'if node_count==12 else
            'Actual128-node publication, detach, rebind, exposure and active-binding observations. No absent events, internal iterations or performance inferred.',
        qualification_credit=False)
    return result


def controls(stdout,stderr,args,kind,mode,*,dependencies=None,node_count=12):
    node_prefixes,node_fields,version,control_count=_schema(node_count)
    deps=DEFAULT if dependencies is None else dependencies
    baseline=check(stdout,stderr,args,kind,mode,dependencies=deps,node_count=node_count)
    arena,nodes,ordinary,first,values=split(stderr,deps[3],node_count=node_count)
    inherited=_pipeline(arena,nodes,deps,node_count=node_count).controls(stdout,ordinary,args,kind,mode)
    lines=stderr[:-1].split(b'\n');refusals=[];owner=baseline['persistent']
    def reject(label,changed):
        need(changed!=stderr,'distinct actual whole arena-program mutation')
        try:check(stdout,changed,args,kind,mode,dependencies=deps,node_count=node_count)
        except ValueError:refusals.append(label)
        else:raise ValueError('accepted arena-program mutation '+label)
    def replace(label,index,value):
        changed=list(lines);changed[first+index]=((PREFIX,)+node_prefixes)[index]+json.dumps(value,separators=(',',':')).encode()
        reject(label,b'\n'.join(changed)+b'\n')
    for index,(fields,actual)in enumerate(zip((FIELDS,)+node_fields,values,strict=True)):
        for name in fields:
            label=str(index)+'.'+name
            value=dict(actual);del value[name];replace('missing.'+label,index,value)
            value=dict(actual);value[name]=bool(value[name]);replace('boolean.'+label,index,value)
            value=dict(actual)
            if index==0:
                if name=='poisoned':changed=2
                elif name.endswith('_node'):changed=node_count
                elif name.endswith('_binding'):changed=0
                elif name in ('version','initialized','topology_epoch'):changed=0
                else:changed=value[name]+1
            elif name in ('version','status','failure_code'):changed=0 if name=='version'else 1
            else:
                node=int(name[4:name.index('_')]);field=name[name.index('_')+1:]
                if field=='generation':changed=owner['publications']+1
                elif field in ('completed_serial','build_serial'):changed=owner['serial']+1
                elif field=='active_slot':changed=9
                elif field=='root':changed=1<<47
                elif field=='node_epoch':changed=arena['epoch_invalidations']+2
                elif field=='issued_epoch':changed=nodes[node]['node_epoch']+1
                elif field in ('prepared_serial','prepared_binding'):changed=1
                else:changed=value[name]^1
            value[name]=changed;replace('semantic.'+label,index,value)
        value=dict(actual);value['extra']=0;replace('extra.'+str(index),index,value)
        replace('key_order.'+str(index),index,dict(reversed(list(actual.items()))))
        changed=list(lines);changed[first+index]=lines[first+index][:-1]+b',"version":'+str(version).encode()+b'}'
        reject('duplicate_key.'+str(index),b'\n'.join(changed)+b'\n')
        reject('missing_row.'+str(index),b'\n'.join(lines[:first+index]+lines[first+index+1:])+b'\n')
        reject('duplicate_row.'+str(index),b'\n'.join(lines[:first+index]+[lines[first+index]]+lines[first+index:])+b'\n')
        changed=list(lines);changed[first+index],changed[first+index+1]=changed[first+index+1],changed[first+index]
        reject('row_order.'+str(index),b'\n'.join(changed)+b'\n')
        changed=list(lines);changed[first+index]=lines[first+index].replace(b'{',b'{ ',1)
        reject('whitespace.'+str(index),b'\n'.join(changed)+b'\n')
        changed=list(lines);changed[first+index]+=b' '*4096
        reject('writer_bound.'+str(index),b'\n'.join(changed)+b'\n')
    reject('newline',stderr[:-1])
    need(len(refusals)==len(set(refusals))==control_count,
         'all200 actual fields retain three full-validator mutations plus33 distinct encoding refusals'if node_count==12 else
         'all1795 actual fields retain three full-validator mutations plus265 distinct encoding refusals')
    result=dict(inherited);result['arena_refusals']=refusals
    # Preserve the certificate equation while falsifying its independently
    # reported physical-preparation count. The complete ownership predicate
    # must still reject; extra queries are never a free offset or tolerance.
    byte_prefix=deps[1].PREFIXES[0]
    positions=[i for i,line in enumerate(lines)if line.startswith(byte_prefix)]
    need(len(positions)==1,'one original validated SBC row for coherent arena query accounting')
    index=positions[0];byte=baseline['certificate']['byte_certificate']
    need(json.loads(lines[index][len(byte_prefix):])==byte,
         'whole SBC source row joins the already validated original certificate')
    changed=list(lines);summary=dict(arena);summary['physical_checks']+=1
    certificate=dict(byte);certificate['live_queries']+=3
    changed[first]=PREFIX+json.dumps(summary,separators=(',',':')).encode()
    changed[index]=byte_prefix+json.dumps(certificate,separators=(',',':')).encode()
    supplied=b'\n'.join(changed)+b'\n'
    need(supplied!=stderr,'distinct coherent physical-count and whole original certificate mutation')
    try:check(stdout,supplied,args,kind,mode,dependencies=deps,node_count=node_count)
    except ValueError as error:
        need(str(error)=='real detach claims, dormant primary/peer consumption and retired closed-node conservation',
             'coherent physical query count reaches its exact ownership conservation predicate')
    else:raise ValueError('accepted coherent arena physical-query count')
    result['physical_query_refusals']=['coherent_physical_query_count']
    return result


def configured(original,ro,rx,parse,shared,group,descriptor,*,node_count=12):
    _,_,_,control_count=_schema(node_count)
    deps=(original,ro,rx,parse,shared,group,descriptor)
    return SimpleNamespace(prior=original,CONTROL_COUNT=control_count,
        check=partial(check,dependencies=deps,node_count=node_count),
        controls=partial(controls,dependencies=deps,node_count=node_count))
