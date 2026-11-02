"""Strict ABI5 per-cell observations; a killed target remains failed."""
from pathlib import Path
import json
import struct
from page_selected import fact, need
from persistent_loop_counter import (MAGIC, LOOP_NAMES, GROUP_NAMES, MAP_NAMES,
                                     VIEW_NAMES, NATIVE_NAMES)
from persistent_loop_effects_counter import EFFECTS_NAMES

VERSION, BYTES, PAGE = 5, 1696, 4096
KINDS = ('no_resident_head','root','internal_head')
GATES = ('installed','stored','registry','bank','source_key','lifetime',
         'registration_epoch','rseq_address','rseq_length','rseq_signature')
OUTCOMES = ('warm_plan','cold_refused','cold_built','warm_bound','empty_publication',
            'replacement_publication','cancelled','completed')
SCHEMA = dict(version=5,bytes=1696,base_bytes=896,page=4096,initial_seals=6,final_seals=23)


def final_counter_prefix(data, initial, pid, seals):
    need(type(initial) is tuple and len(initial)==8 and all(type(n) is int and 0<=n<1<<64 for n in initial)
         and initial[:4]==(MAGIC,VERSION,BYTES,PAGE) and all(n>0 for n in initial[4:]),
         'exact ABI5 initial identity')
    need(type(pid) is int and pid>0 and type(data) is bytes and len(data)==4096 and type(seals) is int and seals==23,
         'whole final sealed counter backing')
    h=struct.unpack_from('<16Q',data)
    need(h[:8]==initial and h[8:12]==(pid,pid,6,23) and 4096<=h[12]<1<<47 and h[12]%4096==0 and
         h[13:]==(1,1,1) and not any(data[BYTES:]) and not any(data[596:600]),
         'exact initialized/protected/closed/ready final counter header and zero tail')
    return dict(version=5,logical_bytes=1696,**_prefix_cells(data))


def _prefix_cells(data):
    ingress=struct.unpack_from('<6Q',data,128)
    group=dict(zip(GROUP_NAMES,struct.unpack_from('<10Q',data,176),strict=True))
    misses=list(struct.unpack_from('<18Q',data,256))
    maps=dict(zip(MAP_NAMES,struct.unpack_from('<6Q4I',data,400),strict=True))
    view=dict(zip(VIEW_NAMES,struct.unpack_from('<9Q4I',data,464),strict=True))
    native=dict(zip(NATIVE_NAMES,struct.unpack_from('<5Q',data,552),strict=True))
    loop=dict(zip(LOOP_NAMES,struct.unpack_from('<9Q',data,752),strict=True))
    effects=dict(zip(EFFECTS_NAMES,struct.unpack_from('<9Q',data,824),strict=True))
    words=struct.unpack_from('<100Q',data,896)
    need(words[0]<=9 and words[3] in (0,1) and words[6:8]==(0,0), 'typed ABI5 reason prefix and reserved cells')
    reasons=dict(zip(('error','attempts','finished','in_flight','root_hits','subentry_hits'),words[:6],strict=True))
    reasons['selection']={kind:[list(words[8+6*k+2*n:8+6*k+2*n+2]) for n in range(3)]
                          for k,kind in enumerate(KINDS)}
    reasons['seen']=dict(zip(GATES,words[26:36],strict=True))
    reasons['passed']=dict(zip(GATES,words[36:46],strict=True))
    reasons['first_failure']={kind:dict(zip(GATES,words[46+10*k:56+10*k],strict=True))
                              for k,kind in enumerate(KINDS)}
    reasons['outcomes']={kind:dict(zip(OUTCOMES,words[76+8*k:84+8*k],strict=True))
                         for k,kind in enumerate(KINDS)}
    # A kill can split any two stores, including observed/production counters.
    # Do not manufacture conservation, a final completion, or a causal timing.
    return dict(events=ingress[0],signals=list(ingress[1:]),
                group=group,misses=misses,maps=maps,view=view,native=native,loop=loop,effects=effects,
                reasons=reasons,reason_prefix_usable=words[0]==0)


def final_prefix(row, private, binary):
    observed=row['counter_observation'];counter=row['counter_input']
    need(row['reaped'] is True and observed['usable'] is True and row['cleanup_errors']==[] and
         all(d['closed'] is True for d in row['descriptors']), 'closed ABI5 read-only counter prefix')
    need(counter['version']==5 and counter['bytes']==4096 and counter['logical_bytes']==1696 and
         counter['initial_seals']==6, 'actual ABI5 input schema')
    capture=row['captures']['counters']
    need(capture['file']==row['name']+'.counters', 'actual child counter capture name')
    path=binary(private/capture['file'])
    need(fact(path)==observed['raw']=={k:capture[k] for k in ('bytes','sha256')}, 'whole retained ABI5 counter bytes')
    initial=(MAGIC,5,1696,4096,counter['nonce'],counter['parent'],counter['device'],counter['inode'])
    exact=final_counter_prefix(path.read_bytes(),initial,row['pid'],observed['final_seals'])
    need(all(observed[k]==v for k,v in exact.items()), 'every retained ABI5 cell rejoins its original observation')
    return exact



def completed_prefix(prefix, terminal):
    """Cross-cell joins only after the unchanged complete application reader."""
    need(type(prefix) is dict and prefix.get('version')==5 and prefix.get('logical_bytes')==1696,
         'distinct ABI5 completion input, never an ABI4 schema substitution')
    return _completed_reason_cells(prefix,terminal)


def _completed_reason_cells(prefix,terminal):
    d=terminal['LI2_PERSISTENT_UNREGISTERED'];l=terminal['LI2_LINKED_EPOCH']
    need(all(d[k]==prefix['group'][k] for k in GROUP_NAMES) and d['misses']==prefix['misses'] and
         l['events']==prefix['events'] and l['signals']==prefix['signals'] and
         all(terminal['LI2_MAPS_VIEW'][k]==v for k,v in prefix['view'].items()) and
         all(terminal['LI2_NATIVE'][k]==v for k,v in prefix['native'].items()) and
         all(terminal['LI2_LOOP_RUNTIME'][k]==v for k,v in prefix['loop'].items()) and
         all(terminal['LI2_LOOP_EFFECTS'][k]==v for k,v in prefix['effects'].items()),
         'all terminal-backed ABI5 prefix cells equal their actual completed rows')
    r=prefix['reasons'];rows=r['outcomes'];total=lambda name:sum(rows[k][name] for k in KINDS)
    need(r['error']==r['in_flight']==0 and prefix['reason_prefix_usable'] is True and
         r['attempts']==r['finished']==d['offers'] and r['root_hits']==d['hits'] and
         r['subentry_hits']==terminal['LI2_PERSISTENT_SUBENTRY']['hits'],
         'complete observer stages and actual root/subentry hit identity')
    for kind in KINDS:
        row=rows[kind]
        need(sum(sum(bank) for bank in r['selection'][kind])==
             row['warm_plan']+row['cold_refused']+row['cold_built'] and
             row['warm_plan']==row['warm_bound'] and row['cold_refused']==row['cancelled'] and
             row['cold_built']==row['empty_publication']+row['replacement_publication'] and
             row['completed']==row['warm_bound']+row['cold_built'],
             'completed reason selection/plan/bind/finish partition '+kind)
    need(total('warm_bound')==r['root_hits']+r['subentry_hits'] and
         rows['no_resident_head']['warm_plan']==0 and rows['root']['warm_bound']==r['root_hits'] and
         rows['internal_head']['warm_bound']==r['subentry_hits'] and
         total('cold_built')==d['publications'] and total('replacement_publication')==d['retirements'] and
         total('cancelled')==d['cancelled'] and total('completed')==d['completed'] and
         total('cold_refused')+total('cold_built')==d['cold_attempts'],
         'completed reason outcomes equal the original owner events')
    for i,name in enumerate(GATES):
        need(r['seen'][name]==(r['attempts'] if i==0 else r['passed'][GATES[i-1]]) and
             r['seen'][name]==r['passed'][name]+sum(r['first_failure'][k][name] for k in KINDS),
             'actual short-circuit partition '+name)
    need(r['passed'][GATES[-1]]==total('warm_plan'), 'all ten true terms precede each actual warm plan')


def _completed_controls(prefix, terminal, check):
    """Each observed reason cell changes independently; no synthetic successful run."""
    check(prefix,terminal);paths=[]
    def leaves(value,path=()):
        if type(value) is dict:
            for k,v in value.items():leaves(v,path+(k,))
        elif type(value) is list:
            for k,v in enumerate(value):leaves(v,path+(k,))
        else:
            need(type(value) is int, 'actual unsigned reason cell');paths.append(path)
    leaves(prefix['reasons']);need(len(paths)==98, 'all nonreserved reason cells')
    refused=[]
    for path in paths:
        changed=json.loads(json.dumps(prefix));target=changed['reasons']
        for part in path[:-1]:target=target[part]
        target[path[-1]]^=1
        need(changed!=prefix, 'nonidentity reason completion stimulus')
        try:check(changed,terminal)
        except ValueError:refused.append('.'.join(map(str,path)))
        else:raise ValueError('accepted reason completion mutation '+str(path))
    need(len(refused)==len(set(refused))==98, 'all98 actual reason completion mutations rejected')
    return dict(refusals=refused,guest_executions=0)

def completed_controls(prefix,terminal):
    return _completed_controls(prefix,terminal,completed_prefix)

def prepare_counter_carrier(state, pin):
    root=Path(__file__).resolve().parents[2]
    old=pin(root/'tools/page-entry/carrier.py')
    need(state['carrier_tool']==old, 'unchanged actual carrier creation tool')
    new=pin(root/'tools/page-entry/loop_ro_reason_carrier.py')
    state['carrier_make_tool']=old;state['carrier_tool']=new
    support=('evaluation/inprocess/loop_ro_reason_counter.py',
             'evaluation/inprocess/loop_ro_reason_process.py',
             'evaluation/inprocess/persistent_loop_counter.py',
             'evaluation/inprocess/persistent_loop_effects_counter.py','tools/page-entry/namespace.py')
    return dict(make=dict(path=str(old),**fact(old)),execute=dict(path=str(new),**fact(new)),
                sources={name:fact(pin(root/name)) for name in support})


def protocol(builder, run, record, pin):
    """Retain the original ABI2/3/4 protocols before the distinct ABI5 checks."""
    from persistent_loop_effects_counter import protocol as old_protocol
    old_protocol(builder,run,record,pin)
    script=pin(Path(__file__).resolve().with_name('loop_ro_reason_protocol.py'))
    _,out,err=run('loop-ro-reason-protocol',[builder.tools['python'],'-B',script],profile='finite')
    refusals=['truncated','extended']+['header_'+str(i) for i in range(16)]+[
        'tail','wrong_seals','typed_pid','native_padding','initial_abi2','coordinated_abi2',
        'initial_list','initial_bool','abi2_reader','initial_abi3','coordinated_abi3','abi3_reader',
        'initial_abi4','coordinated_abi4','abi4_reader','error_range','in_flight_range','reserved0','reserved1',
        'nonce','parent','cloexec','read_only','descriptor_abi2','old_descriptor','descriptor_abi3',
        'abi3_descriptor','descriptor_abi4','abi4_descriptor','write_seal_with_writer','already_sealed',
        'pwrite_sealed','new_shared_writer','read_only_writer','grow','shrink','add_after_seal']
    reasons=dict(error=0,attempts=0,finished=0,in_flight=0,root_hits=0,subentry_hits=0,
        selection={kind:[[0,0] for _ in range(3)] for kind in KINDS},
        seen={name:0 for name in GATES},passed={name:0 for name in GATES},
        first_failure={kind:{name:0 for name in GATES} for kind in KINDS},
        outcomes={kind:{name:0 for name in OUTCOMES} for kind in KINDS})
    prefix=dict(version=5,logical_bytes=1696,events=9,signals=[2,3,1,0,0],
        group=dict(zip(GROUP_NAMES,(5,2,1,4,1,1,2,2,1,0),strict=True)),misses=[0,3]+[0]*16,
        maps={k:0 for k in MAP_NAMES},view={k:0 for k in VIEW_NAMES},
        native=dict(attempts=101,admissions=5,closed=4,blocked=89,low_address_refusals=7),
        loop=dict(zip(LOOP_NAMES,(71,5,67,3,2,11,7,89,4),strict=True)),
        effects=dict(zip(EFFECTS_NAMES,(73,7,61,5,3,13,11,97,6),strict=True)),
        reasons=reasons,reason_prefix_usable=True)
    expected=dict(scope='loop_ro_reason_protocol_only',version=5,guest_executions=0,
        parser_prefix=prefix,cell_offset_checks=116,refusal_count=55,refusals=refusals)
    need(len(refusals)==55 and err==b'' and out==(json.dumps(expected,sort_keys=True)+'\n').encode(),
         'whole ABI5 kernel/parser population with all prior protocols preserved')
    record['loop_ro_reason_protocol']=dict(expected,script=dict(path=str(script),**fact(script)))
