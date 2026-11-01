"""Strict ABI3 counter prefix. No completion, timing, or qualification inference."""
import json
from pathlib import Path
import struct

from page_selected import fact, need

MAGIC = 0x31434f554e544750
VERSION, BYTES, PAGE = 3, 824, 4096
LOOP_NAMES = ('chooser_attempts', 'chooser_selected', 'chooser_no_envelope',
    'publications12', 'hits12', 'entries_with12', 'completed_with12',
    'historical_reconstructions', 'actual_entries12')
GROUP_NAMES = ('offers','publications','hits','cold_attempts','cancelled','retirements',
               'permit_claims','entries','completed','unexpected')
MAP_NAMES = ('fresh_calls','acquisitions','reuses','invalidations','handler_id',
             'mutation_epoch','active','valid','poisoned','reserved')
VIEW_NAMES = ('queries','hits','refreshes','updates','invalidations','comparisons',
              'mismatches','unexplained','stack_probes','enabled','differential','poisoned','reserved')
NATIVE_NAMES = ('attempts','admissions','closed','blocked','low_address_refusals')
SCHEMA = dict(version=3, bytes=824, base_bytes=752, page=4096, initial_seals=6, final_seals=23)


def final_counter_prefix(data, initial, pid, seals):
    need(type(initial) is tuple and len(initial)==8 and all(type(n) is int and 0<=n<1<<64 for n in initial)
         and initial[:4]==(MAGIC,VERSION,BYTES,PAGE) and all(n>0 for n in initial[4:]),
         'exact ABI3 initial identity')
    need(type(pid) is int and pid>0 and type(data) is bytes and len(data)==4096 and type(seals) is int and seals==23,
         'whole final sealed counter backing')
    h=struct.unpack_from('<16Q',data)
    need(h[:8]==initial and h[8:12]==(pid,pid,6,23) and 4096<=h[12]<1<<47 and h[12]%4096==0 and
         h[13:]==(1,1,1) and not any(data[824:]) and not any(data[596:600]),
         'exact initialized/protected/closed/ready final counter header and zero tail')
    ingress=struct.unpack_from('<6Q',data,128)
    group=dict(zip(GROUP_NAMES,struct.unpack_from('<10Q',data,176),strict=True))
    misses=list(struct.unpack_from('<18Q',data,256))
    maps=dict(zip(MAP_NAMES,struct.unpack_from('<6Q4I',data,400),strict=True))
    view=dict(zip(VIEW_NAMES,struct.unpack_from('<9Q4I',data,464),strict=True))
    native=dict(zip(NATIVE_NAMES,struct.unpack_from('<5Q',data,552),strict=True))
    loop=dict(zip(LOOP_NAMES,struct.unpack_from('<9Q',data,752),strict=True))
    # A kill can split the protected/mirror stores or any pair of event sites.
    # Neither these nine cells nor the old prefix form a transaction snapshot.
    return dict(version=3,logical_bytes=824,events=ingress[0],signals=list(ingress[1:]),
                group=group,misses=misses,maps=maps,view=view,native=native,loop=loop)


def final_prefix(row, private, binary):
    observed=row['counter_observation'];counter=row['counter_input']
    need(row['reaped'] is True and observed['usable'] is True and row['cleanup_errors']==[] and
         all(d['closed'] is True for d in row['descriptors']), 'closed ABI3 read-only counter prefix')
    need(counter['version']==3 and counter['bytes']==4096 and counter['logical_bytes']==824 and
         counter['initial_seals']==6, 'actual ABI3 input schema')
    capture=row['captures']['counters']
    need(capture['file']==row['name']+'.counters', 'actual child counter capture name')
    path=binary(private/capture['file'])
    need(fact(path)==observed['raw']=={k:capture[k] for k in ('bytes','sha256')}, 'whole retained ABI3 counter bytes')
    initial=(MAGIC,3,824,4096,counter['nonce'],counter['parent'],counter['device'],counter['inode'])
    exact=final_counter_prefix(path.read_bytes(),initial,row['pid'],observed['final_seals'])
    need(all(observed[k]==v for k,v in exact.items()), 'every retained ABI3 cell rejoins its original observation')
    return exact


def prepare_counter_carrier(state, pin):
    """Keep the unchanged make tool and explicitly bind the separate exec tool."""
    root=Path(__file__).resolve().parents[2]
    old=pin(root/'tools/page-entry/carrier.py')
    need(state['carrier_tool']==old, 'unchanged actual carrier creation tool')
    new=pin(root/'tools/page-entry/persistent_loop_counter_carrier.py')
    state['carrier_make_tool']=old
    state['carrier_tool']=new
    support=('evaluation/inprocess/persistent_loop_counter.py',
             'evaluation/inprocess/persistent_loop_counter_process.py',
             'evaluation/inprocess/persistent_loop_counter_protocol.py',
             'tools/page-entry/namespace.py')
    sources={name:fact(pin(root/name)) for name in support}
    return dict(make=dict(path=str(old),**fact(old)),execute=dict(path=str(new),**fact(new)),sources=sources)


def protocol(builder, run, record, pin):
    """Old ABI2 oracle remains mandatory; ABI3 is a separate additive oracle."""
    from startup_counter import protocol as old_protocol
    root=Path(__file__).resolve().parents[2]
    for name in ('evaluation/inprocess/startup_counter.py',
                 'evaluation/inprocess/persistent_group_counter_protocol.py',
                 'evaluation/inprocess/persistent_group_counter_process.py',
                 'tools/page-entry/carrier.py'):
        pin(root/name)
    old_protocol(builder,run,record)
    script=pin(Path(__file__).resolve().with_name('persistent_loop_counter_protocol.py'))
    _,out,err=run('loop-counter-protocol',[builder.tools['python'],'-B',script],profile='finite')
    refusals=['truncated','extended']+['header_'+str(i) for i in range(16)]+[
        'tail','wrong_seals','typed_pid','native_padding','initial_abi2','coordinated_abi2',
        'initial_list','initial_bool','abi2_reader','nonce','parent','cloexec','read_only',
        'descriptor_abi2','old_descriptor','write_seal_with_writer','already_sealed',
        'pwrite_sealed','new_shared_writer','read_only_writer','grow','shrink','add_after_seal']
    prefix=dict(version=3,logical_bytes=824,events=9,signals=[2,3,1,0,0],
        group=dict(zip(GROUP_NAMES,(5,2,1,4,1,1,2,2,1,0),strict=True)),misses=[0,3]+[0]*16,
        maps={k:0 for k in MAP_NAMES},view={k:0 for k in VIEW_NAMES},
        native=dict(attempts=101,admissions=5,closed=4,blocked=89,low_address_refusals=7),
        loop=dict(zip(LOOP_NAMES,(71,5,67,3,2,11,7,89,4),strict=True)))
    expected=dict(scope='loop_counter_protocol_only',version=3,guest_executions=0,
                  parser_prefix=prefix,cell_offset_checks=9,refusal_count=41,refusals=refusals)
    need(len(refusals)==41 and err==b'' and out==(json.dumps(expected,sort_keys=True)+'\n').encode(),
         'whole separate ABI3 parser, all nine literal offsets and real sealed-memfd protocol')
    record['loop_counter_protocol']=dict(expected,script=dict(path=str(script),**fact(script)))
