"""Strict ABI4 per-cell prefix; completion still requires actual terminal joins."""
import json
from pathlib import Path
import struct

from page_selected import fact, need
from persistent_loop_counter import (MAGIC, LOOP_NAMES, GROUP_NAMES, MAP_NAMES,
                                     VIEW_NAMES, NATIVE_NAMES)

VERSION, BYTES, PAGE = 4, 896, 4096
EFFECTS_NAMES = ('chooser_attempts', 'chooser_selected', 'chooser_no_envelope',
    'publications13', 'hits13', 'entries_with13', 'completed_with13',
    'historical_reconstructions', 'actual_entries13')
SCHEMA = dict(version=4, bytes=896, base_bytes=824, page=4096, initial_seals=6, final_seals=23)


def final_counter_prefix(data, initial, pid, seals):
    need(type(initial) is tuple and len(initial)==8 and all(type(n) is int and 0<=n<1<<64 for n in initial)
         and initial[:4]==(MAGIC,VERSION,BYTES,PAGE) and all(n>0 for n in initial[4:]),
         'exact ABI4 initial identity')
    need(type(pid) is int and pid>0 and type(data) is bytes and len(data)==4096 and type(seals) is int and seals==23,
         'whole final sealed counter backing')
    h=struct.unpack_from('<16Q',data)
    need(h[:8]==initial and h[8:12]==(pid,pid,6,23) and 4096<=h[12]<1<<47 and h[12]%4096==0 and
         h[13:]==(1,1,1) and not any(data[896:]) and not any(data[596:600]),
         'exact initialized/protected/closed/ready final counter header and zero tail')
    ingress=struct.unpack_from('<6Q',data,128)
    group=dict(zip(GROUP_NAMES,struct.unpack_from('<10Q',data,176),strict=True))
    misses=list(struct.unpack_from('<18Q',data,256))
    maps=dict(zip(MAP_NAMES,struct.unpack_from('<6Q4I',data,400),strict=True))
    view=dict(zip(VIEW_NAMES,struct.unpack_from('<9Q4I',data,464),strict=True))
    native=dict(zip(NATIVE_NAMES,struct.unpack_from('<5Q',data,552),strict=True))
    loop=dict(zip(LOOP_NAMES,struct.unpack_from('<9Q',data,752),strict=True))
    effects=dict(zip(EFFECTS_NAMES,struct.unpack_from('<9Q',data,824),strict=True))
    # A kill may split any protected/mirror pair or two separate event sites.
    # Neither the old prefix nor these appended cells is a transaction snapshot.
    return dict(version=4,logical_bytes=896,events=ingress[0],signals=list(ingress[1:]),
                group=group,misses=misses,maps=maps,view=view,native=native,loop=loop,effects=effects)


def final_prefix(row, private, binary):
    observed=row['counter_observation'];counter=row['counter_input']
    need(row['reaped'] is True and observed['usable'] is True and row['cleanup_errors']==[] and
         all(d['closed'] is True for d in row['descriptors']), 'closed ABI4 read-only counter prefix')
    need(counter['version']==4 and counter['bytes']==4096 and counter['logical_bytes']==896 and
         counter['initial_seals']==6, 'actual ABI4 input schema')
    capture=row['captures']['counters']
    need(capture['file']==row['name']+'.counters', 'actual child counter capture name')
    path=binary(private/capture['file'])
    need(fact(path)==observed['raw']=={k:capture[k] for k in ('bytes','sha256')}, 'whole retained ABI4 counter bytes')
    initial=(MAGIC,4,896,4096,counter['nonce'],counter['parent'],counter['device'],counter['inode'])
    exact=final_counter_prefix(path.read_bytes(),initial,row['pid'],observed['final_seals'])
    need(all(observed[k]==v for k,v in exact.items()), 'every retained ABI4 cell rejoins its original observation')
    return exact


def prepare_counter_carrier(state, pin):
    root=Path(__file__).resolve().parents[2]
    old=pin(root/'tools/page-entry/carrier.py')
    need(state['carrier_tool']==old, 'unchanged actual carrier creation tool')
    new=pin(root/'tools/page-entry/persistent_loop_effects_counter_carrier.py')
    state['carrier_make_tool']=old
    state['carrier_tool']=new
    support=('evaluation/inprocess/persistent_loop_effects_counter.py',
             'evaluation/inprocess/persistent_loop_effects_counter_process.py',
             'evaluation/inprocess/persistent_loop_effects_counter_protocol.py',
             'evaluation/inprocess/persistent_loop_counter.py',
             'tools/page-entry/namespace.py')
    return dict(make=dict(path=str(old),**fact(old)),execute=dict(path=str(new),**fact(new)),
                sources={name:fact(pin(root/name)) for name in support})


def protocol(builder, run, record, pin):
    """Both old ABI2/3 oracles remain mandatory before the new ABI4 population."""
    from persistent_loop_counter import protocol as old_protocol
    root=Path(__file__).resolve().parents[2]
    for name in ('evaluation/inprocess/persistent_loop_counter.py',
                 'evaluation/inprocess/persistent_loop_counter_protocol.py',
                 'evaluation/inprocess/persistent_loop_counter_process.py',
                 'tools/page-entry/persistent_loop_counter_carrier.py'):
        pin(root/name)
    old_protocol(builder,run,record,pin)
    script=pin(Path(__file__).resolve().with_name('persistent_loop_effects_counter_protocol.py'))
    _,out,err=run('loop-effects-counter-protocol',[builder.tools['python'],'-B',script],profile='finite')
    refusals=['truncated','extended']+['header_'+str(i) for i in range(16)]+[
        'tail','wrong_seals','typed_pid','native_padding','initial_abi2','coordinated_abi2',
        'initial_list','initial_bool','abi2_reader','initial_abi3','coordinated_abi3','abi3_reader',
        'nonce','parent','cloexec','read_only','descriptor_abi2','old_descriptor','descriptor_abi3',
        'abi3_descriptor','write_seal_with_writer','already_sealed','pwrite_sealed','new_shared_writer',
        'read_only_writer','grow','shrink','add_after_seal']
    prefix=dict(version=4,logical_bytes=896,events=9,signals=[2,3,1,0,0],
        group=dict(zip(GROUP_NAMES,(5,2,1,4,1,1,2,2,1,0),strict=True)),misses=[0,3]+[0]*16,
        maps={k:0 for k in MAP_NAMES},view={k:0 for k in VIEW_NAMES},
        native=dict(attempts=101,admissions=5,closed=4,blocked=89,low_address_refusals=7),
        loop=dict(zip(LOOP_NAMES,(71,5,67,3,2,11,7,89,4),strict=True)),
        effects=dict(zip(EFFECTS_NAMES,(73,7,61,5,3,13,11,97,6),strict=True)))
    expected=dict(scope='loop_effects_counter_protocol_only',version=4,guest_executions=0,
                  parser_prefix=prefix,cell_offset_checks=18,refusal_count=46,refusals=refusals)
    need(len(refusals)==46 and err==b'' and out==(json.dumps(expected,sort_keys=True)+'\n').encode(),
         'whole separate ABI4 parser, all eighteen literal offsets and real sealed-memfd protocol')
    record['loop_effects_counter_protocol']=dict(expected,script=dict(path=str(script),**fact(script)))
