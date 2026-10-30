#!/usr/bin/env python3
"""Fixed supplied perf-ABI parser controls only; no workload or kernel execution."""
import argparse
import hashlib
import importlib.util
import io
import csv
import json
import struct
import tempfile
from pathlib import Path


def record(kind,misc,body):
    return struct.pack('<IHH',kind,misc,len(body)+8)+body


def suffix(stamp,event=22,chains=False):
    return (struct.pack('<IIQIIQ',99,99,stamp,3,0,event)if chains else
            struct.pack('<IIQQII',99,99,stamp,event,3,0))


def sample(stamp,mode,words,*,event=11,declared=None,tail=b'',layout=True,pid=99,tid=99):
    ip=0xffffffff81000100 if mode==1 else 0x401000
    body=(struct.pack('<QQIIQIIQ',event,ip,pid,tid,stamp,3,0,10000000)if layout else
          struct.pack('<QIIQQIIQ',ip,pid,tid,stamp,event,3,0,10000000))
    if words is not None:
        body+=struct.pack('<Q',len(words)if declared is None else declared)
        body+=b''.join(struct.pack('<Q',value)for value in words)
    return record(9,mode,body+tail)


def perf_file(samples,chains,*,side_event=22):
    """Independent fixed ABI fixture: two events, two IDs, exec/sample/exit."""
    attrs=[]
    for index in range(2):
        a=bytearray(160)
        mask=(0x101a7 if index==0 else 0x10187)if chains else 0x1c7
        struct.pack_into('<IIQQQ',a,0,1,144,0 if index==0 else 9,99,mask)
        struct.pack_into('<Q',a,32,20)
        flags=(0x2040403 if index==0 else 0x463943763)|(0x400000 if chains and index==0 else 0)
        struct.pack_into('<Q',a,40,flags);struct.pack_into('<i',a,92,1)
        if chains and index==0:struct.pack_into('<H',a,108,64)
        struct.pack_into('<QQ',a,144,104+index*8,8);attrs.append(bytes(a))
    index=record(69,0,struct.pack('<Q',2)+struct.pack('<4Q',11,0,3,99)+struct.pack('<4Q',22,0,3,99))
    # New sample_id_all is TID/TIME/CPU/IDENTIFIER; scalar is TID/TIME/ID/CPU.
    # Neither sideband suffix includes a CALLCHAIN payload.
    comm=record(3,1<<13,struct.pack('<II',99,99)+b'fixture\0'+suffix(100,event=side_event,chains=chains))
    end=record(4,0,struct.pack('<IIIIQ',99,1,99,1,200)+suffix(200,event=side_event,chains=chains))
    events=index+record(82,0,b'')+comm+b''.join(samples)+end
    header=bytearray(104);header[:8]=b'PERFILE2'
    struct.pack_into('<6Q',header,8,104,160,120,320,440,len(events))
    return bytes(header)+struct.pack('<QQ',11,22)+b''.join(attrs)+events


def altered(data,offset,fmt,value):
    b=bytearray(data);struct.pack_into(fmt,b,offset,value);return bytes(b)


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--reader',required=True);ap.add_argument('--sha256',required=True)
    args=ap.parse_args();path=Path(args.reader).resolve();blob=path.read_bytes()
    assert hashlib.sha256(blob).hexdigest()==args.sha256,'exact final reader bytes'
    spec=importlib.util.spec_from_file_location('supplied_kernel_reader',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    # Only ELF acquisition is supplied. Every perf byte traverses the real parser;
    # these fixtures make no bridge mapping/symbol or runtime identity claim.
    old_elf=module.elf
    module.elf=lambda _:dict(path='/supplied/bridge',bytes=0,sha256='0'*64,build_ids=[],
        device=[0,0],mmap_device=[0,0],inode=0,loads=[],symbols=[],provenance={})
    positives=[];refusals=[];marker=(1<<64)-128;pc=0xffffffff81000100
    basic=perf_file([sample(120,1,[marker,pc,pc+0x100]),sample(130,2,[])],True)
    scalar=perf_file([sample(120,1,None,layout=False),sample(130,2,None,layout=False)],False)
    def check(name,data,mode,expected=None):
        with tempfile.TemporaryDirectory(prefix='li2-kernel-parser-')as temporary:
            d=Path(temporary);(d/'perf.data').write_bytes(data)
            try:
                result=module.summarize(d/'perf.data',Path('/supplied/bridge'),99,3,d,90,210,
                                        **({'kernel_callchains':True}if mode else{}))
            except ValueError as exc:
                assert expected is None,(name,str(exc));refusals.append(name);return
            assert expected is not None,(name,'unexpected acceptance')
            rows=json.loads((d/'samples.json').read_bytes())
            assert result['samples']==len(rows)==expected['samples'] and result['lost_samples']==0
            assert result['throttle_records']==0 and result['full_exec_exit_envelope'] is True
            assert result['sampled_period_total']==10000000*len(rows)
            if mode:
                chains=[r['callchain']for r in rows if r['cpumode']==1]
                assert [c['depth']for c in chains]==expected['depths']
                assert [c['state']for c in chains]==expected['states']
                assert sum(c['depth_limit_hit']for c in chains)==expected['limit']
                assert all(c['unwind_complete']is False for c in chains)
                assert result['kernel_callchains']['kernel_samples']==len(chains)
            else:
                assert 'kernel_callchains'not in result and all('callchain'not in r for r in rows)
            positives.append(name)
    try:
        check('original_default_scalar',scalar,False,dict(samples=2))
        check('kernel_and_empty_user',basic,True,dict(samples=2,depths=[2],states=['frames'],limit=0))
        check('empty_kernel_retained',perf_file([sample(120,1,[])],True),True,
              dict(samples=1,depths=[0],states=['empty'],limit=0))
        check('marker_only_kernel_retained',perf_file([sample(120,1,[marker])],True),True,
              dict(samples=1,depths=[0],states=['marker_only'],limit=0))
        check('64_pcs_plus_context_retained_as_limited',perf_file([sample(120,1,[marker]+[pc+16*i for i in range(64)])],True),True,
              dict(samples=1,depths=[64],states=['frames'],limit=1))
        check('default_rejects_callchain',basic,False)
        check('callchain_rejects_scalar',scalar,True)
        for name,offset,fmt,value in [
            ('cpu_missing_callchain',120+24,'<Q',0x10187),
            ('dummy_has_callchain',280+24,'<Q',0x101a7),
            ('max_stack_63',120+108,'<H',63),('max_stack_65',120+108,'<H',65),
            ('user_callchain_not_excluded',120+40,'<Q',0x2040403),
            ('kernel_callchain_excluded',120+40,'<Q',0x2640403),
            ('additional_RAW_payload',120+24,'<Q',0x105a7),
            ('reserved_attr_byte',120+110,'<B',1)]:
            check(name,altered(basic,offset,fmt,value),True)
        for name,mode,words,kw in [
            ('65_pcs_exceed_bound',1,[marker]+[pc]*65,{}),
            ('count_exceeds_payload',1,[marker,pc],dict(declared=65)),
            ('missing_kernel_marker',1,[pc],{}),
            ('unknown_context',1,[(1<<64)-4095,pc],{}),
            ('repeated_kernel_marker',1,[marker,pc,marker],{}),
            ('user_context',1,[(1<<64)-512,pc],{}),
            ('user_sample_has_kernel_chain',2,[marker,pc],{}),
            ('zero_unwind_pc',1,[marker,0],{}),
            ('trailing_payload',1,[marker,pc],dict(tail=b'\0'*8)),
            ('dummy_id_cannot_sample',1,[marker,pc],dict(event=22)),
            ('unknown_id_cannot_sample',1,[marker,pc],dict(event=33)),
            ('missing_count_word',1,None,{})]:
            check(name,perf_file([sample(120,mode,words,**kw)],True),True)
        check('runtime_sideband_unknown_identifier',perf_file([sample(120,1,[marker,pc])],True,side_event=33),True)
        check('runtime_sideband_cpu_identifier',perf_file([sample(120,1,[marker,pc])],True,side_event=11),True)
        check('old_ID_payload_under_new_attributes',perf_file([sample(120,1,[marker,pc],layout=False)],True),True)
        for name,mode,kw in [('wrong_sample_pid',1,dict(pid=100)),('wrong_sample_tid',1,dict(tid=100)),
                             ('empty_unknown_cpumode',0,{}),('empty_hypervisor_cpumode',3,{})]:
            check(name,perf_file([sample(120,mode,[],**kw)],True),True)
    finally:module.elf=old_elf
    assert len(positives)==5 and len(refusals)==29
    class SuppliedResolver:
        identity={'supplied':True}
        def lookup(self,address):
            names={pc:'leaf',pc+0x100:'caller',pc+0x200:'root',pc+0x500:'perf_event_mmap',
                   pc+0x600:'show_map_vma',pc+0x700:'seq_read_iter'}
            return (dict(reason='core_text_symbol_interval',symbols=[names[address]])
                    if address in names else dict(reason='outside_core_text'))
    def row(ip,pcs,period):
        return dict(pid=99,cpumode=1,in_target_exec_window=True,ip=ip,period=period,
            callchain=dict(pcs=pcs,depth=len(pcs),depth_limit_hit=False,
                           state='frames'if pcs else'empty',unwind_complete=False))
    supplied=[row(pc,[pc,pc+0x100,pc+0x200],10),
              row(pc+0x300,[pc+0x300,pc+0x100,pc+0x200],20),
              row(pc,[],30),row(pc,[pc+0x400,pc+0x100,pc+0x200],40)]
    # Unrelated/user/pre-exec rows must not enter the kernel population.
    supplied += [dict(pid=100,cpumode=1,in_target_exec_window=True),
                 dict(pid=99,cpumode=2,in_target_exec_window=True),
                 dict(pid=99,cpumode=1,in_target_exec_window=False)]
    graph=module.callchain_counts(supplied,SuppliedResolver(),99)
    assert (graph['kernel_samples'],graph['kernel_sampled_period_total'])==(4,100)
    assert len(graph['disjoint'])==4 and sum(x['samples']for x in graph['disjoint'])==4
    assert sum(x['sampled_period_total']for x in graph['disjoint'])==100
    assert (graph['unknown_frame_samples'],graph['unknown_frame_occurrences'],graph['nonempty_head_mismatch_samples'])==(2,2,1)
    assert len(graph['inclusive'])==4 and sum(x['samples']for x in graph['inclusive'])==9
    shared=[x for x in graph['inclusive']if x['path']==['core_interval:caller','core_interval:root']]
    assert len(shared)==1 and (shared[0]['samples'],shared[0]['sampled_period_total'])==(3,70)
    output=io.StringIO();projected=module.callchain_public(graph,csv.writer(output))
    assert projected['disjoint']['additive']is True and projected['inclusive']['additive']is False
    assert projected['disjoint']['remaining']==dict(groups=0,samples=0,sampled_period_total=0)
    named=module.callchain_counts([row(pc,[pc,pc+0x600,pc+0x500],10),
        row(pc,[pc,pc+0x600],20),row(pc,[pc,pc+0x700],30)],SuppliedResolver(),99)
    assert {x['name']:(x['samples'],x['sampled_period_total'])for x in named['categories']}=={
        'perf_observer_named_path':(1,10),'proc_maps_named_path':(1,20),'other_known_kernel_path':(1,30)}
    assert named['observed_anchor_aliases']==dict(perf_observer_named_path=['perf_event_mmap'],proc_maps_named_path=['show_map_vma'])
    graph_refusals=[]
    for name,field,value in [('nonpositive_period','period',0),('wrong_depth','depth',2),
                             ('fabricated_limit_hit','depth_limit_hit',True),('fabricated_complete','unwind_complete',True)]:
        changed=json.loads(json.dumps(supplied[:1]))
        if field=='period':changed[0][field]=value
        else:changed[0]['callchain'][field]=value
        try:module.callchain_counts(changed,SuppliedResolver(),99)
        except ValueError:graph_refusals.append(name)
        else:raise AssertionError(name+' accepted')
    assert len(graph_refusals)==4
    print(json.dumps(dict(scope='supplied parser controls only; no workload, mapping or timing credit',
        reader_sha256=args.sha256,positive_count=len(positives),refusal_count=len(refusals),
        positives=positives,refusals=refusals,graph_positive_count=2,
        graph_refusal_count=len(graph_refusals),graph_refusals=graph_refusals),sort_keys=True))


if __name__=='__main__':main()
