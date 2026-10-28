"""Strict finite C-provider record join to the unchanged Rust reference boundary.

No failed/unexecuted prefix is a completed trajectory. The final ordinary
instruction is observed as a real NX event and remains unexecuted.
"""
import struct
U64=(1<<64)-1
MAGIC=0x314652434232494c
KINDS=range(1,8)
def need(ok,why):
    if not ok:raise ValueError(why)
def q(b):
    need(len(b)%8==0,'whole word record field');return struct.unpack('<'+'Q'*(len(b)//8),b)
def field(b,t,name):
    f=t['fields'][name];need(0<=f['offset']<=len(b)and 0<=f['bytes']<=len(b)-f['offset'],'complete actual DWARF field')
    return b[f['offset']:f['offset']+f['bytes']]
def check(raw,layout,ref,boundary):
    need(type(raw)is bytes and type(layout)is dict and set(layout)=={'b2_record','b2_row','b2_snapshot','layout'},'exact actual ELF layout and record')
    rt,st,bt=(layout[x]for x in('b2_record','b2_row','b2_snapshot'))
    need(len(raw)==rt['bytes']<2<<20 and bt['bytes']==boundary.SNAPSHOT_BYTES==96512,'complete bounded fixed record')
    need(set(rt['fields'])=={'h','bases','rows','final'}and set(st['fields'])=={'h','progress','entry','before','after'}and
         set(bt['fields'])=={'h','si','uc','fp','source','data'},'exact DWARF member sets')
    for t in(rt,st,bt):
        at=0
        for f in sorted(t['fields'].values(),key=lambda x:x['offset']):
            need(f['offset']==at and type(f['bytes'])is int and f['bytes']>0,'complete nonoverlapping storage fields');at+=f['bytes']
        need(at==t['bytes'],'no unparsed struct storage')
    h=q(field(raw,rt,'h'));n=len(ref['rows']);need(2<=n<=4,'complete finite case')
    need(len(h)==32 and h[:17]==(MAGIC,1,len(raw),n,0,0,0,n,n,n,0,6*n+2,0,0,0,1,1)and
         h[17]==sum(r['kind']<=4 for r in ref['rows'])and h[18]==sum(r['kind']>=5 for r in ref['rows'])and
         h[19]==sum(r['kind']==7 for r in ref['rows'])and h[20]==0 and h[21]>0 and h[22]==512<<10 and not any(h[23:]),
         'complete selected sequence and genuine final NX, no fabricated raw syscall or program exit')
    rows=field(raw,rt,'rows');need(len(rows)==4*st['bytes'],'all four row slots retained')
    actual=[];snapshots=[];clocks=0;cpuids=0
    for i,reference in enumerate(ref['rows']):
        b=rows[i*st['bytes']:(i+1)*st['bytes']];v=q(field(b,st,'h'));p=q(field(b,st,'progress'))
        kind=reference['kind'];before=reference['before']['registers'];after=reference['after']['registers'];values=reference['values']
        need(kind in KINDS and len(v)==16 and len(p)==64 and
             v==(2,i,kind,before['rip'],1,1,1,i+1,i+1,i+1,0 if kind==7 else 301,0,0,0,0,0),
             'actual production entered/returned/committed and independent script progression')
        expected=[0]*64
        if kind==1:
            expected[1:3]=[before['rax']&0xffffffff,before['rcx']&0xffffffff]
            # Hardware sample remains observed evidence; it is not configured
            # expected data. Exact production completion/rearm stays required.
            expected[3:7]=p[3:7];need(all(x<=0xffffffff for x in p[3:7]),'raw CPUID scalar widths')
            cpuids+=1;expected[7:11]=values
            expected[14:24]=[1,1,3,cpuids,cpuids,cpuids,before['rip'],after['rip'],before['rax']&0xffffffff,before['rcx']&0xffffffff]
            expected[24:28]=p[3:7];expected[28:32]=values;expected[32:36]=p[3:7]
        elif kind in(2,3,4):
            dst=reference['destination'];expected[2:10]=[1,kind,reference['width'],dst,before['rip'],after['rip'],before['eflags'],before[boundary.GPRS[dst]]]
            expected[10:15]=[kind,reference['width'],reference['carry'],0,values[0]]
        elif kind in(5,6):
            clocks+=1;expected[1:10]=[1,kind,before['rip'],after['rip'],before['eflags'],clocks,values[0],values[1],0]
        else:
            need(before['rax']==39 and values==[173,0,0,0],'exact separate fixture PID173 policy, not production tagged PID')
            expected[1:10]=[1,1,0,0,0,1,1,0,173]
            expected[10:27]=[1,0,before['rip'],after['rip'],before['eflags'],39,
                *[before[name]for name in('rdi','rsi','rdx','r10','r8','r9')],before['rcx'],before['r11'],1,0,173]
        need(p==tuple(expected),'full typed actual callback input/result and effect prefix')
        row={name:field(b,st,name)for name in('entry','before','after')}
        need(row['entry']==row['before'],'complete entry/source/data/frame preservation through actual fetch validation')
        actual.append(dict(index=i,entered=v[4],returned=v[5],committed=v[6],**row));snapshots.extend(row.values())
    need(not any(rows[n*st['bytes']:]),'every unused row byte remains zero')
    result=boundary.compare(ref,actual,layout['layout'])
    final=field(raw,rt,'final');result.update(boundary.final_entry(ref,final,layout['layout']));snapshots.append(final)
    bases=q(field(raw,rt,'bases'));need(len(bases)==32*5 and not any(bases[(6*n+2)*5:]),'all unused base-query prefix slots zero')
    for i,data in enumerate(snapshots):
        s=boundary.snapshot(data,layout['layout']);sh=s['header'];lo,extent=h[21:23]
        for address,size in((sh[2],sh[0]),(sh[3],sh[1]),(sh[13],sh[14])):
            need(lo<=address and size<=extent and address-lo<=extent-size,'actual SI/UC/fullFP in genuine alternate signal stack')
        for j,request in enumerate((0x1003,0x1004)):
            need(bases[(2*i+j)*5:(2*i+j+1)*5]==(request,1,1,0,sh[4+j]),'real ARCH_GET_FS/GS request/returned/result/value')
    result.update(policy='fixture-five-trajectory-v1',selected_callbacks=n,actual_snapshots=3*n+1,
        actual_base_queries=6*n+2,raw_syscalls_forwarded=0,syscall_replacements=h[19],
        complete_source_bytes=20480,complete_data_bytes=8192,record_bytes=len(raw),
        whole_program_completion=False,production_named_policy=False)
    return result
