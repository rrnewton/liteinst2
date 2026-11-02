#!/usr/bin/env python3
"""Check installed loop models' final cold-rseq inspection; no native execution.

From the repository root on one externally reserved CPU:
  python3.12 -B /path/to/loop_rseq_model.py --expect-revision REV --output FRESH
The driver may be copied outside a historical checkout. It enforces 30 CPU /
60 wall seconds, 512 MiB AS and 16 MiB output. FRESH is a new target directory.
The result records exact imported model bytes and tracked status, including a
dirty source tree if present. This finite model test does not validate an owner,
run corruption controls on a real owner record, or provide qualification credit.
"""
import argparse, ast, hashlib, importlib.util, json, os, re, resource, signal
import platform, struct, subprocess, sys, time
from pathlib import Path

sys.dont_write_bytecode=True
ROOT=Path.cwd().resolve()
TESTS=ROOT/'tools/page-entry/selected/tests'
STARTS=(0,4,8,12,18,23,26,28,32,35,37,40,43,46,48,52,56,59,61,63,65,67,71,75,79,81,83,86)
CODES=(249,264,270,1868,214,140,176,2090,271,173,282,282,282,281,381,1057,2090,271,173,107,176,2090,249,249,271,176,214,176)
LAST=(86,86,86,86,86,86,86,86,86,86,35,37,40,43,46,48,52,52,52,52,52,52,52,52,52,52,81,83)
BODY=bytes.fromhex('4983c1014983e8804983f9250f8472ffffff418078f8004d63d175e4410fb6384084ff74db'
    '4c89cd4c89c64889d889f948c1e5070f1f40000fb61084d274c138ca75bd0fb64e014883c6014883c00184c975e580383d75a8')

def need(ok,why):
    if not ok:raise ValueError(why)

def fact(path):
    raw=Path(path).read_bytes()
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def hardware(cpu):
    rows=[dict(line.split(':',1)for line in block.splitlines()if ':'in line)
          for block in Path('/proc/cpuinfo').read_text().split('\n\n')]
    rows=[{k.strip():v.strip()for k,v in row.items()}for row in rows]
    row,=[row for row in rows if row.get('processor')==str(cpu)]
    release=os.uname().release
    return dict(architecture=os.uname().machine,cpu=cpu,
        processor={k:row[k]for k in('vendor_id','cpu family','model','model name','stepping')},
        microcode=row.get('microcode'),
        kernel_version=release.split('-',1)[0],kernel_release_sha256=hashlib.sha256(release.encode()).hexdigest())

def git(*args):
    return subprocess.run(['/usr/bin/git','-c','index.threads=1','-c','core.preloadIndex=false',*args],
        cwd=ROOT,env=dict(PATH='/usr/bin:/bin',LC_ALL='C'),capture_output=True,check=True,timeout=10).stdout.decode().strip()

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def independent_order(root):
    edges={}
    for at,end in zip(STARTS,STARTS[1:]+(88,),strict=True):
        raw=BODY[at:end]
        if raw[0]in(0x74,0x75):edges[at]=(end+struct.unpack('<b',raw[1:])[0],end)
        elif raw[:2]==b'\x0f\x84':edges[at]=(end+struct.unpack('<i',raw[2:])[0],end)
        else:edges[at]=(end,)
    queue=[root]
    for at in queue:
        for target in edges[at]:
            if target in STARTS and target not in queue:queue.append(target)
    need(len(queue)==28,'all literal starts reached from every genuine root')
    return tuple(queue),tuple(5 if any(t not in STARTS for t in edges[at])else 1 for at in queue)

def decoded(source,page,offset,code,length,step=0):
    """Independent complete li2_decoded ABI1 record, including the 15-byte halo."""
    need(0<=offset and offset+15<=len(source),'complete source window')
    return struct.pack('<QQ10I',page+offset,page+offset+length,1,0,code,0,16,0,step,15,length,0)+source[offset:offset+15]+b'\0'

def storage(module,page):
    layout=tuple(page+x for x in(0x100000,0x108000,0x110000,0x111000,0x112000,0x113000))
    at=page+0x180000+64576
    extents=((page,8192),)+tuple(zip(layout,(32768,32768,4096,4096,4096,12288)))+((at,4224),)
    return layout,module.table([(a,a+n)for a,n in extents],at)

def check(focal,life):
    # Exercise the actual installed selection statement for all28 BFS roots;
    # full graph() below additionally checks every permitted fixture entry.
    tree=ast.parse((TESTS/'persistent_loop_owner/plan.py').read_bytes())
    graph=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='graph')
    assignments=[n for n in graph.body if isinstance(n,ast.Assign)and
        any(isinstance(t,ast.Name)and t.id=='last_rseq'for t in n.targets)]
    need(len(assignments)==1,'one installed final-inspection assignment')
    selector=compile(ast.Module(body=assignments,type_ignores=[]),'installed last_rseq assignment','exec')
    orders=[]
    for root,last in zip(STARTS,LAST,strict=True):
        order,kinds=independent_order(root)
        need(tuple(STARTS[i]for i in focal.bfs(root)[0])==order,'whole BFS order from literal branch encodings')
        env=dict(heads=tuple((k,)for k in kinds));exec(selector,env)
        need(order[env['last_rseq']]==last,'independent literal final-inspection location')
        orders.append((root,order,last))
    focal_cases=[];descriptors=0
    for page in(0x4000000,0x700000000000):
        layout,table=storage(focal,page);endpoint=page+0x300000
        for base_offset in(512,4022):
            base=page+base_offset
            for case,entry_offset in enumerate((0,0,23,59,59,18,52)):
                source=focal.source_image(page,base,base+entry_offset,endpoint)
                need(source[base_offset:base_offset+88]==BODY,'whole independent loader body')
                model=focal.graph(source,page,base,base+entry_offset,endpoint,layout,table)
                order,kinds=independent_order(entry_offset)
                need(model['offsets']==tuple(base_offset+x for x in order)and
                    tuple(h[0]for h in model['head_rows'])==kinds and model['links']==0,
                    'whole emitted graph order, NONE/DIRECT kinds and zero later stub inspections')
                for i,off in enumerate(order):
                    index=STARTS.index(off);end=(STARTS+(88,))[index+1]
                    expected=decoded(source,page,base_offset+off,CODES[index],end-off,int(off in(37,40,43,46)))
                    need(model['original_rows'][i][:72]==expected,'whole independently encoded original descriptor')
                    descriptors+=1
                    if kinds[i]==5:
                        need(model['direct_models'][i]['description'][:72]==expected,
                             'emitted DIRECT retains whole final-inspection original')
                last=LAST[STARTS.index(entry_offset)];i=model['last_rseq_index']
                need(order[i]==last and model['last_rseq_decoded']==model['original_rows'][i][:72],
                     'actual graph returns the exact last inspected descriptor')
                need(model['last_none_decoded']==model['original_rows'][model['last_none_index']][:72]and
                    model['head_rows'][model['last_none_index']][0]==1 and
                    model['last_proved_decoded']==model['original_rows'][model['last_proved_index']][:72],
                    'separate NONE/proved metadata meanings remain intact')
                focal_cases.append(dict(case=case,page=page,base_offset=base_offset,last_rseq=last))
    lifecycle=[]
    for page in(0x4000000,0x700000000000):
        layout,table=storage(life,page);endpoint=page+0x300000;source=life.source_image(page,endpoint)
        for root,policy,offsets,codes,lengths,step,last in(
            (512,12,(512,516,520,526,529),(264,270,1868,274,176),(4,4,6,3,2),(),529),
            (256,11,(256,259,263,266),(282,264,282,696),(3,4,3,5),(263,),266),
            (535,12,(535,539),(264,176),(4,2),(),539)):
            model=life.graph(source,page,page+root,layout,table,policy=policy,endpoint=endpoint)
            need(model['offsets']==offsets and model['links']==0,'complete literal A/B/C order without stub inspection')
            for i,(off,code,length)in enumerate(zip(offsets,codes,lengths,strict=True)):
                expected=decoded(source,page,off,code,length,int(off in step))
                need(model['original_rows'][i][:72]==expected,'whole literal A/B/C descriptor including MOV')
                descriptors+=1
            i=model['last_rseq_index'];want=decoded(source,page,last,codes[-1],lengths[-1])
            need(offsets[i]==last and model['last_rseq_decoded']==want and model['head_rows'][i][0]==5,
                 'A/B/C last cold inspection is the actual DIRECT, never the MOV store')
            need(model['direct_models'][i]['description'][:72]==want,'whole emitted A/B/C DIRECT original')
            lifecycle.append(dict(root=root,policy=policy,page=page,last_rseq=last))
    need((len(orders),len(focal_cases),len(lifecycle),descriptors)==(28,28,6,806),'fixed complete model populations')
    return dict(bfs_roots=28,focal_graphs=28,lifecycle_graphs=6,whole_decoded_descriptors=descriptors,
        bfs_orders_sha256=hashlib.sha256(json.dumps(orders,separators=(',',':')).encode()).hexdigest(),
        root_last_offsets=list(zip(STARTS,LAST,strict=True)),focal_cases=focal_cases,lifecycle_cases=lifecycle)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--expect-revision',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',a.expect_revision),'exact source revision and assertions')
    cpu,=os.sched_getaffinity(0)
    for kind,value in((resource.RLIMIT_CPU,30),(resource.RLIMIT_AS,512<<20),(resource.RLIMIT_FSIZE,16<<20),(resource.RLIMIT_CORE,0)):
        resource.setrlimit(kind,(value,value))
    signal.alarm(60)
    out=a.output.resolve();need(out.is_relative_to(ROOT/'target'),'fresh private output');out.mkdir(parents=True,exist_ok=False)
    record=dict(schema=1,profile='loop-rseq-model-v1',status='failed',expected_revision=a.expect_revision,cpu=cpu,
        bounds=dict(cpu_seconds=30,wall_seconds=60,address_space_bytes=512<<20,output_bytes=16<<20),
        driver=fact(Path(__file__)),inputs={},native_subjects=0,owner_validated=False,qualification_credit=False,
        performance_credit=False,error=None,hardware=hardware(cpu),python_version=platform.python_version(),
        reproduction_argv=['python3.12','-B','/path/to/loop_rseq_model.py','--expect-revision',a.expect_revision,
                           '--output','FRESH_TARGET_OUTPUT'],
        source_unchanged=False,inputs_unchanged=False)
    original_spec=importlib.util.spec_from_file_location
    def spec(name,location,*args,**kw):
        path=Path(location).resolve();need(path.is_relative_to(ROOT),'repository-owned model import')
        namepath=str(path.relative_to(ROOT));value=fact(path)
        need(namepath not in record['inputs']or record['inputs'][namepath]==value,'stable model source import')
        record['inputs'][namepath]=value;return original_spec(name,location,*args,**kw)
    started=time.monotonic_ns()
    try:
        record['revision']=git('rev-parse','HEAD');need(record['revision']==a.expect_revision,'actual expected revision')
        record['tracked_status']=git('status','--porcelain','--untracked-files=no')
        record['tracked_clean']=not record['tracked_status']
        importlib.util.spec_from_file_location=spec
        focal=load('focal_rseq_model',TESTS/'persistent_loop_owner/plan.py')
        life=load('lifecycle_rseq_model',TESTS/'persistent_loop_lifecycle_owner/plan.py')
        record['result']=check(focal,life)
        need(git('rev-parse','HEAD')==record['revision']and
             git('status','--porcelain','--untracked-files=no')==record['tracked_status'],'unchanged actual source status')
        need(all(fact(ROOT/k)==v for k,v in record['inputs'].items()),'whole model inputs unchanged')
        need(fact(Path(__file__))==record['driver'],'whole driver unchanged')
        record.update(status='model_regression_passed',source_unchanged=True,inputs_unchanged=True)
    except BaseException as error:record['error']=type(error).__name__+': '+str(error)
    finally:
        importlib.util.spec_from_file_location=original_spec
        record['validation_duration_ns']=time.monotonic_ns()-started
        (out/'result.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
        signal.alarm(0)
    print(json.dumps(dict(status=record['status'],result=fact(out/'result.json'))),flush=True)
    return int(record['status']!='model_regression_passed')

if __name__=='__main__':raise SystemExit(main())
