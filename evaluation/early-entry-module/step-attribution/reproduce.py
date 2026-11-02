"""One fixed strict cohort; attribute only its completed diagnostic transitions.
Build first with evaluation/early-entry-module/ret-inline/build.py. Reuse exact
closed strict-campaign fixtures. This is diagnosis, never strict qualification.
"""
import argparse, hashlib, heapq, importlib.util, json, os, re, resource, subprocess, sys
assert __debug__ and sys.flags.isolated and sys.dont_write_bytecode
for kind, limit in [(resource.RLIMIT_CPU,120),(resource.RLIMIT_FSIZE,8<<20),(resource.RLIMIT_CORE,0)]:
    resource.setrlimit(kind,(limit,limit))
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for key in ('root','revision','build','fixture-request','output','input-pins'):
    p.add_argument('--'+key,required=True)
a=p.parse_args(); root=Path(a.root).resolve(); out=Path(a.output).absolute()
assert re.fullmatch('[0-9a-f]{40}',a.revision)
assert not out.exists(); out.relative_to(root/'ignored'); out.mkdir(parents=True)
logs=root/'target/evaluation'/out.name
assert not logs.exists(); logs.mkdir(parents=True)
def save(p,x):
    with p.open('x') as f:
        json.dump(x,f,indent=2); f.write('\n'); f.flush(); os.fsync(f.fileno())
def pin(p):
    assert p.stat().st_size<=16<<20
    b=p.read_bytes(); return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
input_pins=json.loads(Path(a.input_pins).read_text())
assert set(input_pins)=={str(Path(a.build)/'closed.json'),str(Path(a.build)/'artifact.json'),a.fixture_request,str(Path(a.fixture_request).parent/'closed.json')}
assert all(pin(Path(path))==expected for path,expected in input_pins.items())
helper=root/'evaluation/admission/processes.py'
assert pin(helper)['sha256']=='0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
spec=importlib.util.spec_from_file_location('owner',helper)
owner=importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)
bound=root/'tools/unwind-oracle/bounded_command.py'
assert pin(bound)['sha256']=='c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
mapper_source=root/'evaluation/early-entry-module/entry-ret-normal/map.py'
assert pin(mapper_source)['sha256']=='f8cdd3d16d6d4725631994eea8797507e7000f3dfb4fff659c75ebae106d8986'
spec=importlib.util.spec_from_file_location('mapper',mapper_source)
mapper=importlib.util.module_from_spec(spec); spec.loader.exec_module(mapper)
prior_path=Path(a.fixture_request); prior=json.loads(prior_path.read_text())
prior_owner=json.loads((prior_path.parent/'closed.json').read_text())
mapper.owner(prior_owner,101)
build=Path(a.build); built=json.loads((build/'closed.json').read_text()); artifact=json.loads((build/'artifact.json').read_text())
assert built['status']=='RELEASE_BUILD_PASS' and built['revision']==a.revision
assert artifact['revision']==a.revision
mapper.owner(built['owner'],0)
assert json.loads((build/'owner.json').read_text())==built['owner']
receipt=json.loads((build/'receipt.json').read_text()); assert receipt==built['receipt']
assert receipt['exit']==0 and receipt['absence_proof']=='ECHILD' and not receipt['wall_timeout']
assert receipt['cleanup_events']==receipt['unexpected_descendants']==[] and receipt['cleanup_error'] is receipt['aborted'] is None
assert receipt['inputs_unchanged'] and receipt['request_sha256']==pin(build/'request.json')['sha256']
assert receipt['helper_sha256']==pin(bound)['sha256']
product=artifact['product']
assert product['target']['name']=='frontend-native-oracle' and product['target']['kind']==['bin']
assert product['features']==['frontend-native-qualification'] and product['fresh'] is False
assert product['profile']==dict(opt_level='3',debuginfo=0,test=False,debug_assertions=False,overflow_checks=False)
assert product['manifest_path']==str(root/'tools/rapid-profiler/Cargo.toml')
assert pin(build/'stdout.txt')['sha256']==receipt['stdout_sha256']
assert sum(json.loads(line)==product for line in (build/'stdout.txt').read_text().splitlines())==1
elf=root/'target/release/frontend-native-oracle'; assert pin(elf)==artifact['binary']
assert product['executable']==str(elf) and product['filenames']==[str(elf)]
env=prior['env']; assert len(os.sched_getaffinity(0))==1
assert env['CARGO_TARGET_DIR']==str(root/'target')
git=['/usr/bin/git','-c','index.threads=1','-c','core.preloadIndex=false','-C',str(root)]
assert subprocess.check_output(git+['rev-parse','HEAD'],env=env,timeout=15).decode().strip()==a.revision
assert subprocess.check_output(git+['status','--porcelain','--untracked-files=no'],env=env,timeout=15)==b''
argv=prior['argv'].copy()
assert argv[0]==str(elf) and argv[1:4]==['normal-early-entry-state','enabled','10']
assert argv[6:10]==['4096','126','4224','41'] and argv[12]=='4096'
fixtures={s:prior['pins'][s] for s in argv if s.endswith('.so')}
assert len(fixtures)==4 and all(pin(Path(s))==v for s,v in fixtures.items())
argv[-1]=str(out/'native-output')
closed=dict(status='FAILED_DIAGNOSTIC',revision=a.revision,hardware='AMD EPYC Zen 5 dev host',cpus=sorted(os.sched_getaffinity(0)),load=os.getloadavg(),attempts=1,input_pins=input_pins,mapper=pin(mapper_source),build=pin(build/'closed.json'),artifact=artifact['binary'],fixtures=fixtures,strict_gate='unchanged20k',runs=[])
def run(name,args,file_limit):
    d=out/name; d.mkdir()
    request=dict(argv=args,cwd=str(root),env=env,stdout=str(d/'stdout'),stderr=str(d/'stderr'),cpu_seconds=120,wall_seconds=180,file_bytes=file_limit)
    save(d/'request.json',request)
    rec=owner.run_command(['/usr/bin/python3.9','-I','-B',str(root/'tools/unwind-oracle/bounded_command.py'),'--request',str(d/'request.json'),'--receipt',str(d/'receipt.json')],env,logs/(name+'.log'),205,1<<20)
    save(d/'owner.json',rec)
    assert rec['cleanup_complete'] and rec['termination'] is None and rec['reaped_descendants']==0
    receipt=json.loads((d/'receipt.json').read_text())
    assert not receipt['wall_timeout'] and receipt['absence_proof']=='ECHILD' and receipt['unexpected_descendants']==receipt['cleanup_events']==[]
    assert receipt['aborted'] is receipt['cleanup_error'] is None and receipt['inputs_unchanged']
    assert rec['exit_code']==(0 if receipt['exit']==0 else 1)
    assert receipt['request_sha256']==pin(d/'request.json')['sha256'] and receipt['helper_sha256']==pin(bound)['sha256']
    for s in ('stdout','stderr'): assert pin(d/s)['sha256']==receipt[s+'_sha256']
    closed['runs'].append(dict(name=name,request=request,owner=rec,receipt=receipt))
    return receipt['exit'],(d/'stdout').read_text(),(d/'stderr').read_text()
try:
    save(out/'intent.json',closed)
    rc,stdout,stderr=run('strict',argv,1<<20)
    closed['strict_exit']=rc
    assert rc==101, 'no expected strict step refusal; preserve outcome without attribution'
    guard=re.findall(r'whole ordinary child 20000-step budget: phase=normal candidate steps=(\d+) rip=(0x[0-9a-f]+) pid=\d+ step_anchor=(0x[0-9a-f]+)',stderr)
    assert len(guard)==1 and guard[0][0]=='20000'
    h=re.findall(r'early-entry code-pcs: capacity=20000 first_observed_step=Some\((\d+)\) recorded_completed_steps=(\d+) dropped_completed_steps=(\d+) unpaired_observations=(\d+)',stderr)
    assert len(h)==1
    first,recorded,dropped,unpaired=map(int,h[0]); assert dropped==unpaired==0 and first+recorded==20000
    pcs=[(int(pc,16),int(n)) for pc,n in re.findall(r'^early-entry pc: ([0-9a-f]{16}) (\d+)$',stderr,re.M)]
    assert 0<len(pcs)<=20000 and sum(line.startswith('early-entry pc:') for line in stderr.splitlines())==len(pcs)
    assert len({pc for pc,n in pcs})==len(pcs) and all(n>0 for pc,n in pcs) and sum(n for pc,n in pcs)==recorded
    page_header=re.findall(r'early-entry code-pages: page_bytes=4096 first_observed_step=Some\((\d+)\) completed_single_steps=(\d+) recorded_completed_steps=(\d+) dropped_completed_steps=(\d+) unpaired_observations=(\d+) records=(\d+)',stderr)
    assert len(page_header)==1
    pf,completed,pr,pd,pu,number=map(int,page_header[0])
    assert (pf,completed,pr,pd,pu)==(first,recorded,recorded,0,0)
    pages=re.findall(r'^early-entry code-page: page=(0x[0-9a-f]+) completed_single_steps=(\d+) first_completed_step=(\d+) last_completed_step=(\d+)$',stderr,re.M)
    assert len(pages)==number==sum(line.startswith('early-entry code-page:') for line in stderr.splitlines())
    assert 0<number<=128 and len({pc for pc,n,lo,hi in pages})==number
    assert all(int(pc,16)%4096==0 and int(n)>0 and first<int(lo)<=int(hi)<=20000 for pc,n,lo,hi in pages)
    by_page={}
    for pc,n in pcs: by_page[pc&~4095]=by_page.get(pc&~4095,0)+n
    assert by_page=={int(pc,16):int(n) for pc,n,lo,hi in pages}
    data,_=mapper.read(elf,16<<20,artifact['binary'])
    loads,rx,symbols,undefined,entries=mapper.elf_tables(data)
    anchor=mapper.unique(symbols,r'_RNvM.*15native_ordinary.*4Walk4step')
    bias=int(guard[0][2],16)-anchor['start']; assert 0<=bias<1<<64 and bias%4096==0
    marker=mapper.unique(symbols,r'_RNv.*6normal6module11early_entry14snapshot_ready')
    markers=[int(pc,16) for pc in re.findall(r'early-entry boundary: kind=snapshot_marker_pc step=\d+ pc=(0x[0-9a-f]+) ordinal=\d+',stderr)]
    assert markers and all(pc==bias+marker['start'] for pc in markers)
    counts={}; unknown={}; ambiguous={}
    symbols.sort(key=lambda s:(s['start'],s['end'],s['name']))
    index=0; active={}; ends=[]; joins=0
    for pc,n in sorted(pcs):
        relative=pc-bias
        while index<len(symbols) and symbols[index]['start']<=relative:
            s=symbols[index]; active[index]=s
            heapq.heappush(ends,(max(s['end'],s['start']+1),index)); index+=1
        while ends and ends[0][0]<=relative:
            _,old=heapq.heappop(ends); del active[old]
        joins+=len(active); assert joins<=1_000_000
        hits=list(active.values())
        if not any(segment['start']<=relative<segment['end'] for segment in rx):
            unknown[hex(pc)]=n
        elif len(hits)==1 and hits[0]['end']>hits[0]['start']:
            s=hits[0]; key=(s['start'],s['end']-s['start'],s['name']); counts[key]=counts.get(key,0)+n
        elif not hits: unknown[hex(pc)]=n
        else: ambiguous[hex(pc)]=dict(count=n,symbols=hits)
    rows=[dict(address=hex(k[0]),bytes=k[1],symbol=k[2],completed_steps=n) for k,n in counts.items()]
    rows.sort(key=lambda r:(-r['completed_steps'],r['symbol']))
    assert sum(r['completed_steps'] for r in rows)+sum(unknown.values())+sum(v['count'] for v in ambiguous.values())==recorded
    save(out/'counts.json',dict(revision=a.revision,first_observed_step=first,completed_steps=recorded,unique_pcs=len(pcs),image_bias=hex(bias),functions=rows,unclassified=unknown,ambiguous=ambiguous,limitations='Completed strict prefix only. Symbol intervals include inlined code. No caller-inclusive costs, timing, whole-program totals, causal speedup or strict pass.'))
    assert all(pin(Path(s))==v for s,v in fixtures.items()) and pin(elf)==artifact['binary']
    assert all(pin(Path(path))==expected for path,expected in input_pins.items())
    closed['status']='DIAGNOSTIC_COMPLETE_STRICT_FAILED'
except BaseException as e:
    closed['error']=repr(e)
finally:
    save(out/'closed.json',closed)
print(json.dumps({k:closed[k] for k in ('status','revision','attempts')}))
raise SystemExit(0 if closed['status']=='DIAGNOSTIC_COMPLETE_STRICT_FAILED' else 1)
