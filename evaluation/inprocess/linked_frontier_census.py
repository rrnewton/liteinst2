#!/usr/bin/env python3
"""One real LS pre-edge frontier census; no qualification or timing comparison.

Fresh committed-source build and unchanged mandatory byte oracle precede the
single bounded subject. Counter failures never become accepted observations.
"""
import argparse,csv,hashlib,importlib.util,io,json,os,re,struct,subprocess,sys,types,shutil
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
SCRIPT='evaluation/inprocess/linked_frontier_census.py'
PROGRAM=[30,512<<20,16<<20,60]
SHORT=[5,512<<20,16<<20,15]
LABEL='LI2_LINKED_FRONTIER_CENSUS '
CODE_LABEL='LI2_LINKED_FRONTIER_CODE '
CHANNELS=('cold_unsupported','cold_page_cut','root_unsupported','root_page_cut','completed_unsupported','completed_page_cut')
CODE_COUNT=4936
CENSUS_BYTES=592616
REASONS=('initial_enqueue_invariant','enqueue_outside_page','queue_capacity',
    'source_byte_overlap','unsupported_frontier_capacity','supported_head_capacity',
    'empty_supported_heads','no_unsupported_frontier','unresolved_primary_successor',
    'unresolved_conditional_fallthrough','kahn_stall','zero_distance','incoming_edge_underflow')
H=lambda b:hashlib.sha256(b).hexdigest()
D=lambda v:H(json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode())
EXPECTED={'tools/page-entry/selected/linked_preedge_plan.h': {'bytes': 6337, 'sha256': '20fb22552ea7e0bdffc3e4f662696848b2039faa3353030ae40ccd1daa0d0d72'}, 'tools/page-entry/selected/linked_preedge_plan.c': {'bytes': 18313, 'sha256': '8146368c2a274ee61d724266f84a0f20d3e8a70fbe706a778f2d23fae992c9e0'}, 'tools/page-entry/selected/linked_controller.inc': {'bytes': 64758, 'sha256': '54a99a1290fcfc5b144613d5ae756f0ccdd72a4b4eed8a6347959a0ba6ba1627'}, 'tools/page-entry/selected/build-linked-preedge-frontier-census.sh': {'bytes': 3389, 'sha256': 'bd437824f599150004fa82e38c7dd5b977bd92cc0ae8d4f2be71765166e15edc'}, 'evaluation/inprocess/linked_epoch_build.py': {'bytes': 33873, 'sha256': 'd585f9037b56414f920d6847ffe915379eec3b4d5a8b1216bb585811ec3251b9'}}

def need(ok, why):
    if not ok:
        raise ValueError(why)

def fact(path):
    data = Path(path).read_bytes()
    return dict(bytes=len(data), sha256=H(data))

def git(*args):
    return subprocess.check_output(['/usr/bin/git', '-C', str(ROOT), *args],
                                   env=dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C'),
                                   timeout=15)

def git_bytes(revision, paths):
    """One bounded read-only Git batch, retaining exact complete blob bytes."""
    paths=sorted(paths)
    request=''.join(revision+':'+p+'\n' for p in paths).encode()
    data=subprocess.check_output(['/usr/bin/git','-C',str(ROOT),'cat-file','--batch'],
        input=request,env=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C'),timeout=15)
    need(len(data)<=96<<20,'bounded source snapshot')
    cursor=0;result={}
    for path in paths:
        end=data.index(b'\n',cursor);header=data[cursor:end].split()
        need(len(header)==3 and header[1]==b'blob','actual complete committed source blob')
        size=int(header[2]);cursor=end+1
        need(size<=len(data)-cursor-1 and data[cursor+size:cursor+size+1]==b'\n','whole Git blob boundary')
        result[path]=data[cursor:cursor+size];cursor+=size+1
    need(cursor==len(data),'no unconsumed Git source output')
    return result

def source_paths(revision):
    paths=git('ls-tree','-r','--name-only',revision,'--','tools/page-entry',
              'evaluation/inprocess','evaluation/admission','evaluation/precontext/verify.py').decode().splitlines()
    code={p for p in paths if (p.endswith('.py') and not p.startswith('evaluation/inprocess/results/')) or
          (p.endswith('.json') and str(Path(p).parent) in ('evaluation/inprocess','evaluation/admission'))}
    compile_sources={p for p in paths if p.startswith('tools/page-entry/') and
        Path(p).suffix in ('.c','.h','.inc','.S','.sh','.py','.ld','.rs','.toml','.lock')}
    return code,compile_sources

def counters(stderr, hint):
    """Canonical raw numeric extraction only, not a release acceptance gate."""
    def pairs(items):
        need(len(items) == len(dict(items)), 'no duplicate terminal keys')
        return dict(items)
    result = {}
    for label in ('LI2_LINKED_PREEDGE', 'LI2_LINKED_NATIVE_HINT', 'LI2_MAPS_VIEW', 'LI2_NATIVE'):
        prefix = (label + ' ').encode()
        lines = [x for x in stderr.splitlines() if x.startswith(prefix)]
        if label == 'LI2_LINKED_NATIVE_HINT' and not hint:
            need(not lines, 'baseline must not emit hint counters')
            continue
        need(len(lines) == 1 and len(lines[0]) <= 4096, 'one complete ' + label)
        value = json.loads(lines[0][len(prefix):], object_pairs_hook=pairs)
        need(type(value) is dict and value and all(type(x) is int and 0 <= x < 1 << 64
             or type(x) is list and all(type(y) is int and 0 <= y < 1 << 64 for y in x)
             for x in value.values()), 'unsigned actual terminal values')
        need(prefix + json.dumps(value, separators=(',', ':'), allow_nan=False).encode() == lines[0],
             'canonical whole numeric terminal row')
        result[label] = value
    native=result['LI2_NATIVE']
    need(native.get('version')==1 and native.get('status')==native.get('failure_code')==0,
         'observed exit-zero native terminal outcome')
    linked = result['LI2_LINKED_PREEDGE']
    need(linked.get('version') == 2 and linked.get('status') == 0 and
         linked.get('failure_code') == linked.get('first_error') == 0,
         'observed exit-zero linked terminal outcome')
    need(type(linked.get('signals')) is list and len(linked['signals']) == 5 and
         type(linked.get('refusals')) is list and len(linked['refusals']) == 4,
         'actual five event buckets and four refusal classes')
    need(('graph_refaults' in linked) is hint, 'distinct actual hint report domain')
    if hint:
        row=result['LI2_LINKED_NATIVE_HINT']
        need(row.get('version')==1 and row.get('status')==row.get('failure_code')==row.get('errors')==0,
             'observed exit-zero hint terminal outcome')
    return result

def observation(stderr,linked):
    """Strict counters only. Failed/incomplete observations are never ranks."""
    def parse(line,prefix,keys):
        need(len(line)<=2048,'bounded census row')
        def pairs(items):
            need(len(items)==len(dict(items)),'no duplicate census keys')
            return dict(items)
        value=json.loads(line[len(prefix):],object_pairs_hook=pairs)
        need(type(value)is dict and list(value)==keys,'exact census schema')
        need(prefix+json.dumps(value,separators=(',',':'),allow_nan=False).encode()==line,
             'canonical complete census row')
        return value
    def uint(v):return type(v)is int and 0<=v<1<<64
    def vector(v,n):return type(v)is list and len(v)==n and all(uint(x)for x in v)
    prefix=LABEL.encode();lines=[x for x in stderr.splitlines()if x.startswith(prefix)]
    need(len(lines)==1,'one actual census header')
    row=parse(lines[0],prefix,['version','status','failure_code','overflow','invalid','started','returned',
        'results','reasons','totals','rsp_mov'])
    need(all(uint(row[k])for k in('version','status','failure_code','overflow','invalid','started','returned'))and
         vector(row['results'],8)and vector(row['reasons'],13)and vector(row['totals'],6)and
         vector(row['rsp_mov'],6),'typed bounded census counters')
    need(row['version']==1 and row['status']==row['failure_code']==row['overflow']==row['invalid']==0,
         'complete error-free unsaturated census')
    results=row['results'];totals=row['totals']
    need(row['started']==row['returned']==sum(results)and row['started']>0,
         'all cold planner calls returned exactly once')
    need(results[0]==linked['publications']and results[2]==results[3]==results[7]==0 and
         [results[i]for i in(1,4,5,6)]==linked['refusals']and
         sum(row['reasons'])==results[5],
         'exact actual cold successes and first-refusal result partitions')
    need(totals[2]+totals[3]==results[1]and totals[2]<=totals[0]and totals[3]<=totals[1]and
         totals[4]+totals[5]==linked['completed']and totals[5]==linked['cut_exits']and
         all(row['rsp_mov'][i]<=totals[i]for i in range(6)),
         'root refusals and completed actual frontier populations')
    prefix=CODE_LABEL.encode();lines=[x for x in stderr.splitlines()if x.startswith(prefix)]
    need(0<len(lines)<=CODE_COUNT,'bounded nonempty Code histogram')
    hist=[];previous=-1
    for line in lines:
        v=parse(line,prefix,['code','counts','different','sample_length','sample_step','sample_bytes'])
        need(uint(v['code'])and previous<v['code']<CODE_COUNT and vector(v['counts'],6)and
             vector(v['different'],6)and sum(v['counts'])>0 and
             all(v['different'][i]<=v['counts'][i]for i in range(6))and
             uint(v['sample_length'])and 1<=v['sample_length']<=15 and
             uint(v['sample_step'])and v['sample_step']<=11 and vector(v['sample_bytes'],16)and
             all(x<256 for x in v['sample_bytes'])and not any(v['sample_bytes'][v['sample_length']:]),
             'strict ordered actual Code rows, encoding witness and diversity counts')
        previous=v['code'];hist.append(v)
    need([sum(v['counts'][i]for v in hist)for i in range(6)]==totals,
         'whole Code histogram equals all six actual populations')
    return dict(header=row,codes=hist)


def code_table(builder,pin):
    packages=[x for x in builder.packages if x['name']=='iced-x86']
    need(len(packages)==1 and packages[0]['version']=='1.21.0','exact built decoder Code source')
    root=Path(packages[0]['root']);path=pin(root/'src/code.rs');constants=pin(root/'src/iced_constants.rs')
    need(re.search(r'CODE_ENUM_COUNT: usize = 4936;',constants.read_text())is not None,
         'actual locked decoder has exactly4936 Codes')
    values=re.findall(r'^\s*([A-Za-z_][A-Za-z0-9_]*) = ([0-9]+),$',path.read_text(),re.M)
    names={int(value):name for name,value in values}
    need(len(values)==len(names)==CODE_COUNT and sorted(names)==list(range(CODE_COUNT)),
         'complete actual Code enum without inferred opcode values')
    return names,dict(code=fact(path),constants=fact(constants),package_checksum=packages[0]['checksum'])


def ranked_histogram(observed,names):
    rows=[]
    for v in observed['codes']:
        name=names[v['code']]
        row=dict(code=v['code'],name=name,**dict(zip(CHANNELS,v['counts'])))
        row.update(call=int(name.startswith('Call_')),ret=int(name.startswith(('Retn','Retf'))),
            indirect=int(re.match(r'^(Call|Jmp)_(rm|m)',name)is not None),
            loop_opcode=int(name.startswith(('Loop','Jcxz_','Jecxz_','Jrcxz_'))),
            implicit_stack_form=int(name.startswith(('Call_','Retn','Retf','Iret','Push','Pop','Enter','Leave'))),
            encoding_differences=sum(v['different']))
        rows.append(row)
    return sorted(rows,key=lambda v:(-v['completed_unsupported']-v['completed_page_cut'],
        -v['root_unsupported']-v['root_page_cut'],-v['cold_unsupported']-v['cold_page_cut'],v['code']))


def compiled_observation(data):
    """Actual ELF sizes/loads, with no runtime permission or storage credit."""
    def take(at,n):
        need(type(at)is int and type(n)is int and 0<=at<=len(data)and 0<=n<=len(data)-at,'bounded actual ELF extent')
        return data[at:at+n]
    h=struct.unpack('<16sHHIQQQIHHHHHH',take(0,64))
    need(h[0][:7]==b'\x7fELF\x02\x01\x01'and h[1:4]==(3,62,1)and h[8:10]==(64,56)and
         0<h[10]<=64 and h[11]==64 and 0<h[12]<=4096,'actual bounded ET_DYN observation bridge')
    ph=[struct.unpack('<IIQQQQQQ',take(h[5]+56*i,56))for i in range(h[10])]
    sh=[struct.unpack('<IIQQQQIIQQ',take(h[6]+64*i,64))for i in range(h[12])]
    tables=[x for x in sh if x[1]==2];need(len(tables)==1,'one complete observation symbol table')
    t=tables[0];need(t[9]==24 and t[5]%24==0 and t[6]<len(sh),'whole actual observation symbols')
    strings=sh[t[6]];need(strings[1]==3,'actual symbol names');names=take(strings[4],strings[5]);found={}
    wanted={b'selected_linked_epoch',b'li2_preedge_plan_page_observed'}
    for at in range(t[4],t[4]+t[5],24):
        name,info,other,section,address,size=struct.unpack('<IBBHQQ',take(at,24))
        need(name<len(names)and b'\0'in names[name:],'complete symbol name')
        name=names[name:names.index(b'\0',name)]
        if name in wanted:
            need(name not in found and 0<section<len(sh),'one defined actual observation symbol')
            expected=6 if name==b'selected_linked_epoch'else 5
            loads=[(i,x)for i,x in enumerate(ph)if x[0]==1 and x[1]==expected and
                   x[3]<=address and size>0 and address-x[3]+size<=x[6]]
            need(len(loads)==1,'whole observation symbol in exact compiled RW/NX or RX load')
            if name==b'selected_linked_epoch':
                need(info&15==1 and size>CENSUS_BYTES and address%8==0 and sh[section][1]==8 and
                     sh[section][2]&3==3,'actual whole zero-initialized controller contains bounded census storage')
            else:need(info&15==2 and size>0,'actual callable observation getter')
            found[name.decode()]=dict(address=address,bytes=size,load_index=loads[0][0],flags=expected)
    need(set(found)=={x.decode()for x in wanted},'complete compiled observed cold entry and protected-controller storage')
    return dict(scope='COMPILED_ELF_ONLY',symbols=found)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--revision',required=True)
    parser.add_argument('--output',type=Path,required=True)
    a=parser.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0))==1,'assertions and exactly one externally reserved CPU')
    need(Path(__file__).resolve()==ROOT/SCRIPT and re.fullmatch('[0-9a-f]{40}',a.revision)is not None and
         git('rev-parse','HEAD').decode().strip()==a.revision,'canonical committed observer and exact revision')
    need(git('diff','--name-only',a.revision,'--','tools/page-entry','evaluation/inprocess',
             'evaluation/admission','evaluation/precontext/verify.py')==b'','no tracked source edits')
    code,compiled=source_paths(a.revision);actual=git_bytes(a.revision,code|compiled)
    current={p:dict(bytes=len(b),sha256=H(b))for p,b in actual.items()}
    need(all(current.get(p)==v for p,v in EXPECTED.items()),'exact reviewed observer/runtime/build source')
    need(all((ROOT/p).read_bytes()==b for p,b in actual.items()),'all whole committed local source/data')
    need((ROOT/SCRIPT).read_bytes()==actual[SCRIPT],'whole committed collector identity')
    manifest=dict(driver=current[SCRIPT],revision=a.revision,code={p:current[p]for p in code},
                  compiled={p:current[p]for p in compiled},reviewed=EXPECTED)
    out=a.output.resolve();out.relative_to(ROOT/'target/page-region-next');out.mkdir(mode=0o700)
    cpu=next(iter(os.sched_getaffinity(0)))
    sys.path[:0]=[str(ROOT/'evaluation/inprocess'),str(ROOT/'tools/page-entry')]
    from page_selected import ENV,save
    from page_selected_process import invoke
    from page_selected_generic_build import Build,PROFILES
    from page_selected_oneshot_build import before_default
    from page_native_pair_performance import program_invoke
    import page_native_pair_performance as pair
    import linked_epoch_build as linked_build
    import namespace
    from run import hardware
    r=dict(schema=1,scope='UNQUALIFIED_PREEDGE_FRONTIER_CENSUS_ONLY',qualification_credit=False,
        timing_credit=False,aggregate_credit=False,source_revision=a.revision,cpu=cpu,hardware=hardware(cpu),
        bounds=dict(PROFILES,metadata=PROGRAM,build_metadata=PROFILES['metadata'],program=PROGRAM,
                    release_build=PROGRAM,finite=SHORT),commands=[],inputs={},artifacts={},aliases={},namespace_aliases={},
        case=dict(name='frontier-ls',status='not_run'),error=None,final_errors=[],source_unchanged=False,cleanup_complete=False)

    def pin(path):
        alias = Path(os.path.abspath(path)); path = alias.resolve(strict=True)
        value = fact(path)
        need(str(alias) not in r['aliases'] or r['aliases'][str(alias)] == str(path), 'stable input alias')
        need(str(path) not in r['inputs'] or r['inputs'][str(path)] == value, 'stable input bytes')
        r['aliases'][str(alias)] = str(path); r['inputs'][str(path)] = value
        return path

    def binary(path):
        path = pin(path); value = dict(fact(path), mode=path.stat().st_mode & 0o7777)
        need(str(path) not in r['artifacts'] or r['artifacts'][str(path)] == value, 'stable artifact')
        r['artifacts'][str(path)] = value
        return path

    def imports():
        # Include dynamically loaded modules referenced by module objects, not
        # just sys.modules: checks.admission is loaded through exec_module().
        queue = [v for v in sys.modules.values() if isinstance(v, types.ModuleType)]
        seen = set()
        while queue:
            module = queue.pop()
            if id(module) in seen: continue
            seen.add(id(module)); need(len(seen) <= 8192, 'bounded module closure')
            queue.extend(v for v in vars(module).values() if isinstance(v, types.ModuleType))
            p = getattr(module, '__file__', None)
            if not p or not Path(p).is_file(): continue
            p = Path(p).resolve()
            if p == ROOT / SCRIPT:
                need(fact(p) == manifest['driver'], 'executed diagnostic identity')
                pin(p)
                continue
            if p.is_relative_to(ROOT):
                rel = str(p.relative_to(ROOT))
                need(rel in manifest['code'] and fact(p) == manifest['code'][rel],
                     'actual executed local module is in baseline closure: ' + rel)
            pin(p)

    def stable():
        imports()
        need(all(Path(k).resolve(strict=True) == Path(v) for k,v in r['aliases'].items()), 'all aliases unchanged')
        need(all(fact(p) == v for p,v in r['inputs'].items()), 'whole input byte closure')
        need(all(dict(fact(p), mode=Path(p).stat().st_mode & 0o7777) == v
                 for p,v in r['artifacts'].items()), 'whole artifact byte/mode closure')
        need(all(Path(p).is_symlink() and os.readlink(p) == value for p,value in
                 r['namespace_aliases'].items()), 'sealed namespace aliases unchanged')

    def run(name,argv,profile='metadata',expected=0,env=None,record=False,step=False):
        stable();need(name not in [x['name']for x in r['commands']],'unique retained command')
        executable=str(argv[0]);resolved=executable if '/'in executable else shutil.which(executable,path=(ENV if env is None else env)['PATH'])
        need(resolved is not None,'resolved actual command executable');binary(resolved)
        row=dict(name=name,argv=list(map(str,argv)),profile=profile,bounds=r['bounds'][profile],
                 expected_exit=expected,capture_limit=16<<20,environment=dict(ENV if env is None else env))
        r['commands'].append(row)
        try:stdout,stderr=(program_invoke if name=='frontier-ls'else invoke)(row,out,cpu,record=record,step=step)
        finally:
            for value in row.get('captures',{}).values():binary(out/value['file'])
            save(out/'receipt.json',r)
        need(type(row['exit'])is int and (expected is None or row['exit']==expected),'actual required command outcome: '+name)
        return row,stdout,stderr

    def build_run(name,argv,profile='metadata',env=None,expected=0):
        before_default(name,argv,builder,pin,r['aliases'],run,r)
        return run(name,argv,profile='build_metadata'if profile=='metadata'else profile,env=env,expected=expected)

    builder=Build(r,out,pin,binary,build_run,extra_decoder_sources=('region.rs',),scalar_span=True,linked_epoch=True)
    try:
        pin(ROOT/SCRIPT);save(out/'source-manifest.json',manifest);binary(out/'source-manifest.json')
        for path in current:pin(ROOT/path)
        products=builder.prepare()
        need(builder.decoder_features==('scalar-region','scalar-span','linked-epoch'),'fresh exact linked archive')
        archive=binary(products['archive']);r['archive']=fact(archive)
        bridge=linked_build.build_bridge(builder,products,out,pin,binary,r['aliases'],run,r,
                                        native_hint=True,preedge=True,frontier_census=True)
        r['compiled_observation']=compiled_observation(bridge.read_bytes())
        names,r['code_table']=code_table(builder,pin)
        (out/'external-inputs').mkdir()
        state=pair.prepare_workload('frontier-ls','/bin/ls',['-d','.'],bridge,builder,out,pin,binary,run,r,namespace)
        ns=out/'frontier-ls-namespace';tools=builder.tools
        argv=[tools['python'],'-B',state['carrier_tool'],'exec-loader','--library-root','/usr/lib64',
              '--namespace',ns,state['carrier'],state['original'],'--',*state['argv']]
        case=r['case'];case['status']='failed';start=len(r['commands'])
        try:
            row,stdout,stderr=run('frontier-ls',argv,profile='program',expected=None,env=pair.PROGRAM_ENV)
            need(row['exit']==0,'actual diagnostic subject must exit zero')
            need(stdout==b'.\n','exact full LS stdout')
            pair.namespace_join(state,ns,binary,r,namespace)
            raw=counters(stderr,True);census=observation(stderr,raw['LI2_LINKED_PREEDGE'])
            case.update(status='observed_unqualified',raw_counters=raw,census=census,
                        histogram=ranked_histogram(census,names))
        except Exception as error:case['error']=type(error).__name__+': '+str(error)
        finally:
            if len(r['commands'])>start:
                row=r['commands'][start]
                case.update({k:row.get(k)for k in ('pid','exit','process_ns','duration_ns','timed_out','reaped')})
                case['captures']=row.get('captures',{})
            save(out/'receipt.json',r)
    except BaseException as error:r['error']=type(error).__name__+': '+str(error)
    finally:
        try:r['final_errors'].extend(builder.finish())
        except BaseException as error:r['final_errors'].append('build finish: '+type(error).__name__+': '+str(error))
        try:
            stable()
            need(git('rev-parse','HEAD').decode().strip()==a.revision,'invocation revision unchanged')
            need(all(fact(ROOT/path)==value for path,value in current.items()),'all committed sources unchanged')
            r['source_unchanged']=True
        except BaseException as error:r['final_errors'].append(type(error).__name__+': '+str(error))
        r['cleanup_complete']=all(c.get('reaped')is True and c.get('cleanup_errors')==[] and
            all(d.get('closed')is True for d in c.get('descriptors',[]))for c in r['commands'])
        r['status']=('complete_unqualified'if r['error']is None and not r['final_errors']and
            r['cleanup_complete']and r['case']['status']=='observed_unqualified'else'failed')
        save(out/'receipt.json',r)
        c=r['case'];raw=c.get('raw_counters',{});le=raw.get('LI2_LINKED_PREEDGE',{});hint=raw.get('LI2_LINKED_NATIVE_HINT',{})
        view=raw.get('LI2_MAPS_VIEW',{});native=raw.get('LI2_NATIVE',{});census=c.get('census');header=census['header']if census else None
        row=dict(name=c['name'],status=c['status'],exit=c.get('exit'),process_ns=c.get('process_ns'),
            timed_out=c.get('timed_out'),events=le.get('events'),traps=le.get('signals',[None]*5)[1],
            offers=le.get('offers'),entries=le.get('entries'),graph_refusals=le.get('refusals',[None]*4)[2],
            refaults=le.get('refaults'),graph_refaults=le.get('graph_refaults'),hint_hits=hint.get('hits'),
            hint_admitted=hint.get('admitted'),hint_refused=hint.get('refused'),
            maps_queries=view.get('queries'),maps_hits=view.get('hits'),maps_refreshes=view.get('refreshes'),
            maps_comparisons=view.get('comparisons'),maps_fresh=view['refreshes']+view['comparisons']if view else None,
            maps_updates=view.get('updates'),maps_invalidations=view.get('invalidations'),maps_unexplained=view.get('unexplained'),
            total_native_attempts=native.get('attempts'),total_native_admissions=native.get('admissions'),
            total_native_closed=native.get('closed'),observation_overflow=header['overflow']if header else None,
            cold_calls=header['started']if header else None,cut_exits=le.get('cut_exits'))
        row.update({name:header['reasons'][i]if header else None for i,name in enumerate(REASONS)})
        if header:
            row.update({name:header['totals'][i]for i,name in enumerate(CHANNELS)})
            row.update({'recognized_mov_rsp_'+name:header['rsp_mov'][i]for i,name in enumerate(CHANNELS)})
        hw=dict(r['hardware']);flags=hw.pop('isa_flags');hw.update(isa_flags_count=len(flags),isa_flags_sha256=D(flags))
        summary=dict(scope=r['scope'],status=r['status'],source_revision=a.revision,cpu=cpu,hardware=hw,bounds=r['bounds'],
            qualification_credit=False,timing_credit=False,aggregate_credit=False,row=row,
            code_table=r.get('code_table'),top_codes=c.get('histogram',[])[:32],
            category_counts={kind:[sum(v[channel]for v in c.get('histogram',[])if v[kind])for channel in CHANNELS]
                for kind in('call','ret','indirect','loop_opcode','implicit_stack_form')},
            reproduction_argv=['python3','-B',SCRIPT,'--revision',a.revision,'--output','${PRIVATE_OUTPUT}'],
            reproduction_environment='One externally reserved CPU; each child uses its recorded original hard bounds.',
            driver=manifest['driver'],source_manifest=fact(out/'source-manifest.json'),archive=r.get('archive'),
            input_count=len(r['inputs']),inputs_sha256=D(r['inputs']),artifact_count=len(r['artifacts']),artifacts_sha256=D(r['artifacts']),
            command_count=len(r['commands']),commands_sha256=D(r['commands']),cleanup_complete=r['cleanup_complete'],
            source_unchanged=r['source_unchanged'],receipt=fact(out/'receipt.json'),
            count_scope='Explicit cold calls only; proof rebuilds excluded. Candidate frontiers, root refusals and actual completed exits are distinct. Kahn-stall is cycle evidence; no-frontier is not. Code families use the exact locked enum. Recognized MOV-to-RSP is a subset; general RSP effects remain unknown. One encoding witness per Code is not an exhaustive encoding/effect census. No qualification or saved-event/timing credit.')
        text=json.dumps(summary,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
        stream=io.StringIO();writer=csv.DictWriter(stream,fieldnames=list(row),lineterminator='\n');writer.writeheader();writer.writerow(row)
        need(len(text.encode())<=16<<10 and len(stream.getvalue().encode())<=8<<10 and
             all(x not in text+stream.getvalue()for x in (str(ROOT),str(Path.home()),'/home/')),'bounded numeric summary without private paths')
        histogram=io.StringIO();rows=c.get('histogram',[])
        if rows:
            table=csv.DictWriter(histogram,fieldnames=list(rows[0]),lineterminator='\n');table.writeheader();table.writerows(rows)
        need(len(histogram.getvalue().encode())<=2<<20 and all(x not in histogram.getvalue()for x in
             (str(ROOT),str(Path.home()),'/home/')),'bounded numeric Code histogram without host paths')
        (out/'histogram.csv').write_text(histogram.getvalue())
        summary['histogram']=fact(out/'histogram.csv')
        text=json.dumps(summary,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
        need(len(text.encode())<=32<<10 and all(x not in text for x in(str(ROOT),str(Path.home()),'/home/')),
             'final bounded sanitized census summary')
        (out/'summary.json').write_text(text);(out/'summary.csv').write_text(stream.getvalue())
    return int(r['status']!='complete_unqualified')


if __name__=='__main__':
    raise SystemExit(main())
