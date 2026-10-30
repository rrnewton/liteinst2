#!/usr/bin/env python3
"""One real LS first-refusal diagnostic; no qualification or timing comparison.

Fresh committed-source build and unchanged mandatory byte oracle precede the
single bounded subject. Counter failures never become accepted observations.
"""
import argparse,csv,hashlib,importlib.util,io,json,os,re,struct,subprocess,sys,types
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
SCRIPT='evaluation/inprocess/linked_graph_observe.py'
PROGRAM=[30,512<<20,16<<20,60]
SHORT=[5,512<<20,16<<20,15]
LABEL='LI2_LINKED_GRAPH_OBSERVE '
REASONS=('initial_enqueue_invariant','enqueue_outside_page','queue_capacity',
    'source_byte_overlap','unsupported_frontier_capacity','supported_head_capacity',
    'empty_supported_heads','no_unsupported_frontier','unresolved_primary_successor',
    'unresolved_conditional_fallthrough','kahn_stall','zero_distance','incoming_edge_underflow')
H=lambda b:hashlib.sha256(b).hexdigest()
D=lambda v:H(json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode())
EXPECTED={'tools/page-entry/selected/linked_plan.c': {'bytes': 15028, 'sha256': 'd6557b1be3b3d428dd934955f97614da7900553a72ced43cd90a16d5f46086e8'}, 'tools/page-entry/selected/linked_plan.h': {'bytes': 3066, 'sha256': '8937bb2bb857c05faddd72dd172e63c4b858bf7db973f11a08fc48758b5f10ab'}, 'tools/page-entry/selected/linked_controller.inc': {'bytes': 54073, 'sha256': '1e30ba15d5ff68979479f36e1bbe1f3a087590351ec1ab80b885446307770bfd'}, 'tools/page-entry/selected/build-linked-epoch-graph-observe.sh': {'bytes': 3241, 'sha256': 'bbfd95c4b579e5fba9b41f7d438c396083255cc28dbf6ae337d8b9c6fcfad25d'}, 'evaluation/inprocess/linked_epoch_build.py': {'bytes': 17509, 'sha256': '3662a10021fdc587a3ffac647b5c2a72be7fe2f315708f983a53269a1a16fc71'}, 'tools/page-entry/selected/linked_native_hint.h': {'bytes': 2801, 'sha256': '0e04619eb32696e610d5c854b5314b07f9e372709863ccf6a540188f76011436'}, 'tools/page-entry/selected/linked_native_hint.inc': {'bytes': 10182, 'sha256': '8819d244d60d89ecdf18701c58658a955de06bc1647bebeffb28055d524e9f52'}, 'tools/page-entry/selected/build-linked-epoch-native-hint.sh': {'bytes': 3214, 'sha256': '35c9ea90f467bcf5b2a06811ec9ef68d29f57c3a65d7a142c66e175dc9687197'}, 'tools/page-entry/selected/runtime_loader.c': {'bytes': 53639, 'sha256': '10161f612e4d9d1b6702dba4bf644bc724abe1c01b2caf490cbb84ba4a138975'}}

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
    for label in ('LI2_LINKED_EPOCH', 'LI2_LINKED_NATIVE_HINT', 'LI2_MAPS_VIEW', 'LI2_NATIVE'):
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
    linked = result['LI2_LINKED_EPOCH']
    need(linked.get('version') == 1 and linked.get('status') == 0 and
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
    prefix=LABEL.encode();lines=[x for x in stderr.splitlines()if x.startswith(prefix)]
    need(len(lines)==1 and len(lines[0])<=1024,'one complete graph observation row')
    def pairs(items):
        need(len(items)==len(dict(items)),'no duplicate graph observation keys')
        return dict(items)
    row=json.loads(lines[0][len(prefix):],object_pairs_hook=pairs)
    need(type(row)is dict and list(row)==['version','status','failure_code','overflow','reasons'],
         'exact graph observation schema')
    need(all(type(row[k])is int and 0<=row[k]<1<<64 for k in ('version','status','failure_code','overflow'))and
         type(row['reasons'])is list and len(row['reasons'])==13 and
         all(type(v)is int and 0<=v<1<<64 for v in row['reasons']),'exact unsigned graph values')
    need(prefix+json.dumps(row,separators=(',',':'),allow_nan=False).encode()==lines[0],
         'canonical complete graph observation row')
    need(row['version']==1 and row['status']==row['failure_code']==0,
         'actual completed graph observation outcome')
    need(row['overflow']==0,'graph observation overflow is not measurable')
    need(linked['status']==linked['failure_code']==linked['first_error']==0 and
         sum(row['reasons'])==linked['refusals'][2],
         'all first GRAPH refusals equal actual error-free cold refusals')
    return row


def observation_controls(stderr,linked):
    """Small supplied report corruptions, never additional native cases."""
    row=observation(stderr,linked);prefix=LABEL.encode()
    original=next(x for x in stderr.splitlines()if x.startswith(prefix));names=[]
    def reject(name,value,message):
        changed=prefix+json.dumps(value,separators=(',',':'),allow_nan=False).encode()
        forged=stderr.replace(original,changed,1)
        try:observation(forged,linked)
        except ValueError as e:need(str(e)==message,'specific supplied graph refusal: '+name)
        else:raise ValueError('accepted supplied graph corruption: '+name)
        names.append(name)
    for i,name in enumerate(REASONS):
        value=json.loads(json.dumps(row));value['reasons'][i]=(value['reasons'][i]+1)%(1<<64)
        reject(name,value,'all first GRAPH refusals equal actual error-free cold refusals')
    for name,key,value,message in (
        ('overflow','overflow',1,'graph observation overflow is not measurable'),
        ('version','version',2,'actual completed graph observation outcome'),
        ('status','status',1,'actual completed graph observation outcome'),
        ('failure','failure_code',1,'actual completed graph observation outcome'),
        ('typed_version','version',True,'exact unsigned graph values'),
        ('reason_count','reasons',row['reasons']+[0],'exact unsigned graph values')):
        altered=dict(row);altered[key]=value;reject(name,altered,message)
    for name,forged in (('missing',stderr.replace(original+b'\n',b'',1)),
                        ('duplicate',stderr+original+b'\n')):
        try:observation(forged,linked)
        except ValueError as e:need(str(e)=='one complete graph observation row','specific row population refusal')
        else:raise ValueError('accepted supplied row population corruption')
        names.append(name)
    need(len(names)==21 and len(set(names))==21,'fixed21 supplied observation refusals')
    return names


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
    wanted={b'link_graph_counts',b'li2_link_graph_observation'}
    for at in range(t[4],t[4]+t[5],24):
        name,info,other,section,address,size=struct.unpack('<IBBHQQ',take(at,24))
        need(name<len(names)and b'\0'in names[name:],'complete symbol name')
        name=names[name:names.index(b'\0',name)]
        if name in wanted:
            need(name not in found and 0<section<len(sh),'one defined actual observation symbol')
            expected=6 if name==b'link_graph_counts'else 5
            loads=[(i,x)for i,x in enumerate(ph)if x[0]==1 and x[1]==expected and
                   x[3]<=address and size>0 and address-x[3]+size<=x[6]]
            need(len(loads)==1,'whole observation symbol in exact compiled RW/NX or RX load')
            if name==b'link_graph_counts':
                need(info&15==1 and size==112 and address%8==0 and sh[section][1]==8 and
                     sh[section][2]&3==3,'actual exact112-byte zero-initialized observation object')
            else:need(info&15==2 and size>0,'actual callable observation getter')
            found[name.decode()]=dict(address=address,bytes=size,load_index=loads[0][0],flags=expected)
    need(set(found)=={x.decode()for x in wanted},'complete compiled observation getter/store')
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
    r=dict(schema=1,scope='UNQUALIFIED_LINKED_GRAPH_FIRST_REFUSAL_ONLY',qualification_credit=False,
        timing_credit=False,aggregate_credit=False,source_revision=a.revision,cpu=cpu,hardware=hardware(cpu),
        bounds=dict(PROFILES,metadata=PROGRAM,build_metadata=PROFILES['metadata'],program=PROGRAM,
                    release_build=PROGRAM,finite=SHORT),commands=[],inputs={},artifacts={},aliases={},namespace_aliases={},
        case=dict(name='graph-ls',status='not_run'),error=None,final_errors=[],source_unchanged=False,cleanup_complete=False)

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
        row=dict(name=name,argv=list(map(str,argv)),profile=profile,bounds=r['bounds'][profile],
                 expected_exit=expected,capture_limit=16<<20,environment=dict(ENV if env is None else env))
        r['commands'].append(row)
        try:stdout,stderr=(program_invoke if name=='graph-ls'else invoke)(row,out,cpu,record=record,step=step)
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
                                        native_hint=True,graph_observe=True)
        r['compiled_observation']=compiled_observation(bridge.read_bytes())
        (out/'external-inputs').mkdir()
        state=pair.prepare_workload('graph-ls','/bin/ls',['-d','.'],bridge,builder,out,pin,binary,run,r,namespace)
        ns=out/'graph-ls-namespace';tools=builder.tools
        argv=[tools['python'],'-B',state['carrier_tool'],'exec-loader','--library-root','/usr/lib64',
              '--namespace',ns,state['carrier'],state['original'],'--',*state['argv']]
        case=r['case'];case['status']='failed';start=len(r['commands'])
        try:
            row,stdout,stderr=run('graph-ls',argv,profile='program',expected=None,env=pair.PROGRAM_ENV)
            need(row['exit']==0,'actual diagnostic subject must exit zero')
            need(stdout==b'.\n','exact full LS stdout')
            pair.namespace_join(state,ns,binary,r,namespace)
            raw=counters(stderr,True);graph=observation(stderr,raw['LI2_LINKED_EPOCH'])
            controls=observation_controls(stderr,raw['LI2_LINKED_EPOCH'])
            case.update(status='observed_unqualified',raw_counters=raw,graph_observation=graph,
                        supplied_refusals=controls)
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
        c=r['case'];raw=c.get('raw_counters',{});le=raw.get('LI2_LINKED_EPOCH',{});hint=raw.get('LI2_LINKED_NATIVE_HINT',{})
        view=raw.get('LI2_MAPS_VIEW',{});native=raw.get('LI2_NATIVE',{});graph=c.get('graph_observation')
        row=dict(name=c['name'],status=c['status'],exit=c.get('exit'),process_ns=c.get('process_ns'),
            timed_out=c.get('timed_out'),events=le.get('events'),traps=le.get('signals',[None]*5)[1],
            offers=le.get('offers'),entries=le.get('entries'),graph_refusals=le.get('refusals',[None]*4)[2],
            refaults=le.get('refaults'),graph_refaults=le.get('graph_refaults'),hint_hits=hint.get('hits'),
            hint_admitted=hint.get('admitted'),hint_refused=hint.get('refused'),
            maps_queries=view.get('queries'),maps_hits=view.get('hits'),maps_refreshes=view.get('refreshes'),
            maps_comparisons=view.get('comparisons'),maps_fresh=view['refreshes']+view['comparisons']if view else None,
            maps_updates=view.get('updates'),maps_invalidations=view.get('invalidations'),maps_unexplained=view.get('unexplained'),
            total_native_attempts=native.get('attempts'),total_native_admissions=native.get('admissions'),
            total_native_closed=native.get('closed'),observation_overflow=graph['overflow']if graph else None,
            supplied_refusals=len(c.get('supplied_refusals',[])))
        row.update({name:graph['reasons'][i]if graph else None for i,name in enumerate(REASONS)})
        hw=dict(r['hardware']);flags=hw.pop('isa_flags');hw.update(isa_flags_count=len(flags),isa_flags_sha256=D(flags))
        summary=dict(scope=r['scope'],status=r['status'],source_revision=a.revision,cpu=cpu,hardware=hw,bounds=r['bounds'],
            qualification_credit=False,timing_credit=False,aggregate_credit=False,row=row,
            reproduction_argv=['python3','-B',SCRIPT,'--revision',a.revision,'--output','${PRIVATE_OUTPUT}'],
            reproduction_environment='One externally reserved CPU; each child uses its recorded original hard bounds.',
            driver=manifest['driver'],source_manifest=fact(out/'source-manifest.json'),archive=r.get('archive'),
            input_count=len(r['inputs']),inputs_sha256=D(r['inputs']),artifact_count=len(r['artifacts']),artifacts_sha256=D(r['artifacts']),
            command_count=len(r['commands']),commands_sha256=D(r['commands']),cleanup_complete=r['cleanup_complete'],
            source_unchanged=r['source_unchanged'],receipt=fact(out/'receipt.json'),
            count_scope='First actual GRAPH returns across all planner calls; complete error-free sum equals cold refusals. No-frontier is not cycle evidence. No protected storage, native qualification, timing comparison or saved-event credit.')
        text=json.dumps(summary,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
        stream=io.StringIO();writer=csv.DictWriter(stream,fieldnames=list(row),lineterminator='\n');writer.writeheader();writer.writerow(row)
        need(len(text.encode())<=16<<10 and len(stream.getvalue().encode())<=8<<10 and
             all(x not in text+stream.getvalue()for x in (str(ROOT),str(Path.home()),'/home/')),'bounded numeric summary without private paths')
        (out/'summary.json').write_text(text);(out/'summary.csv').write_text(stream.getvalue())
    return int(r['status']!='complete_unqualified')


if __name__=='__main__':
    raise SystemExit(main())
