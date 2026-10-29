"""Three additive actual registered-store controls; original17 checker stays exact."""
import hashlib,json,os,struct,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2]
HERE=ROOT/'evaluation/inprocess'
if str(HERE) not in sys.path:sys.path.insert(0,str(HERE))
from page_selected import ENV,fact,need,interpreter
from page_selected_rseq_prepare import prepare
from page_selected_rseq_build import _link,FIXTURE as OLD_FIXTURE
import page_selected_rseq_application_compare as old
import page_selected_rseq_application_images as images

FIXTURE=ROOT/'tools/page-entry/selected/tests/vmovdqa64_store_rseq'
IMAGE='evaluation/inprocess/page_selected_rseq_application_images.py'
OBSERVER='tools/page-entry/selected/tests/rseq_application/observe.c'
COMPARE='evaluation/inprocess/page_selected_rseq_application_compare.py'
STORE_WORDS=(0x1122334455667788,images.DATA+1024,0x1021324354657687,0x98a9bacbdcedfe0f,0x0123456789abcdef,0xfedcba9876543210,0x0f1e2d3c4b5a6978,0x8877665544332211)
INDICES=(1,6,5)
NAMES=('disjoint','sse_overlap','trace_mov_overlap')
MAGIC=0x3152465453515256
PREFIX=13312
TRAILER=8944

def configuration(family):
    need(type(family)is int and family in (1838,1847),'one explicit registered store family')
    if family==1838:
        return dict(fixture=FIXTURE,magic=MAGIC,code=1838,literal='62e1fd487f0f',destination=192,
                    overlap=images.WORD-8,key='store_rseq',label='store-rseq')
    return dict(fixture=ROOT/'tools/page-entry/selected/tests/vmovdqu64_store_rseq',
                magic=0x3152465453514456,code=1847,literal='62e1fe487f0f',destination=321,
                overlap=images.WORD-7,key='store_rseq_1847',label='store-rseq-1847')

def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()

def adapted(path,source,manifest):
    need(fact(ROOT/path)==manifest['inputs'][path],'unchanged old source authority')
    original=source;used=[]
    for op in manifest['operations']:
        if op['path']!=path:continue
        before,after=op['before'].encode(),op['after'].encode()
        need(hashlib.sha256(source).hexdigest()==op['before_sha256'] and source.count(before)==op['count']==1,
             'exact observation or derived-image input span')
        source=source.replace(before,after)
        need(hashlib.sha256(source).hexdigest()==op['after_sha256'],'exact adapted output span');used.append(op)
    restored=source
    for op in reversed(used):
        before,after=op['before'].encode(),op['after'].encode()
        need(restored.count(after)==1,'unique full inverse');restored=restored.replace(after,before)
    need(restored==original and used,'complete original source recovered')
    return source

def generate(out,cpu,family=1838):
    """Metadata-only image generation; no generated image is executed here."""
    need(not sys.flags.optimize and type(cpu)is int and 0<=cpu<1<<31,'literal CPU')
    out=Path(out).resolve();need(out.is_relative_to(ROOT/'target')and not out.exists(),'unique private images')
    cfg=configuration(family)
    out.mkdir(parents=True);manifest=old.decode((cfg['fixture']/'ADAPTERS.json').read_bytes())
    data=adapted(IMAGE,(ROOT/IMAGE).read_bytes(),manifest)
    derived=out/'derived-images.py';derived.write_bytes(data)
    # Same module globals/path and all original helpers. Only the exact bound
    # source spans above differ; its original main remains uncalled.
    namespace=dict(vars(images));namespace['__name__']='store_rseq_derived_images'
    exec(compile(data,str(derived),'exec'),namespace)
    rows=[]
    for i in INDICES:
        spec=namespace['program'](i,cpu)
        actual=namespace['emit_one'](out/images.NAMES[i],spec)
        prefix=namespace['emit_one'](out/(images.NAMES[i]+'-native-prefix'),namespace['program'](i,cpu,True))if i!=1 else None
        rows.append(dict(actual=actual,native_prefix=prefix))
    (out/'images.json').write_text(json.dumps(rows,sort_keys=True,indent=2)+'\n')

def target(spec,family=1838):
    cfg=configuration(family)
    rows=[x for x in spec['rows']if x['name']==('sse_store'if spec['index']==1 else 'forbidden_operation')]
    need(len(rows)==1 and rows[0]['bytes']==cfg['literal'],'one literal original-PC store')
    return rows[0]['pc']

def check(spec,row,stdout,stderr,data,native_stdout,schema,compare,family=1838):
    cfg=configuration(family)
    need(len(data)==PREFIX+TRAILER,'complete old prefix and separate actual store trailer')
    result=compare(spec,row,stdout,stderr,data[:PREFIX],native_stdout,schema)
    raw=data[PREFIX:];h=struct.unpack_from('<40Q',raw)
    before=struct.unpack_from('<23Q',raw,320);after=struct.unpack_from('<23Q',raw,504)
    code=raw[688:704];f=struct.unpack_from('<4Q4I',raw,704)
    pages=(raw[752:4848],raw[4848:8944]);mode=INDICES.index(spec['index']);pc=target(spec,family)
    error=0 if mode==0 else 1205;first=images.AREA_PAGE+cfg['destination'] if mode==0 else cfg['overlap']
    need(h[:7]==(cfg['magic'],1,TRAILER,spec['index'],1,1,error)and h[7:11]==(pc,pc+6,cfg['code'],6),
         'exact once-returned real registered guard observation and outcome')
    need(6<=h[11]<=15 and code[:6]==bytes.fromhex(cfg['literal'])and
         code[:h[11]]==bytes.fromhex(spec['code_hex'])[pc-images.MAIN:pc-images.MAIN+h[11]],
         'complete available actual source bytes, no invented instruction')
    need(h[20:25]==(1,1,3,row['pid'],row['pid'])and h[25]+1==h[26]and h[27]+1==h[28],
         'actual registered/held owner and exactly one real instruction/RANGE guard')
    need(before==after and h[14]==h[15]and h[16]==h[17]and h[18]==h[19],
         'all23 saved registers/flags/mask unchanged; no RAW or RX opening during guard')
    need(before[16]==pc and before[8]==first and before[20]==h[12]and before[19]==h[13],
         'actual before-RIP/RDI and signal frame association')
    # The positive can use either existing authenticated ingress; the two
    # negative images deliberately require NX and genuine predecessor TRACE.
    need((h[12],h[13])in ((14,21),(1,0))and(mode==0 or h[12]==spec['trap']),
         'genuine NX/TRACE frame; exact failure ingress preserved')
    need(h[31:36]==(pc,cfg['code'],2,first,first+64)and
         f==(pc,pc+6,first,first+64,1,2,cfg['code'],6),
         'actual production last_footprint RANGE64, independently from before-RDI')
    need(h[36:]==(mode,1,1,0),'complete page observations and reserved tail')
    mutable=set(range(64,72))|set(range(84,92))
    need(all(pages[0][i]==pages[1][i]for i in range(4096)if i not in mutable),
         'complete guard data-page non-kernel bytes unchanged')
    need(pages[0][72:80]==pages[1][72:80]==bytes(8),'publication word remains zero before effect')
    if mode:
        old_h=struct.unpack_from('<128Q',data)
        need(before==old_h[40:63]and after==old_h[63:86]and code==struct.pack('<QQ',*old_h[88:90])and
             pages[0]==data[1024:5120]and pages[1]==data[5120:9216],
             'exact independently recorded old/new guard frame, bytes and whole-page views')
    else:
        need(spec['target_pc']==0 and row['exit']==0,'old successful whole-application protocol preserved')
        start=cfg['destination'];end=start+64
        need(pages[0][start:end]==pages[1][start:end]==bytes(64)and
             data[9216+start:9216+end]==struct.pack('<8Q',*STORE_WORDS),
             'real store changes64 initially-zero bytes only after the successful guard')
    result['store_guard']=dict(mode=mode,code=cfg['code'],policy=2,length=6,first=first,end=first+64,
        guard_result=error,actual_trap=h[12],guard_calls=1,raw_calls_during_guard=h[17]-h[16],
        rx_calls_during_guard=h[19]-h[18],full_trailer_sha256=hashlib.sha256(raw).hexdigest())
    return result

def registered_controls(builder,products,private,pin,binary,run,receipt,cpu,family=1838):
    """Use shared Build/products; caller owns global final source/capture closure."""
    cfg=configuration(family);fixture=cfg['fixture']
    private=Path(private)/cfg['label'];private.mkdir(exist_ok=False)
    state=receipt[cfg['key']]=dict(status='failed',cases=[],commands=[],private_build={},final_errors=[])
    pending=[];source_tree=private/'source'
    def observed_run(name,argv,expected=0,profile='native',env=None,record=False):
        label=cfg['label']+'-'+name;state['commands'].append(label)
        return run(label,argv,expected,profile=profile,env=env,record=record)
    def retain(path):
        if path.exists()or path.is_symlink():binary(path)
    try:
        pin(Path(__file__));manifest=old.decode(pin(fixture/'ADAPTERS.json').read_bytes())
        pin(ROOT/IMAGE);pin(ROOT/OBSERVER);pin(ROOT/COMPARE)
        compare_source=adapted(COMPARE,(ROOT/COMPARE).read_bytes(),manifest)
        compare_path=private/'derived-compare.py';compare_path.write_bytes(compare_source);binary(compare_path)
        comparison=dict(vars(old));comparison['__name__']='store64_rseq_derived_compare'
        exec(compile(compare_source,str(compare_path),'exec'),comparison)
        selected=prepare(source_tree,pin)
        observer=selected/'observe.c';before=fact(observer)
        observer.write_bytes(adapted(OBSERVER,observer.read_bytes(),manifest))
        extra=selected/'store_observe.inc';extra.write_bytes(pin(fixture/'observe.inc').read_bytes())
        composition=dict(old_preparation=fact(source_tree/'COMPOSITION.json'),observer_before=before,
            observer_after=fact(observer),extra=fact(extra),adapters=fact(fixture/'ADAPTERS.json'))
        (source_tree/'STORE-COMPOSITION.json').write_text(json.dumps(composition,sort_keys=True,indent=2)+'\n')
        for p in sorted(source_tree.rglob('*')):
            if p.is_file():pin(p);binary(p)
        state['private_build']['composition']=composition
        bridge=private/'bridge-store-rseq.so';pending.append(bridge)
        build=state['private_build'];build['final_errors']=state['final_errors']
        _link(builder,products,selected,OLD_FIXTURE/'build.sh',bridge,pin,binary,observed_run,build,True)
        schema=old.decode(pin(HERE/'page_selected_rseq_schema.json').read_bytes())
        image_dir=private/'images';pending.extend([image_dir/'images.json',image_dir/'derived-images.py'])
        for name in NAMES:
            for suffix in ('','-native-prefix')if name!='disjoint'else ('',):
                pending.extend(image_dir/(name+suffix)/n for n in ('original','interpreter.so','li2-stream.so'))
        observed_run('generate',[builder.tools['python'],Path(__file__),'--images',image_dir,cpu]+([]if family==1838 else[1847]),profile='metadata',env=builder.environment)
        catalogue=old.decode(binary(image_dir/'images.json').read_bytes());binary(image_dir/'derived-images.py')
        need(len(catalogue)==3 and [x['actual']['index']for x in catalogue]==list(INDICES)and
             [x['actual']['name']for x in catalogue]==list(NAMES),'exact three additive store cases')
        for item in catalogue:
            spec=item['actual'];name=spec['name'];case=dict(name=name,accepted=False);state['cases'].append(case)
            target(spec,family);original=binary(Path(spec['original']));ip=binary(Path(spec['interpreter']))
            need(interpreter(original)==ip and fact(original)['sha256']==spec['original_sha256']and
                 fact(ip)['sha256']==spec['interpreter_sha256'],'actual literal ELF and independent interpreter identity')
            binary(Path(spec['library_root'])/'li2-stream.so')
            nspec=item['native_prefix']or spec
            native=binary(Path(nspec['original']));binary(Path(nspec['interpreter']));binary(Path(nspec['library_root'])/'li2-stream.so')
            need((item['native_prefix']is None)==(spec['index']==1),'only disjoint native program executes the store')
            if spec['index']!=1:
                need(nspec['prefix_only']and not any(x['name']=='forbidden_operation'for x in nspec['rows']),
                     'dangerous native baseline stops before publication')
            row,out,err=observed_run('native-'+name,[native],record=True)
            capture=Path(private.parent)/row['captures']['record']['file']
            need(not err and binary(capture).read_bytes()==b'','native baseline has no fabricated guard report')
            old.output(nspec,out);native_stdout=out
            case['native_kind']='complete_operation'if spec['index']==1 else 'stopped_before_forbidden_operation'
            carrier=private/('carrier-'+name);pending.append(carrier)
            try:observed_run('make-'+name,[builder.tools['python'],ROOT/'tools/page-entry/carrier.py','make',original,bridge,carrier],profile='metadata',env=builder.environment)
            finally:
                try:retain(carrier)
                except BaseException as exc:state['final_errors'].append('partial carrier retention: '+repr(exc))
            binary(carrier);namespace=private/('namespace-'+name)
            pending.extend([namespace/'namespace.json',namespace/'launch.json'])
            row,out,err=observed_run('gated-'+name,[builder.tools['python'],ROOT/'tools/page-entry/carrier.py','exec-loader',
                '--library-root',spec['library_root'],'--namespace',namespace,carrier,original,'--',original],
                expected=spec['expected_exit'],record=True)
            capture=binary(private.parent/row['captures']['record']['file'])
            case.update(check(spec,row,out,err,capture.read_bytes(),native_stdout,schema,comparison['check'],family))
            ns=old.decode(binary(namespace/'namespace.json').read_bytes());launch=old.decode(binary(namespace/'launch.json').read_bytes())
            need(launch['carrier_sha256']==fact(carrier)['sha256']and'GLIBC_TUNABLES'not in launch['environment'],
                 'fresh actual registration environment, no libc masking')
            for obj in ns['objects']:
                need(obj['seals']==15 and fact(pin(obj['source']))['sha256']==obj['sha256'],'actual sealed dependency identity')
            case['namespace']={n:fact(namespace/n)for n in ('namespace.json','launch.json')}
        need(len(state['cases'])==3 and all(c['accepted']for c in state['cases'])and
             [c['operation_exit']for c in state['cases']]==[0,125,125]and len(state['commands'])==14,
             'one complete registered store and two genuine pre-effect refusals, all14 commands')
        need(not state['final_errors']and build['rseq_build']['status']=='passed','complete observed source/build closure')
        state['status']='passed_three_store_controls'
    finally:
        for p in pending:
            try:retain(p)
            except BaseException as exc:state['final_errors'].append('retained partial artifact: '+repr(exc))
        if source_tree.exists():
            for p in sorted(source_tree.rglob('*')):
                if p.is_file():
                    try:binary(p)
                    except BaseException as exc:state['final_errors'].append('source artifact: '+repr(exc))
        receipt['final_errors'].extend(state['final_errors'])
        if state['final_errors']:state['status']='failed'
    return state

def summary(receipt,family=1838):
    cfg=configuration(family);s=receipt[cfg['key']]
    return dict(status=s['status'],required_cases=3,completed_operations=sum(c.get('outcome')=='completed'for c in s['cases']),
        required_refusals=sum(c.get('outcome')=='required_refusal'for c in s['cases']),cases=s['cases'],
        command_count=len(s['commands']),build_sha256=digest(s['private_build']),final_error_count=len(s['final_errors']),
        scope=('Three additive registered VMOVDQA64-store controls; original17 remains a separate mandatory cohort. No active critical sections or complete B3 claim.'if family==1838 else'Three additive registered Code1847 unaligned full64-byte stores: disjoint plus actual NX and predecessor TRACE overlap refusals. Original1838 three and original17 remain mandatory. No active critical sections or complete B3 claim.'))

if __name__=='__main__':
    need(len(sys.argv)in (4,5) and sys.argv[1]=='--images','only literal metadata generator mode')
    generate(Path(sys.argv[2]),int(sys.argv[3]),int(sys.argv[4])if len(sys.argv)==5 else 1838)
