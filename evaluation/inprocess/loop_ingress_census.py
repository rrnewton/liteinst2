#!/usr/bin/env python3
"""One maintained case0/placement0 ingress census, followed by offline source joins.

Reserve one CPU and use Python3.12, a clean expected revision, and fresh output.
Supply the actual closed native receipt and failed six-command smoke receipts
with their whole SHA256 values. Reuses the unchanged archive/fixture inputs,
builds the distinct current maintained census bridge, then runs one subject.
All original child bounds and terminal checks remain; no owner qualification or
performance credit. TRACE ingress is a destination, never a guessed producer.
"""
import argparse, hashlib, json, os, platform, re, shutil, struct, subprocess, sys
from pathlib import Path
from types import SimpleNamespace
sys.dont_write_bytecode = True
ROOT = Path.cwd().resolve()
sys.path[:0] = [str(ROOT/'evaluation/inprocess'), str(ROOT/'tools/page-entry')]
from checks import source
from run import hardware
from page_selected import ENV, fact, need, save, elf
from page_selected_process import invoke
from page_selected_effect_ls import program_invoke
from persistent_dynamic import imported_sources
from direct_frontier_loop_helpers import prepare_inputs
from persistent_loop_native_build import preparation
from persistent_loop_counter_terminal import split
from persistent_fused_counter_terminal import counters

SELECTED = ROOT/'tools/page-entry/selected'
BOUNDS = [30, 512 << 20, 16 << 20, 60]
LANES = (('maintained', 'ingress'),)
H = lambda b: hashlib.sha256(b).hexdigest()


PREFIX = b'LI2_LOOP_INGRESS '


def census(stderr):
    """Remove exactly one complete typed final row; preserve all old bytes."""
    need(type(stderr) is bytes and stderr.endswith(b'\n'), 'complete census terminal')
    lines = stderr.splitlines(keepends=True)
    need(len(lines)>1 and lines[-1].startswith(PREFIX) and
         sum(x.startswith(PREFIX) for x in lines)==1, 'one final census row')
    def pairs(items):
        value={}
        for k,v in items:
            need(k not in value,'no duplicate census JSON key');value[k]=v
        return value
    c=json.loads(lines[-1][len(PREFIX):],object_pairs_hook=pairs)
    keys=('version','status','failure_code','initialized','sealed','error','capacity','total','overflow','used',
          'signals','start','end','bias','sites')
    need(type(c) is dict and tuple(c)==keys and
         lines[-1]==PREFIX+json.dumps(c,separators=(',',':'),allow_nan=False).encode()+b'\n',
         'exact canonical census keys and encoding')
    def uint(v):return type(v) is int and 0<=v<1<<64
    need(all(uint(c[k]) for k in keys[:10]) and
         [c[k] for k in keys[:7]]==[1,0,0,1,1,0,1024] and 0<c['total'] and c['used']<=1024,
         'complete successful bounded census; arithmetic/initialization failure refuses')
    for k,n in (('signals',5),('start',6),('end',6),('bias',3)):
        need(type(c[k]) is list and len(c[k])==n and all(uint(v) for v in c[k]), 'whole '+k)
    need(type(c['sites']) is list and len(c['sites'])==c['used'], 'all retained table rows')
    seen=set();last=-1;signals=[0]*5;retained=0
    for row in c['sites']:
        need(type(row) is list and len(row)==11,'complete census key/count row')
        slot,pc,sig,code,route,producer,count,d,encoded,n,pages=row
        need(all(uint(v) for v in (slot,pc,route,producer,count,n)) and last<slot<1024 and
             type(sig) is type(code) is int and 1<=sig<=64 and -(1<<31)<=code<1<<31 and
             producer in (0,1,2) and count>0 and type(d) is list and len(d)==12 and all(uint(v) for v in d) and
             type(encoded) is str and re.fullmatch('[0-9a-f]{32}',encoded) and type(pages) is list and len(pages)==2 and
             all(type(p) is list and len(p)==6 and all(uint(v) for v in p) for p in pages), 'typed whole census site')
        key=json.dumps(row[1:6]+row[7:],separators=(',',':'))
        need(key not in seen,'unique exact tuple');seen.add(key);last=slot
        if producer:
            need(sig==5 and code==2 and d[2:4]==[1,0] and d[5]==d[11]==0 and d[4]>0 and
                 1<=d[10]<=d[9]<=15 and d[1]==d[0]+d[10] and n in (1,2) and
                 n==1+int(d[0]//4096!=(d[1]-1)//4096), 'actual running predecessor descriptor geometry')
            for i,p in enumerate(pages):
                need((p[0]==(d[0]&~4095)+i*4096 and p[1]>0 and p[2]>0 and p[4:]==[1,5]) if i<n else p==[0]*6,
                     'actual owned source page keys or exact zero unused page')
        else:need(d==[0]*12 and encoded=='00'*16 and n==0 and pages==[[0]*6]*2,'explicit whole unknown predecessor')
        signals[{11:0,5:1,4:2,31:3}.get(sig,4)]+=count;retained+=count
    need(retained+c['overflow']==c['total']==sum(c['signals']) and
         all(a<=b for a,b in zip(signals,c['signals'],strict=True)) and
         sum(b-a for a,b in zip(signals,c['signals'],strict=True))==c['overflow'], 'exact retained/overflow and signal partitions')
    need([b-a for a,b in zip(c['start'],c['end'],strict=True)]==[c['total'],*c['signals']],
         'every post-initialization linked ingress reached the accepted handler guard')
    original=b''.join(lines[:-1]);loop,old=split(original);raw=counters(old)
    need(c['end']==[raw['LI2_LINKED_EPOCH']['events'],*raw['LI2_LINKED_EPOCH']['signals']],
         'actual whole terminal event count and signal cells')
    return c,original,loop,raw


def classify(c,out,baseline,native,original,interp,pin,binary,run,private):
    """Offline actual ELF/source-byte joins, never backward-decode post-RIP."""
    need(len(out)==len(baseline)==len(native)==8588824,'complete actual fixture stdout extent')
    h=struct.unpack_from('<64Q',out);old=struct.unpack_from('<64Q',baseline);nh=struct.unpack_from('<64Q',native)
    need(h[:6]==old[:6]==(0x32504c5032494c,2,18944,8569880,0,0) and
         h[10:26]==old[10:26] and h[30:]==old[30:] and
         h[:5]==nh[:5] and h[10:26]==nh[10:26] and h[30:48]==nh[30:48] and
         h[10:12]==(0x4000200,0x4000000) and h[48]==1,'same actual case0/placement0 paired geometry')
    source=out[2336:10528]
    need(source==baseline[2336:10528]==native[2336:10528] and
         out[18944+4920:18944+13112]==source,'whole actual initialized source retained unchanged through completion')
    need(c['bias'][0]==0,'actual ET_EXEC source has zero bias')
    images=[];instructions={};objdump=pin(shutil.which('objdump',path=ENV['PATH']))
    for role,path,bias in (('original',original,c['bias'][0]),('interpreter',interp,c['bias'][1])):
        data,head,ph=elf(path)
        need(head[1:4]==((2,62,1) if role=='original' else (3,62,1)), 'actual ELF source class')
        loads=[p for p in ph if p[0]==1 and p[1]==5]
        need(loads and all(p[2]+p[5]<=len(data) for p in loads),'complete actual RX file ranges')
        images.append((role,bias,data,loads))
        _,assembly,err=run('disassemble-'+role,[objdump,'-d','-w','-M','att',path],profile='metadata')
        need(not err and assembly,'actual source ELF disassembly')
        for line in assembly.decode().splitlines():
            m=re.fullmatch(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)',line)
            if not m:continue
            at=int(m[1],16);chunk=bytes.fromhex(m[2]);owners=[p for p in loads if p[3]<=at and at+len(chunk)<=p[3]+p[5]]
            need(len(owners)==1 and chunk,'one actual executable instruction byte range')
            p=owners[0];offset=p[2]+at-p[3]
            need(data[offset:offset+len(chunk)]==chunk and at+bias not in instructions,'whole disassembler/ELF byte join')
            instructions[at+bias]=(chunk,m[3].strip())
    blob=private/'actual-loop-source.bin';blob.write_bytes(source);binary(blob)
    _,assembly,err=run('disassemble-loop',[objdump,'-D','-w','-b','binary','-m','i386:x86-64','-M','att',
        '--adjust-vma='+hex(h[11]),'--start-address='+hex(h[10]-5),'--stop-address='+hex(h[10]+94),blob],profile='metadata')
    need(not err and assembly,'actual E9, 88-byte loop and six-byte cut disassembly; no inline literal bytes')
    for line in assembly.decode().splitlines():
        m=re.fullmatch(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)',line)
        if not m:continue
        at=int(m[1],16);chunk=bytes.fromhex(m[2]);offset=at-h[11]
        need(h[10]-5<=at<at+len(chunk)<=h[10]+94 and source[offset:offset+len(chunk)]==chunk and
             at not in instructions,'actual loop instruction extent excludes all target-literal bytes')
        instructions[at]=(chunk,m[3].strip())
    def locate(pc,length=1):
        found=[]
        for role,bias,data,loads in images:
            for p in loads:
                at=pc-bias
                if p[3]<=at and at+length<=p[3]+p[5]:
                    offset=p[2]+at-p[3];found.append((role,at,offset,data[offset:offset+length]))
        if h[11]<=pc and pc+length<=h[11]+8192:
            offset=pc-h[11];found.append(('fixture_source',offset,offset,source[offset:offset+length]))
        need(len(found)<=1,'unambiguous actual source range')
        return found[0] if found else None
    result=[];groups={};ingresses={};known=0
    for row in c['sites']:
        _,pc,sig,code,route,producer,count,d,encoded,n,pages=row
        entry=dict(pc=pc,signal=sig,si_code=code,route=route,count=count,predecessor_owner=producer,
                   ingress_semantics='post_instruction_destination' if (sig,code)==(5,2) else 'signal_ingress_pc')
        ingress=locate(pc)
        instruction=instructions.get(pc)
        entry['ingress_source']=None if ingress is None else dict(role=ingress[0],offset=ingress[1],
            instruction=None if instruction is None else instruction[1],
            bytes=None if instruction is None else instruction[0].hex())
        ikey=('unknown',pc,sig,code,None) if ingress is None else (ingress[0],ingress[1],sig,code,
            None if instruction is None else instruction[1])
        ingresses[ikey]=ingresses.get(ikey,0)+count
        entry['producer']=None
        if producer:
            owner=locate(d[0],d[9]);decoded=bytes.fromhex(encoded)
            if owner is not None:
                need(owner[3]==decoded[:d[9]],'every recorded predecessor byte equals its actual immutable source')
                instruction=instructions.get(d[0])
                if instruction is not None:
                    need(instruction[0]==decoded[:d[10]],'owned descriptor length and bytes equal actual disassembly')
                    entry['producer']=dict(role=owner[0],offset=owner[1],code=d[4],length=d[10],
                        bytes=decoded[:d[10]].hex(),instruction=instruction[1]);known+=count
        p=entry['producer'];key=('unknown',None,None) if p is None else (p['role'],p['offset'],p['instruction'])
        groups[key]=groups.get(key,0)+count;result.append(entry)
    need(known<=c['total']-c['overflow'] and sum(groups.values())+c['overflow']==c['total'],'all events retained in classified/unknown/overflow partition')
    return dict(sites=result,classified_producer_events=known,unknown_producer_events=c['total']-c['overflow']-known,
        overflow_events=c['overflow'],source_sha256=H(source),
        producers=[dict(role=k[0],offset=k[1],instruction=k[2],events=v) for k,v in sorted(groups.items(),key=lambda x:(-x[1],str(x[0])))],
        ingresses=[dict(role=k[0],offset=k[1],signal=k[2],si_code=k[3],instruction=k[4],events=v)
                   for k,v in sorted(ingresses.items(),key=lambda x:(-x[1],str(x[0])))])


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    ap.add_argument('--output', type=Path, required=True)
    for n in ('native-receipt', 'smoke-receipt'):
        ap.add_argument('--'+n, type=Path, required=True); ap.add_argument('--'+n+'-sha256', required=True)
    a = ap.parse_args(); affinity = os.sched_getaffinity(0)
    need(not sys.flags.optimize and sys.version_info[:2] == (3,12) and len(affinity) == 1 and
         re.fullmatch('[0-9a-f]{40}', a.expect_revision) and
         all(re.fullmatch('[0-9a-f]{64}',v) for v in (a.native_receipt_sha256,a.smoke_receipt_sha256)), 'assertions, Python3.12, exact revision and reserved singleton')
    cpu = next(iter(affinity)); private = a.output.absolute()
    need(private.parent == ROOT/'target/evaluation/inprocess' and not private.exists(), 'fresh direct-child output')
    private.mkdir(); pins, aliases, artifacts = {}, {}, {}
    r = dict(schema=1, profile='loop-ingress-census-diagnostic-v1', status='failed', revision=a.expect_revision,
        cpu=cpu, hardware=hardware(cpu), argv=[sys.executable,'-B',*sys.argv], bounds=BOUNDS,
        source=None, source_unchanged=False, inputs_unchanged=False, cleanup_complete=False,
        commands=[], lanes=[], namespace_aliases={}, error=None, final_errors=[],
        owner_credit=False, qualification_credit=False, performance_credit=False)
    def pin(path):
        lexical = Path(path).absolute(); p = lexical.resolve(strict=True); value = fact(p)
        need(p.is_file() and (str(p) not in pins or pins[str(p)] == value), 'stable whole input')
        need(str(lexical) not in aliases or aliases[str(lexical)] == str(p), 'stable input alias')
        pins[str(p)] = value; aliases[str(lexical)] = str(p); return p
    def binary(path):
        p = pin(path); value = dict(fact(p), mode=p.stat().st_mode & 0o777)
        need(str(p) not in artifacts or artifacts[str(p)] == value, 'stable artifact bytes/mode')
        artifacts[str(p)] = value; return p
    def guard():
        need(source() == r['source'] and os.sched_getaffinity(0) == {cpu}, 'same clean whole source and CPU')
        need(all(fact(p) == v for p,v in pins.items()) and
             all(str(Path(p).resolve(strict=True)) == v for p,v in aliases.items()), 'whole inputs and aliases unchanged')
        need(all(dict(fact(p),mode=Path(p).stat().st_mode & 0o777) == v for p,v in artifacts.items()), 'whole artifacts unchanged')
        need(all(Path(p).is_symlink() and os.readlink(p) == v for p,v in r['namespace_aliases'].items()), 'namespace aliases unchanged')
    def run(name, argv, profile='release_build', expected=0, env=None, record=False):
        guard(); need(len(r['commands']) < 6 and expected == 0, 'six fixed build/carrier/subject/disassembly commands, expected exit zero')
        row = dict(name=name, argv=list(map(str,argv)), environment=dict(ENV if env is None else env),
            profile=profile, bounds=BOUNDS, capture_limit=16 << 20, expected_exit=0)
        r['commands'].append(row)
        try:
            out, err = (program_invoke if record else invoke)(row, private, cpu, record=record)
            if not record: need(row['exit'] == 0, 'actual build/carrier exit zero')
            return row, out, err
        finally:
            save(private/'receipt.json',r)
            print(json.dumps(dict(command=name,exit=row.get('exit'),timed_out=row.get('timed_out'))),flush=True)
    try:
        r['source'] = source(); need(r['source']['revision'] == a.expect_revision, 'exact clean checkout')
        pin(__file__); imported_sources(pin)
        names = subprocess.check_output(['/usr/bin/git','-c','index.threads=1','-c','core.preloadIndex=false',
            'ls-files','-z','tools/page-entry','evaluation/inprocess'],cwd=ROOT)
        for n in names.split(b'\0'):
            if n and not n.startswith(b'evaluation/inprocess/results/'): pin(ROOT/os.fsdecode(n))
        native_path = pin(a.native_receipt); smoke_path = pin(a.smoke_receipt)
        need(fact(native_path)['sha256'] == a.native_receipt_sha256 and fact(smoke_path)['sha256'] == a.smoke_receipt_sha256,
             'exact closed native and original smoke receipts')
        n = json.loads(native_path.read_bytes()); smoke = json.loads(smoke_path.read_bytes())
        need(smoke['profile']=='loop-guard-cancel-smoke-v1' and smoke['status']=='failed' and
             smoke['source_unchanged'] is smoke['inputs_unchanged'] is smoke['cleanup_complete'] is True and
             smoke['final_errors']==[] and smoke['bounds']==BOUNDS and
             smoke['owner_credit'] is smoke['qualification_credit'] is smoke['performance_credit'] is False and
             [x['name'] for x in smoke['commands']]==['maintained-build','maintained-carrier','subject-maintained-0-0',
                'differential-build','differential-carrier','subject-differential-0-0'] and
             [x['exit'] for x in smoke['commands']]==[0,0,0,0,0,-9], 'original smoke outcome stays failed')
        prior=smoke['commands'][2];prior_path=pin(smoke_path.parent/(prior['name']+'.json'))
        need(json.loads(prior_path.read_bytes())==prior,'whole original completed maintained command')
        baseline_path=pin(smoke_path.parent/prior['captures']['stdout']['file'])
        need(fact(baseline_path)=={k:prior['captures']['stdout'][k] for k in ('bytes','sha256')},'whole original maintained output')
        baseline=baseline_path.read_bytes()
        native_rows=[x for x in n['commands'] if x['name']=='subject-native-0-0']
        need(len(native_rows)==1 and native_rows[0]['exit']==0,'actual completed native case0/placement0')
        native_capture=native_rows[0]['captures']['stdout'];native_output=pin(native_path.parent/native_capture['file'])
        need(fact(native_output)=={k:native_capture[k] for k in ('bytes','sha256')} and
             fact(native_output)['sha256']==n['cases'][0]['native']['raw_sha256'],'whole native source observation')
        native_bytes=native_output.read_bytes()
        need(n['profile'] == 'persistent-loop-native-v2' and n['status'] == 'observed_native_references' and
             n['source_unchanged'] is n['inputs_unchanged'] is n['cleanup_complete'] is True and
             n['error'] is None and n['final_errors'] == [], 'closed native inputs; no current-head native credit')
        b = n['build']; app = n['application_build']; archive = binary(b['artifacts']['decoder.a']['path'])
        original = binary(app['argv'][-1]); interp = binary(app['interpreter']['path'])
        need(b['status'] == app['status'] == 'passed' and b['command_completed'] is True and len(b['dep_info']) == 11 and
             archive == native_path.parent/'artifacts/decoder.a' and archive.read_bytes()[:8] == b'!<arch>\n' and
             b['decoder_features'] == ['scalar-region','scalar-span','linked-epoch','mov-guard','scalar-read'], 'actual eleven-source scalar-read archive')
        for p,v in b['dep_info'].items(): need(fact(pin(ROOT/p)) == v, 'whole current decoder sources equal reused archive inputs')
        for mapping in (app['headers'],app['interpreter_headers']):
            for p,v in mapping.items(): need(fact(pin(p)) == v, 'whole original fixture compiler inputs unchanged')
        need(fact(pin(SELECTED/'tests/tunables_loop_paired_app/build.sh')) == app['recipe'] and
             fact(pin(SELECTED/'tests/persistent_direct_frontier_app/app.ld')) == app['linker'], 'unchanged actual fixture recipe and linker source')
        for p,v in ((archive,b['artifacts']['decoder.a']),(original,app['artifact']),(interp,app['interpreter'])):
            need(fact(p) == {k:v[k] for k in ('bytes','sha256')} and artifacts[str(p)] == n['artifacts'][str(p)], 'native receipt joins actual retained product')
        tools = {}
        for k in ('sh','cc','cc1','collect2','as','ld','python'):
            v = b['tools'][k]; tools[k] = pin(v['path']); need(fact(tools[k]) == {q:v[q] for q in ('bytes','sha256')}, 'same actual tool '+k)
        need(Path(sys.executable).resolve() == tools['python'], 'same actual Python tool')
        r['reused_inputs'] = dict(native_receipt=fact(native_path), native_revision=n['revision'], native_cpu=n['cpu'],
            archive=fact(archive), original=fact(original), interpreter=fact(interp), prior_command=fact(prior_path),
            prior_exit=prior['exit'], prior_expected_exit=prior['expected_exit'], smoke_receipt=fact(smoke_path),
            smoke_revision=smoke['revision'], smoke_status=smoke['status'], current_native_credit=False)
        launch = pin(SELECTED/'tests/tunables_loop_paired_app/launch.py'); olddir = prior_path.parent/'maintained/subject'
        oldargv = [str(tools['python']),'-B',str(launch),'--root',str(ROOT),'--role','gated','--case','0','--placement','0',
            '--control','0','--original',str(original),'--preparation',str(olddir/'preparation.json'),'--library-root',str(original.parent),
            '--carrier',str(prior_path.parent/'maintained/carrier'),'--namespace',str(olddir/'namespace'),'--record-fd',prior['argv'][-1]]
        need(prior['name'] == 'subject-maintained-0-0' and prior['argv'] == oldargv and prior['environment'] == ENV and
             prior['bounds'] == BOUNDS and prior['capture_limit'] == 16 << 20 and prior['expected_exit'] == 0 and prior['exit'] == 0 and
             prior['reaped'] is True and prior['timed_out'] is False and prior['error'] is None and prior['cleanup_errors'] == [] and
             all(d['closed'] is True for d in prior['descriptors']), 'whole original closed maintained launch contract')
        environment = dict(ENV,LI2_CC=str(tools['cc']),LI2_PYTHON=str(tools['python']))
        for lane,mode in LANES:
            state = dict(lane=lane,status='failed',terminal=None,error=None); r['lanes'].append(state)
            directory = private/lane; directory.mkdir(); generated = directory/'build'; generated.mkdir()
            def lane_run(name,argv,profile='metadata',expected=0,env=None,record=False):
                return run(lane+'-'+name,argv,profile,expected,env,record)
            try:
                recipe = pin(SELECTED/('build-persistent-loop-'+mode+'.sh'))
                _,out,err = lane_run('build',[tools['sh'],recipe,archive,original,generated],env=environment)
                need(out == err == b'', 'strict actual recipe diagnostics')
                for p in generated.iterdir(): binary(p)
                bridge = binary(generated/('bridge-persistent-loop-'+mode+'.so'))
                _,roots,objects,description,_,_,carrier = prepare_inputs(original,bridge,SimpleNamespace(tools=tools),
                    directory,pin,binary,lane_run,state,app)
                subject = directory/'subject'; subject.mkdir(); argv = list(oldargv)
                for key,value in (('--carrier',carrier),('--namespace',subject/'namespace'),('--preparation',subject/'preparation.json'),('--record-fd','{record_fd}')):
                    argv[argv.index(key)+1] = str(value)
                row,out,err = run('subject-'+lane+'-0-0',argv,profile='program',record=True)
                preparation(dict(lane=1,mode=0,placement=0,control=0),row,subject,original,roots,objects,description,carrier,private,binary,r)
                c,original_stderr,loop,raw=census(err);group=raw['LI2_PERSISTENT_UNREGISTERED']
                terminal_path=private/'original-terminal.stderr';terminal_path.write_bytes(original_stderr);binary(terminal_path)
                state['census']=c;state['original_terminal']=fact(terminal_path)
                need(loop['status'] == group['status'] == row['exit'] and loop['failure_code'] == group['failure_code'], 'typed terminal outcome agrees with actual process exit')
                state['terminal'] = dict(loop={k:loop[k] for k in ('status','failure_code','route','scope','choice_complete')},
                    owner={k:group[k] for k in ('status','failure_code','detail_abs','detail_negative','phase','busy')})
                need(row['exit'] == 0 and loop['failure_code'] == group['detail_abs'] == group['detail_negative'] == 0, 'the actual maintained diagnostic must exit zero')
                header=struct.unpack_from('<64Q',out)
                need(header[6]==header[7]==row['pid'] and header[8]==cpu,'actual observed subject process and CPU')
                state['classification']=classify(c,out,baseline,native_bytes,original,interp,pin,binary,run,private)
                state['status'] = 'observed_ingress_diagnostic_only'
            except Exception as e: state['error'] = type(e).__name__+': '+str(e)
            guard(); need(all(x['exit'] == x['expected_exit'] == 0 and x['timed_out'] is False and
                x['error'] is None and x['bounds'] == BOUNDS and x['capture_limit'] == 16 << 20 and
                x.get('reaped') is True and x.get('cleanup_errors') == [] and
                type(x.get('descriptors')) is list and
                all(d.get('closed') is True for d in x['descriptors']) for x in r['commands']), 'exact successful child protocol and closed descriptors before next lane')
        need(len(r['commands']) == 6 and all(s['status'] == 'observed_ingress_diagnostic_only' for s in r['lanes']), 'complete one-subject census and three offline disassemblies')
        r['status'] = 'observed_ingress_diagnostic_only'
    except BaseException as e: r['error'] = type(e).__name__+': '+str(e)
    finally:
        try:
            imported_sources(pin); guard(); r['source_unchanged'] = r['inputs_unchanged'] = True
            for row in r['commands']:
                need(json.loads(binary(private/(row['name']+'.json')).read_bytes()) == row, 'whole retained command record')
                for c in row.get('captures',{}).values(): need(fact(binary(private/c['file'])) == {k:c[k] for k in ('bytes','sha256')}, 'whole retained capture')
        except BaseException as e: r['final_errors'].append(type(e).__name__+': '+str(e))
        r['cleanup_complete'] = all(x.get('reaped') is True and x.get('cleanup_errors') == [] and
            all(d.get('closed') is True for d in x.get('descriptors',[])) for x in r['commands'])
        if r['error'] or r['final_errors'] or not r['cleanup_complete']: r['status'] = 'failed'
        r.update(inputs=pins,aliases=aliases,artifacts=artifacts); save(private/'receipt.json',r)
        public = {k:r[k] for k in ('schema','profile','status','revision','cpu','bounds','source_unchanged','inputs_unchanged','cleanup_complete','owner_credit','qualification_credit','performance_credit')}
        public.update(receipt=fact(private/'receipt.json'), reused_inputs=r.get('reused_inputs'),
            hardware={k:v for k,v in r['hardware'].items() if k not in ('isa_flags','runner_euid','runner_cap_eff')},
            isa_flags_sha256=H(json.dumps(r['hardware']['isa_flags'],separators=(',',':')).encode()),
            commands=[{k:x.get(k) for k in ('name','exit','timed_out','duration_ns','expected_exit')} for x in r['commands']],
            lanes=[dict(**{k:s[k] for k in ('lane','status','terminal')},
                census=None if 'census' not in s else {k:s['census'][k] for k in ('total','overflow','used','signals','error')},
                classified_producer_events=s.get('classification',{}).get('classified_producer_events'),
                unknown_producer_events=s.get('classification',{}).get('unknown_producer_events'),
                top_producers=s.get('classification',{}).get('producers',[])[:20],
                top_ingresses=s.get('classification',{}).get('ingresses',[])[:20]) for s in r['lanes']],
            reproduction_argv=['python3.12','-B','evaluation/inprocess/loop_ingress_census.py',
                '--expect-revision',a.expect_revision,'--output','target/evaluation/inprocess/<fresh-census-output>',
                '--native-receipt','<retained-native-receipt.json>','--native-receipt-sha256',a.native_receipt_sha256,
                '--smoke-receipt','<retained-smoke-receipt.json>','--smoke-receipt-sha256',a.smoke_receipt_sha256],
            scope='One maintained ingress census and offline actual ELF/source joins. Unknown predecessors and table overflow remain explicit. No full-state, cancellation, owner, qualification or timing credit.')
        public_text = json.dumps(public, indent=2, sort_keys=True)+'\n'
        need(len(public_text.encode()) <= 32 << 10 and all(not value or value not in public_text
            for value in (str(ROOT), str(Path.home()), '/home/', platform.node())), 'bounded public summary without host paths or hostname')
        save(private/'summary.json',public)
    print(json.dumps(dict(status=r['status'],receipt=str((private/'receipt.json').relative_to(ROOT)))),flush=True)
    return int(r['status'] != 'observed_ingress_diagnostic_only')


if __name__ == '__main__': raise SystemExit(main())
