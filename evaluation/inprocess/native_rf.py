#!/usr/bin/env python3
"""Run the finite RF/native-NX oracle on exactly one externally reserved CPU.

Builds at -O2, saves all actual frames privately, and publishes only numeric
results and hashes. This is an architecture component test, not execution of
the production native-admission owner. No timing or whole-program claim.
"""
import argparse, datetime, hashlib, json, os, pathlib, platform, resource, shutil, struct, subprocess, time
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--expect-revision', required=True)
parser.add_argument('--output', type=pathlib.Path, required=True)
args = parser.parse_args()
ROOT = pathlib.Path(__file__).resolve().parents[2]
os.chdir(ROOT)
BASE = ROOT / 'target/page-native-rf-validation'
BASE.mkdir(parents=True, exist_ok=True)
SOURCE = ROOT / 'tools/page-entry/selected/tests/native_pages/rf_probe.c'
RUN = BASE / datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
RUN.mkdir()
def digest(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def fact(p):
    p = pathlib.Path(p)
    return {'bytes': p.stat().st_size, 'sha256': digest(p)}
def need(x, why):
    if not x: raise ValueError(why)
affinity = sorted(os.sched_getaffinity(0))
need(len(affinity) == 1, 'exactly_one_reserved_cpu')
revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
need(revision == args.expect_revision, 'exact_revision')
need(digest(SOURCE) == '42811f1cc2e14bc1d2fad286b5c769cb96afb0675994b31a8807107a2f561aa7',
     'exact_probe_source')
cpu_rows = [{k.strip(): v.strip() for k, v in
             (line.split(':', 1) for line in row.splitlines() if ':' in line)}
            for row in pathlib.Path('/proc/cpuinfo').read_text().split('\n\n')]
cpu_row = next(r for r in cpu_rows if r.get('processor') == str(affinity[0]))
hardware = {'machine': platform.machine(), 'kernel': platform.release(),
            'reserved_cpu': affinity[0], 'reserved_cpu_count': 1,
            'cpu': {key: cpu_row[key] for key in
                    ('vendor_id','cpu family','model','model name','stepping','microcode','flags')}}
env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
commands = []
receipt = {'schema': 1, 'scope': 'RF next-instruction architecture component, not production owner',
           'revision': revision, 'hardware': hardware, 'runner': fact(__file__),
           'cpu': affinity[0], 'source': fact(SOURCE), 'commands': commands,
           'status': 'failed', 'result': None}
def run(name, argv, cpu=3, memory=256<<20, cap=2<<20, wall=8, fd3=False):
    row = {'name': name, 'argv': argv, 'limits': {'cpu_seconds': cpu, 'memory_bytes': memory,
            'file_bytes': cap, 'wall_seconds': wall, 'core_bytes': 0}, 'environment': env}
    commands.append(row)
    rec = None
    if fd3:
        rec = os.open(RUN/(name+'.record'), os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
        need(rec == 3, 'fd3_actual')
    def limits():
        resource.setrlimit(resource.RLIMIT_CPU,(cpu,cpu))
        resource.setrlimit(resource.RLIMIT_AS,(memory,memory))
        resource.setrlimit(resource.RLIMIT_FSIZE,(cap,cap))
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    start=time.monotonic()
    with (RUN/(name+'.stdout')).open('wb') as out, (RUN/(name+'.stderr')).open('wb') as err:
        try:
            process=subprocess.Popen(argv, stdout=out, stderr=err, env=env, cwd=ROOT,
                preexec_fn=limits, pass_fds=(() if rec is None else (rec,)), start_new_session=True)
            try: row['exit_code']=process.wait(timeout=wall)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, 9); row['exit_code']=process.wait(); row['timeout']=True
        finally:
            if rec is not None: os.close(rec)
    row['elapsed_seconds']=time.monotonic()-start
    for suffix in ('stdout','stderr') + (('record',) if fd3 else ()):
        row[suffix]=fact(RUN/(name+'.'+suffix))
    need(row['exit_code']==0 and not row.get('timeout'), name+'.exit')
    need((RUN/(name+'.stderr')).read_bytes()==b'',name+'.stderr')
    return (RUN/(name+'.stdout')).read_bytes()
try:
    compiler=pathlib.Path(shutil.which('cc',path=env['PATH'])).resolve()
    tools = {str(p):fact(p) for p in (compiler,pathlib.Path('/usr/bin/nm'),pathlib.Path('/usr/bin/objdump'))}
    receipt['tools']=tools
    run('compiler_version',[str(compiler),'--version'])
    binary=RUN/'rf_probe'
    compile_args=[str(compiler),'-O2','-g','-std=gnu11','-Wall','-Wextra','-Werror',
        '-fno-pie','-no-pie','-fcf-protection=none','-mno-red-zone','-MD','-MF',str(RUN/'compile.d'),
        str(SOURCE),'-o',str(binary)]
    run('compile',compile_args,cpu=5,memory=512<<20,cap=16<<20,wall=10)
    deps=(RUN/'compile.d').read_text().replace('\\\n',' ').split(':',1)[1].split()
    dependencies={p:fact(p) for p in sorted(set(deps))}
    receipt['dependencies']=dependencies
    receipt['binary']=fact(binary)
    symbols=run('symbols',['/usr/bin/nm','-S','--defined-only',str(binary)]).decode()
    matches=[line.split() for line in symbols.splitlines() if line.split()[-1:] == ['rows']]
    need(len(matches)==1 and int(matches[0][1],16)==48*2240,'actual_ELF_rows_extent')
    run('disassembly',['/usr/bin/objdump','-d',str(binary)])
    result=json.loads(run('native',[str(binary)],fd3=True))
    need(result['schema']==1 and result['cases']==48 and result['native_operations']==48 and
         result['nx_operations']==48 and result['same_pc'] is True,'stdout_counts')
    raw=(RUN/'native.record').read_bytes()
    need(len(raw)==48*2240,'complete_actual_record')
    patterns=(0x202,0x203,0x246,0xa96,0x602,0xed7)
    indexes=(13,11,14,12,9,8,10,15,0,1,2,3,4,5,6,7)
    numeric=[]
    for i in range(48):
        blob=raw[i*2240:(i+1)*2240]
        q=struct.unpack_from('<88Q',blob)
        ident,op,restored,epoch,flags,logical=q[:6]
        seed=q[6:22]; native=q[22:39]; completed=q[39:56]; g=q[56:79]
        need((ident,op,epoch,restored)==(i,i//24,(i%24)//12,i%2),'case_tuple')
        expected=patterns[(i%12)//2]
        need(flags==expected|(0x10000 if restored else 0),'actual_requested_flags')
        need(logical==((expected&~0x8d5)|0x55 if epoch else expected),'literal_ordinary_flags')
        need(native==completed and native[16]==logical,'complete_16GPR_fullflags_equality')
        need(blob[704:1216]==blob[1216:1728],'complete_512B_FXSAVE_equality')
        need(q[79:82]==(11,2,0) and q[83:88]==(0,1,1,1,1),'actual_NX_prefix')
        need(g[20]==14 and g[19]==21 and g[17]==logical|0x10000 and g[18]&0xffff==0x33,
             'actual_frame_fields')
        need(g[16]==g[22]==q[82] and g[16] != 0,'same_actual_NX_address')
        need(all(g[index]==(0 if epoch and k==8 else seed[k]) for k,index in enumerate(indexes)),
             'actual_fault_before_GPRs')
        for k in range(16):
            if (op==0 and k in (0,2,11)) or (op==1 and k<=3): continue
            need(native[k]==(0 if epoch and k==8 else seed[k]),'literal_preserved_GPR')
        if op==0:
            need(native[0]>0 and native[2]==g[16]+2 and native[11]==logical,
                 'SYSCALL_actual_PID_PC_R11_fullflags')
        numeric.append([i,op,restored,epoch,flags,g[17],native[16],completed[16],native[11]])
    need(result['rows']==numeric,'numeric_projection_exact')
    need(fact(SOURCE)==receipt['source'] and fact(binary)==receipt['binary'],'source_binary_closure')
    need(fact(__file__)==receipt['runner'], 'runner_closure')
    need(subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()==revision,
         'revision_closure')
    need(all(fact(p)==v for p,v in dependencies.items()),'dependency_closure')
    need(all(fact(p)==v for p,v in tools.items()),'tool_closure')
    receipt['status']='passed';receipt['result']=result
except BaseException as error:
    receipt['error']=type(error).__name__+': '+str(error)
finally:
    receipt['captures']={p.name:fact(p) for p in sorted(RUN.iterdir()) if p.is_file()}
    (RUN/'receipt.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
    (BASE/'LATEST').write_text(RUN.name+'\n')
# Exact original arguments are retained privately. Public paths are relative to
# the checkout; the compiler/tool basenames are bound by their byte hashes.
def public_argv(argv):
    return [str(x).removeprefix(str(ROOT) + '/') if str(x).startswith(str(ROOT) + '/')
            else pathlib.Path(x).name if str(x).startswith('/usr/bin/') else x for x in argv]
public = {'schema': 1, 'profile': 'native_rf_architecture_component',
    'status': receipt['status'], 'revision': revision, 'hardware': hardware,
    'source': {'path': str(SOURCE.relative_to(ROOT)), **receipt['source']},
    'runner': {'path': str(pathlib.Path(__file__).resolve().relative_to(ROOT)), **receipt['runner']},
    'working_tree_scope': 'Only the hash-bound new probe is linked; concurrent product changes are not exercised.',
    'reproduce': ['python3', 'evaluation/inprocess/native_rf.py', '--expect-revision',
                  revision, '--output', str(args.output)],
    'commands': [{**{k:v for k,v in row.items() if k!='argv'}, 'argv': public_argv(row['argv'])}
                 for row in commands],
    'tools': {pathlib.Path(p).name:v for p,v in receipt.get('tools',{}).items()},
    'binary': receipt.get('binary'), 'private_receipt_sha256': digest(RUN/'receipt.json'),
    'result': receipt['result'], 'row_fields': ['id','operation_0_syscall_1_cpuid','restored_rf',
        'arithmetic_epoch','input_flags','actual_fault_flags','native_pushfq','completed_pushfq','native_r11'],
    'comparison': {'same_original_pc': True, 'gpr_words_per_lane': 16, 'full_flags': True,
        'legacy_fxsave_bytes_per_lane': 512, 'full_xsave': False, 'rdtsc_exercised': False,
        'production_native_epoch_owner_exercised': False},
    'architecture_reference': {'document': 'Intel SDM Vol.3 325384-078US, section 18.3.1.1',
        'pdf_sha256': '8b988bc23b81bc97a7ea6d0cac8bf3ce9e47db106fbb7a2b9d11aa412c93859b',
        'pdf_page': 647},
    'error': receipt.get('error')}
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(public, indent=2, sort_keys=True)+'\n')
print(json.dumps({'directory':RUN.name,'status':receipt['status'],'error':receipt.get('error'),
                  'receipt_sha256':digest(RUN/'receipt.json')}))
raise SystemExit(0 if receipt['status']=='passed' else 1)
