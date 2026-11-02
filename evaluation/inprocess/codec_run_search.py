#!/usr/bin/env python3
"""Compare the original codec with the current candidate; no guest/qualification credit.

On one externally reserved CPU at a clean checkout, first regenerate schema10:
  python3.12 -B evaluation/inprocess/direct_frontier_loop.py --expect-revision REV
Use that passed receipt and its subject-maintained-0-0.record/capture-codec/vector.bin:
  python3.12 -B evaluation/inprocess/codec_run_search.py --expect-revision REV \
    --old-revision 47bc4fafe14f89ec035db28d66e221ff58d783db \
    --candidate-sha256 SHA --native RECEIPT --native-sha256 SHA \
    --record RECORD --vector VECTOR --output target/evaluation/inprocess/FRESH
All original824 controls run twice at5CPU/15wall/512MiB/16MiB; one comparison
runs at30CPU/60wall/512MiB/16MiB. No retry or guest execution. Raw data stays in
memory. The old donor is a Git blob; the capture must match the current revision.
"""
import argparse,array,hashlib,importlib.util,json,os,resource,stat,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path.cwd().resolve();SCRIPT=Path(__file__).resolve()
sys.path.insert(0,str(ROOT/'evaluation/inprocess'))
OLD='47bc4fafe14f89ec035db28d66e221ff58d783db'
CODEC='tools/page-entry/selected/tests/capture_rle/read.py'
CONTROL='tools/page-entry/selected/tests/capture_rle/controls.py'
FINITE=[5,512<<20,16<<20,15];MICRO=[30,512<<20,16<<20,60]
EXPECTED=dict(scope='capture_codec_reader_only',roundtrips=40,transport_refusals=824,
 truncations=794,semantic_reachability=2,cross_language_vectors=1,native_qualification=False)

def need(value, message):
  if not value:
    raise ValueError(message)

def fact(data):
  return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())

def whole(path, expected=None):
  path = Path(path)
  before = path.lstat()
  need(stat.S_ISREG(before.st_mode), 'regular whole input: '+str(path))
  data = path.read_bytes()
  after = path.lstat()
  identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
  need(identity(before) == identity(after), 'stable whole input: '+str(path))
  got = fact(data)
  if expected is not None:
    need(got == {key: expected[key] for key in ('bytes', 'sha256')}, 'whole input fact: '+str(path))
    if 'mode' in expected:
      need(stat.S_IMODE(before.st_mode) == expected['mode'], 'whole input mode: '+str(path))
  return data

def write_json(path, data):
  with Path(path).open('x') as out:
    out.write(json.dumps(data, indent=2, sort_keys=True, allow_nan=False)+'\n')

def success(row, bounds, profile):
  need(row['exit'] == row['expected_exit'] == 0 and row['timed_out'] is False and
    row['error'] is None and row['reaped'] is True and row['cleanup_errors'] == [] and
    type(row['descriptors']) is list and all(x['closed'] is True for x in row['descriptors']) and
    row['bounds'] == bounds and row['capture_limit'] == bounds[2] and row['profile'] == profile,
    'complete original command outcome/bounds: '+row['name'])

def import_codec(name, path, expected):
  whole(path, expected)
  spec = importlib.util.spec_from_file_location(name, path)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  need(Path(module.__file__).resolve() == path.resolve(), 'exact isolated codec import')
  return module

def micro(context_path, context_sha, script_sha):
  """Only the two isolated codec modules execute here; no owner reader imports."""
  data = whole(context_path)
  need(fact(data)['sha256'] == context_sha, 'whole parent context')
  c = json.loads(data)
  need(c['revision'] == REVISION and c['driver']['sha256'] == script_sha and
    c['bounds'] == MICRO and os.sched_getaffinity(0) == {c['cpu']}, 'exact micro domain')
  for key, value in ((resource.RLIMIT_CPU, MICRO[0]), (resource.RLIMIT_AS, MICRO[1]),
           (resource.RLIMIT_FSIZE, MICRO[2]), (resource.RLIMIT_CORE, 0)):
    need(resource.getrlimit(key) == (value, value), 'actual unchanged child limit')
  for name, expected in c['inputs'].items():
    whole(name, expected)
  need(fact(whole(SCRIPT)) == c['driver'], 'whole executed micro driver')
  old = import_codec('codec_old', Path(c['old']), c['inputs'][c['old']])
  new = import_codec('codec_candidate', Path(c['candidate']), c['inputs'][c['candidate']])
  counts = {}
  def outcome(module, raw, at):
    try:
      value = module._run(raw, at)
      return ('value', type(value).__module__, type(value).__qualname__, value)
    except Exception as error:
      return ('exception', type(error).__module__, type(error).__qualname__, str(error))
  def compare(group, raw, at):
    a, b = outcome(old, raw, at), outcome(new, raw, at)
    need(a == b, 'exact _run result/exception: '+group+' '+repr(at)+' '+repr((a, b)))
    counts[group] = counts.get(group, 0)+1
  def buffers(raw):
    return raw, bytearray(raw), memoryview(raw)
  for value in range(256):
    for other in range(256):
      if value == other:
        continue
      for raw in buffers(bytes((value,))*9+bytes((other,))):
        compare('all_distinct_byte_pairs', raw, 0)
    for n in (1, 7, 8, 9):
      for raw in buffers(bytes((value,))*n):
        compare('run_thresholds', raw, 0)
        compare('last_byte', raw, n-1)
  for value in (0, 10, 13, 46, 91, 92, 93, 94, 127, 128, 255):
    for n in (65535, 65536, 65537):
      raw = bytes((value,))*n
      for obj in buffers(raw):
        compare('long_runs', obj, 0)
      compare('nonzero_buffer_offset', memoryview(b'ab'+raw+b'cd')[2:-2], 0)
      for obj in buffers(bytes(i % 256 for i in range(n))):
        for at in (0, n-2, n-1):
          compare('literal_boundaries', obj, at)
  class BytesSubclass(bytes):
    pass
  class BytearraySubclass(bytearray):
    pass
  class IntSubclass(int):
    pass
  released = memoryview(b'aaa')
  released.release()
  values = (b'', bytearray(), memoryview(b''), b'aaab', bytearray(b'aaab'), memoryview(b'aaab'),
       'aaab', [97, 97, 97, 98], (97, 97, 97, 98), BytesSubclass(b'aaab'),
       BytearraySubclass(b'aaab'), memoryview(b'aXaXaXbX')[::2],
       memoryview(array.array('b', [-1, -1, 1])), memoryview(array.array('H', [257, 257, 258])),
       memoryview(b'aaaa').cast('B', shape=[2, 2]), memoryview(b'zaaabz')[1:-1], released)
  for raw in values:
    try:
      size = len(raw)
    except ValueError:
      size = 3  # This test's released view originally had exactly three bytes.
    for at in (-size-2, -size, -1, 0, max(0, size-1), size, size+1,
         False, True, 0.0, 0.5, None, '0', IntSubclass(0)):
      compare('fallback_offsets_and_exceptions', raw, at)
  need(counts == dict(all_distinct_byte_pairs=195840, run_thresholds=3072, last_byte=3072,
           long_runs=99, nonzero_buffer_offset=33, literal_boundaries=297,
           fallback_offsets_and_exceptions=238), 'complete fixed edge population')
  encoded = whole(c['record'], c['inputs'][c['record']])
  def decode(module, value):
    raw, transport = module.decode(value, raw_bytes=4549248, schema_version=10)
    need(type(raw) is memoryview and raw.readonly and raw.c_contiguous and raw.format == 'B' and
      raw.ndim == 1 and raw.itemsize == 1 and raw.nbytes == 4549248 and type(raw.obj) is bytearray,
      'complete readonly view over one owned raw allocation')
    return raw, transport
  old_raw, actual_transport = decode(old, encoded)
  new_raw, new_transport = decode(new, encoded)
  need(old_raw == new_raw and actual_transport == new_transport, 'whole raw and real transport equality')
  raw = bytes(old_raw)
  del old_raw, new_raw
  old_synthetic = old.encode_for_control(raw, schema_version=10)
  new_synthetic = new.encode_for_control(raw, schema_version=10)
  need(type(old_synthetic) is bytes and old_synthetic == new_synthetic, 'whole synthetic encoding equality')
  a, ta = decode(old, old_synthetic)
  b, tb = decode(new, new_synthetic)
  need(a == b == raw and ta == tb, 'whole synthetic roundtrip and synthetic receipt equality')
  synthetic_transport = ta
  del a, b, new_synthetic
  samples = []
  for operation in ('decode', 'encode_for_control'):
    for pair, order in enumerate((('old', 'candidate'), ('candidate', 'old'))):
      for position, name in enumerate(order):
        module = old if name == 'old' else new
        cpu_start, wall_start = time.process_time_ns(), time.perf_counter_ns()
        result = (module.decode(encoded, raw_bytes=4549248, schema_version=10) if operation == 'decode'
             else module.encode_for_control(raw, schema_version=10))
        wall_ns, cpu_ns = time.perf_counter_ns()-wall_start, time.process_time_ns()-cpu_start
        if operation == 'decode':
          view, receipt = result
          need(type(view) is memoryview and view.readonly and view.c_contiguous and
            view.ndim == 1 and view.format == 'B' and view.nbytes == len(raw) and
            type(view.obj) is bytearray and view == raw and receipt == actual_transport,
            'every timed decode whole result')
          del view, receipt
        else:
          need(type(result) is bytes and result == old_synthetic, 'every timed encode whole result')
        samples.append(dict(operation=operation, pair=pair, position=position, implementation=name,
          cpu_ns=cpu_ns, wall_ns=wall_ns,
          process_maxrss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss))
        del result
  for name, expected in c['inputs'].items():
    whole(name, expected)
  need(fact(whole(context_path))['sha256'] == context_sha and fact(whole(SCRIPT)) == c['driver'],
    'complete micro input/driver closure')
  print(json.dumps(dict(schema=1, status='codec_comparison_passed', scope='Python codec operations only',
    cpu=c['cpu'], revision=REVISION, driver=c['driver'], controls=counts,
    actual_record=c['inputs'][c['record']], raw=fact(raw), actual_transport=actual_transport,
    synthetic=fact(old_synthetic), synthetic_transport=synthetic_transport, samples=samples,
    process_maxrss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    rss_scope='Linux process cumulative high-water KiB, not per-operation allocation',
    qualification_credit=False, guest_performance_credit=False), sort_keys=True))

def parent(a):
  from checks import source,admission
  from page_selected_process import invoke
  from run import hardware
  out=a.output.resolve()
  need(out.is_relative_to(ROOT/'target/evaluation/inprocess'),'fresh output beneath target/evaluation/inprocess')
  out.mkdir(parents=True,exist_ok=False)
  r=dict(schema=1,profile='codec-run-search-v1',status='failed',commands=[],inputs={},artifacts={},
    expected_revision=REVISION,old_revision=a.old_revision,argv=sys.argv,final_errors=[],
    source_unchanged=False,inputs_unchanged=False,cleanup_complete=False,
    qualification_credit=False,guest_performance_credit=False)
  def pin(path,expected=None):
    path=Path(path).resolve();data=whole(path,expected)
    f=fact(data)|dict(mode=stat.S_IMODE(path.stat().st_mode))
    need(r['inputs'].setdefault(str(path),f)==f,'stable repeated input')
    return data
  try:
    cpu,=os.sched_getaffinity(0);r['cpu']=cpu;r['hardware']=hardware(cpu)
    need(SCRIPT==ROOT/'evaluation/inprocess/codec_run_search.py','current tracked reproducer')
    r['source']=source();need(r['source']['revision']==REVISION,'exact clean current revision')
    r['driver']=fact(pin(SCRIPT));native_path=a.native.resolve();base=native_path.parent
    raw=pin(native_path);need(fact(raw)['sha256']==a.native_sha256,'supplied complete native receipt hash')
    n=json.loads(raw)
    need(n['profile']=='persistent-direct-frontier-finite-v1'and n['status']=='passed'and
      n['revision']==REVISION and n['source']==r['source']and n['source_unchanged']is True and
      n['cleanup_complete']is True and n['error']is None and n['final_errors']==[]and
      len(n['commands'])==139 and len(n['cases'])==3,'passed same-source complete native41 receipt')
    r['native']=dict(file=str(native_path),**fact(raw))
    python=Path(n['build']['tools']['python']['path']).resolve();pin(python,n['build']['tools']['python'])
    need(Path(sys.executable).resolve()==python,'same actual Python executable')
    for m in list(sys.modules.values()):
      p=getattr(m,'__file__',None)
      if p and Path(p).resolve().is_relative_to(ROOT):pin(p)
    old=admission.git('show',a.old_revision+':'+CODEC)
    controls=pin(ROOT/CONTROL,n['inputs'][str(ROOT/CONTROL)])
    need(controls==admission.git('show',a.old_revision+':'+CONTROL),'whole unchanged original control source')
    candidate=pin(ROOT/CODEC,n['inputs'][str(ROOT/CODEC)])
    need(fact(candidate)['sha256']==a.candidate_sha256,'explicit current candidate identity')
    r['codecs']=dict(old=dict(revision=a.old_revision,path=CODEC,**fact(old)),
      candidate=dict(revision=REVISION,path=CODEC,**fact(candidate)),controls=fact(controls))
    rows={x['name']:x for x in n['commands']};need(len(rows)==139,'distinct retained commands')
    subject=rows['subject-maintained-0-0'];reader=rows['capture-codec-reader']
    success(subject,MICRO,'program');success(reader,FINITE,'finite')
    for row in(subject,reader):
      p=base/(row['name']+'.json')
      need(json.loads(pin(p,n['artifacts'][str(p)]))==row,'whole command/receipt equality')
      for name,f in row['captures'].items():
        p=base/f['file'];need(p==base/(row['name']+'.'+name),'exact capture location')
        need(fact(pin(p,n['artifacts'][str(p)]))=={k:f[k]for k in('bytes','sha256')},'whole capture join')
    case,=[x for x in n['cases']if x['label']==subject['name']]
    need(case['launched']is True and case['exit']==0 and case['timed_out']is False and
      case['status']=='observed_generated_direct_frontier_maintained'and case['captures']==
      {k:{j:v[j]for j in('bytes','sha256')}for k,v in subject['captures'].items()},'whole passed record case')
    record=a.record.resolve();vector=a.vector.resolve()
    need(record==base/subject['captures']['record']['file'],'exact supplied record')
    pin(record,n['artifacts'][str(record)])
    need(fact(pin(vector,n['artifacts'][str(vector)]))==n['capture_codec_component']['vector']and
      n['capture_codec_component']['status']=='passed'and
      n['capture_codec_component']['reader_counts']==EXPECTED and
      reader['argv']==[str(python),'-B',str(ROOT/CONTROL),str(vector)],'whole actual C vector/control join')
    expected=(json.dumps(EXPECTED,sort_keys=True)+'\n').encode()
    need(pin(base/reader['captures']['stdout']['file'])==expected,'original complete control stdout')
    copies={}
    for label,data in(('old',old),('candidate',candidate)):
      d=out/label;d.mkdir()
      for name,b,mode in(('read.py',data,0o644),('controls.py',controls,stat.S_IMODE((ROOT/CONTROL).stat().st_mode))):
        p=d/name
        with p.open('xb')as f:f.write(b)
        p.chmod(mode);need(whole(p)==b,'exact isolated source copy')
        r['artifacts'][str(p)]=fact(b)|dict(mode=mode)
      copies[label]=d/'read.py'
    def run(name,argv,bounds,profile):
      row=dict(name=name,argv=argv,environment=reader['environment'],bounds=bounds,
        profile=profile,capture_limit=bounds[2],expected_exit=0)
      r['commands'].append(row);stdout,stderr=invoke(row,out,cpu);success(row,bounds,profile)
      need(not stderr and json.loads(whole(out/(name+'.json')))==row,'complete command/empty stderr')
      for key,b in(('stdout',stdout),('stderr',stderr)):
        need(whole(out/row['captures'][key]['file'],row['captures'][key])==b,'whole command capture')
      return stdout
    for label in('old','candidate'):
      need(run(label+'-controls',[str(python),'-B',str(copies[label].parent/'controls.py'),str(vector)],
        FINITE,'finite')==expected,'all original824 controls unchanged')
    c=dict(schema=1,revision=REVISION,cpu=cpu,bounds=MICRO,driver=r['driver'],old=str(copies['old']),
      candidate=str(copies['candidate']),record=str(record),inputs={str(p):fact(whole(p))for p in
      (SCRIPT,copies['old'],copies['candidate'],record)})
    context=out/'context.json';write_json(context,c)
    r['artifacts'][str(context)]=fact(whole(context))
    stdout=run('micro',[str(python),'-B',str(SCRIPT),'--expect-revision',REVISION,
      '--micro',str(context),'--context-sha256',fact(whole(context))['sha256'],
      '--script-sha256',r['driver']['sha256']],MICRO,'program')
    result=json.loads(stdout)
    need(result['status']=='codec_comparison_passed'and result['cpu']==cpu and result['revision']==REVISION and
      len(result['samples'])==8 and result['qualification_credit']is False and
      result['guest_performance_credit']is False,'complete bounded comparison')
    r.update(status='codec_comparison_passed',comparison=result)
  except BaseException as e:r['error']=type(e).__name__+': '+str(e)
  finally:
    try:
      for p,f in(r['inputs']|r['artifacts']).items():whole(p,f)
      r['inputs_unchanged']=True;r['source_unchanged']=source()==r.get('source')
      r['cleanup_complete']=all(x.get('reaped')is True and x.get('cleanup_errors')==[]and
        all(d.get('closed')is True for d in x.get('descriptors',[]))for x in r['commands'])
    except BaseException as e:r['final_errors'].append(repr(e))
    if not all(r[k]for k in('source_unchanged','inputs_unchanged','cleanup_complete'))or r['final_errors']:
      r['status']='failed'
    write_json(out/'receipt.json',r)
    print(json.dumps(dict(status=r['status'],receipt=str(out/'receipt.json')),sort_keys=True))
  return 0 if r['status']=='codec_comparison_passed'else 1

def main():
  global REVISION
  p=argparse.ArgumentParser(description=__doc__)
  p.add_argument('--expect-revision',required=True)
  for name in('old-revision','candidate-sha256','native-sha256','context-sha256','script-sha256'):
    p.add_argument('--'+name)
  for name in('native','record','vector','output','micro'):p.add_argument('--'+name,type=Path)
  a=p.parse_args();REVISION=a.expect_revision
  need(not sys.flags.optimize and sys.version_info[:2]==(3,12)and
    len(REVISION)==40 and all(c in'0123456789abcdef'for c in REVISION),'Python3.12 and exact revision')
  if a.micro is not None:
    need(a.script_sha256 and a.context_sha256 and fact(whole(SCRIPT))['sha256']==a.script_sha256,
      'exact internal child identity')
    micro(a.micro,a.context_sha256,a.script_sha256);return 0
  need(a.old_revision==OLD and all(getattr(a,k)is not None for k in('native','record','vector','output'))and
    all(v and len(v)==64 and all(c in'0123456789abcdef'for c in v)for v in
    (a.candidate_sha256,a.native_sha256)),'explicit original donor/current candidate/retained inputs')
  return parent(a)

if __name__=='__main__':raise SystemExit(main())
