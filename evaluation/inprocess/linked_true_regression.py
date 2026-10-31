#!/usr/bin/env python3
"""Regenerate two genuine TRUE inputs, then run three isolated reader checks.

This is an adoption regression, not historical/current hardware qualification
or a timing experiment. Historical runtime sources come from Git objects;
only build-output locations are projected onto the slot's single Cargo target.
"""
import argparse
import functools
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shlex
import signal
import subprocess
import sys
import types

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SCRIPT = 'evaluation/inprocess/linked_true_regression.py'
OLD = 'f7dd159db74f7ca1181a89bd48c11a329d7a49a5'
POSITIVE = '92fb7d268751cba077fd763903daba0b76168a94'
SCHEDULE = ('historical-unused', 'candidate-unused', 'candidate-positive')
PROGRAM = [30, 512 << 20, 16 << 20, 60]
READER = dict(cpu_seconds=3, wall_seconds=10, address_space=256 << 20,
              file_size=1 << 20, core=0)
PROFILE = 'linked-true-before-first-rseq-v1'
HISTORICAL = {
    OLD: dict(tree='2f8f8e436eaa514dca0d191e4e4b112df83e0c44', files=1362, bytes=16280536,
              manifest_sha256='376b4abc95678e073b221f3f60210d61ad56650938db143217f44731e7dd35a4'),
    POSITIVE: dict(tree='49eedc787b14b167f1778822d0809b0c4aab5b25', files=1669, bytes=20787112,
                   manifest_sha256='a17c6660bdfc3521685afa45c78836056b279bbeee6464529aaa1d773dd0b68c'),
}
H = lambda b: hashlib.sha256(b).hexdigest()
CANON = lambda v: json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def need(ok, why):
    if not ok:
        raise ValueError(why)


def fact(path):
    b = Path(path).read_bytes()
    return dict(bytes=len(b), sha256=H(b))


def save(path, value):
    with Path(path).open('xb') as f:
        f.write(json.dumps(value, sort_keys=True, indent=2, allow_nan=False).encode()+b'\n')


def git(*args, data=None):
    return subprocess.check_output(['/usr/bin/git', '--no-replace-objects', '-C', str(ROOT), *args],
        input=data, env=dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C'), timeout=30)


def paths(revision):
    rows = git('ls-tree', '-rz', revision, '--', 'tools/page-entry', 'evaluation/inprocess',
               'evaluation/admission', 'evaluation/precontext').split(b'\0')
    result = {}
    for row in rows:
        if not row:
            continue
        metadata, name = row.split(b'\t', 1)
        mode, kind, oid = metadata.split()
        name = os.fsdecode(name)
        if '/results/' in name:
            continue
        need(kind == b'blob' and mode in (b'100644', b'100755'), 'regular historical source leaves')
        result[name] = dict(mode=int(mode, 8) & 0o777, oid=oid.decode())
    return result


def snapshot(revision, directory, shared_target, *, project_build):
    entries = paths(revision)
    names = sorted(entries)
    raw = git('cat-file', '--batch', data=''.join(revision+':'+p+'\n' for p in names).encode())
    need(len(raw) <= 96 << 20, 'bounded complete Git source snapshot')
    cursor = 0
    projections = {}
    for name in names:
        end = raw.index(b'\n', cursor)
        oid, kind, size = raw[cursor:end].split()
        size = int(size); cursor = end+1
        need(kind == b'blob' and oid.decode() == entries[name]['oid'] and
             raw[cursor+size:cursor+size+1] == b'\n', 'exact complete requested Git blob')
        before = raw[cursor:cursor+size]; cursor += size+1
        data = before
        if project_build and name in ('evaluation/inprocess/page_selected_generic_build.py',
                                     'tools/page-entry/selected/build.sh'):
            data, spans = target_projection(name, before, shared_target)
            projections[name] = dict(before=dict(bytes=len(before), sha256=H(before)),
                                     spans=spans)
        path = directory/name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as f:
            f.write(data)
        path.chmod(entries[name]['mode'])
        entries[name].update(fact(path))
    need(cursor == len(raw), 'no unconsumed snapshot bytes')
    result = dict(revision=revision, tree=git('rev-parse', revision+'^{tree}').decode().strip(),
                  files=entries, build_path_projections=projections)
    source_check(directory, result, shared_target=shared_target)
    return result


def target_projection(name, before, shared_target):
    """Eight path-only substitutions; all other historical bytes invert exactly."""
    if name.endswith('.py'):
        value = repr(str(shared_target))
        changes = [
            ("BUILD = REPO/'target/page-entry/selected'", "BUILD = Path("+value+")/'page-entry/selected'"),
            ("CARGO_TARGET_DIR=str(REPO/'target')", "CARGO_TARGET_DIR="+value),
            ("Path(metadata['target_directory']).resolve() == REPO/'target'",
             "Path(metadata['target_directory']).resolve() == Path("+value+")"),
            ("str(REPO/'target/release/libli2_page_selected_decoder.a')",
             "str(Path("+value+")/'release/libli2_page_selected_decoder.a')"),
        ]
    else:
        value = shlex.quote(str(shared_target))
        changes = [
            ('output_dir=target/page-entry/selected', 'output_dir='+shlex.quote(str(shared_target/'page-entry/selected'))),
            ('export CARGO_TARGET_DIR="$PWD/target"', 'export CARGO_TARGET_DIR='+value),
            ('cp target/release/libli2_page_selected_decoder.a', 'cp '+shlex.quote(str(shared_target/'release/libli2_page_selected_decoder.a'))),
            ('cp target/release/libli2_page_selected_decoder.d', 'cp '+shlex.quote(str(shared_target/'release/libli2_page_selected_decoder.d'))),
        ]
    data = before
    spans = []
    for old, new in changes:
        a, b = old.encode(), new.encode()
        need(data.count(a) == 1, 'one exact historical build-path expression')
        at = data.index(a); data = data[:at]+b+data[at+len(a):]
        spans.append(dict(offset=at, before=old, after=new))
    inverse = data
    for span in reversed(spans):
        at = span['offset']; b = span['after'].encode()
        need(inverse[at:at+len(b)] == b, 'exact build-path inverse interval')
        inverse = inverse[:at]+span['before'].encode()+inverse[at+len(b):]
    need(inverse == before, 'whole historical build restored; no flags or guards changed')
    return data, spans


def source_check(directory, spec, shared_target=None):
    originals = {}
    for name, row in spec['files'].items():
        need(not Path(name).is_absolute() and '..' not in Path(name).parts, 'relative source path')
        path = directory/name
        need(not path.is_symlink() and fact(path) == {k:row[k] for k in ('bytes', 'sha256')} and
             path.stat().st_mode & 0o777 == row['mode'], 'exact snapshot source: '+name)
        originals[name] = dict(row)
        if name in spec['build_path_projections']:
            need(shared_target is not None or ROOT/'target' == (ROOT/'target').resolve(), 'canonical shared target')
            projected = spec['build_path_projections'][name];before = path.read_bytes()
            for span in reversed(projected['spans']):
                at=span['offset'];after=span['after'].encode()
                need(before[at:at+len(after)]==after, 'exact retained build-path inverse')
                before=before[:at]+span['before'].encode()+before[at+len(after):]
            need(dict(bytes=len(before),sha256=H(before))==projected['before'] and
                 target_projection(name,before,ROOT/'target' if shared_target is None else shared_target)==
                    (path.read_bytes(),projected['spans']), 'only the eight declared build-path substitutions')
            originals[name].update(projected['before'])
    if spec['revision'] in HISTORICAL:
        expected=HISTORICAL[spec['revision']]
        need(spec['tree']==expected['tree'] and len(originals)==expected['files'] and
             sum(r['bytes'] for r in originals.values())==expected['bytes'] and
             H(CANON(originals))==expected['manifest_sha256'] and
             set(spec['build_path_projections'])=={'evaluation/inprocess/page_selected_generic_build.py',
                                                  'tools/page-entry/selected/build.sh'},
             'whole original historical source/mode/Git identity, only explicit output-path projections')
    else:
        need(spec['build_path_projections']=={}, 'candidate readers are exact Git bytes without projections')


def modules(directory, spec):
    queue = [m for m in tuple(sys.modules.values()) if isinstance(m, types.ModuleType)]
    seen = set(); observed = {}
    while queue:
        module = queue.pop()
        if id(module) in seen:
            continue
        seen.add(id(module)); need(len(seen) <= 8192, 'bounded imported-module graph')
        queue.extend(v for v in vars(module).values() if isinstance(v, types.ModuleType))
        name = getattr(module, '__file__', None)
        if not name:
            continue
        path = Path(name).resolve()
        if path == Path(__file__).resolve():
            continue
        if path.is_relative_to(directory):
            key = str(path.relative_to(directory))
            need(key in spec['files'] and fact(path) == {k:spec['files'][key][k] for k in ('bytes', 'sha256')},
                 'executed source is in the pinned snapshot')
            observed[key] = fact(path)
        else:
            need(path.is_relative_to(Path(sys.base_prefix).resolve()) and
                 'site-packages' not in path.parts and 'dist-packages' not in path.parts,
                 'only snapshot and Python standard library modules execute')
    return observed


def enter_snapshot(directory, spec, *, reader=False):
    source_check(directory, spec)
    sys.path[:] = [str(directory/'evaluation/inprocess'), str(directory/'tools/page-entry')]+[
        p for p in sys.path if p and not Path(p).resolve().is_relative_to(ROOT)]
    os.chdir(directory)
    def audit(event, args):
        if event == 'exec' and args[0].co_filename.startswith('/'):
            path = Path(args[0].co_filename).resolve()
            if path.is_relative_to(ROOT) and path != Path(__file__).resolve():
                need(path.is_relative_to(directory), 'no live or other snapshot Python execution')
                key = str(path.relative_to(directory))
                need(key in spec['files'] and fact(path) == {k:spec['files'][key][k] for k in ('bytes', 'sha256')},
                     'source authentication before module execution')
        if reader:
            need(event not in ('subprocess.Popen', 'os.system', 'os.exec', 'os.posix_spawn', 'os.fork',
                 'os.forkpty', 'pty.spawn', 'socket.__new__', 'os.kill', 'os.killpg'), 'reader cannot execute native code or signal')
            if event == 'open':
                _, mode, flags = args
                need(not (mode and any(c in mode for c in 'wa+')) and
                     not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND),
                     'reader cannot write inputs or results')
    sys.addaudithook(audit)


def generate(kind, output, manifest):
    """Use the actual historical Build/launcher helpers, never a cohort main()."""
    directory = output/'snapshots'/kind; spec = manifest['snapshots'][kind]
    enter_snapshot(directory, spec)
    from page_selected import ENV, interpreter
    from page_selected_generic_build import Build, PROFILES
    from page_selected_oneshot_build import before_default
    from page_selected_process import invoke
    from page_selected_effect_ls import finalize
    from run import hardware
    import page_cost_compare as cost
    import page_native_pair_performance as pair
    import namespace
    private = output/kind
    private.mkdir(mode=0o700)
    cpu = manifest['cpu']
    bounds = dict(PROFILES, release_build=PROGRAM, program=PROGRAM, finite=[5,512<<20,16<<20,15])
    r = dict(schema=1, status='failed', purpose='fresh TRUE regression input only',
        source_revision=spec['revision'], cpu=cpu, hardware=hardware(cpu), commands=[], bounds=bounds,
        inputs={}, artifacts={}, aliases={}, namespace_aliases={}, error=None, final_errors=[],
        native_qualification_credit=False, performance_credit=False)
    def pin(name, want=None):
        alias = Path(os.path.abspath(name)); path = alias.resolve(strict=True); value = fact(path)
        need(want is None or value == {k:want[k] for k in ('bytes','sha256')}, 'exact requested source input')
        need(str(alias) not in r['aliases'] or r['aliases'][str(alias)] == str(path), 'stable input alias')
        need(str(path) not in r['inputs'] or r['inputs'][str(path)] == value, 'stable input bytes')
        r['aliases'][str(alias)] = str(path); r['inputs'][str(path)] = value
        return path
    def binary(name):
        path = Path(name).resolve(strict=True); value = dict(fact(path), mode=path.stat().st_mode & 0o777)
        need(str(path) not in r['artifacts'] or r['artifacts'][str(path)] == value, 'stable retained artifact')
        r['artifacts'][str(path)] = value
        return path
    def stable():
        need(all(Path(p).resolve(strict=True) == Path(v) for p,v in r['aliases'].items()), 'all input aliases unchanged')
        need(all(fact(p) == v for p,v in r['inputs'].items()), 'all source/tool inputs unchanged')
        need(all(dict(fact(p), mode=Path(p).stat().st_mode & 0o777) == v for p,v in r['artifacts'].items()),
             'all retained artifacts unchanged')
        finalize(r)
    def run(name, argv, profile='metadata', expected=0, env=None, record=False, step=False):
        stable(); need(name not in [c['name'] for c in r['commands']], 'unique actual command')
        row = dict(name=name, argv=list(map(str,argv)), profile=profile, bounds=bounds[profile],
            capture_limit=16<<20, environment=dict(ENV if env is None else env), expected_exit=expected)
        r['commands'].append(row)
        try:
            out, err = (cost.program_invoke if name == 'true' else invoke)(row, private, cpu, record=record, step=step)
            need(type(row['exit']) is int and row['exit'] == expected, 'actual command exit: '+name)
            return row, out, err
        finally:
            for capture in row.get('captures', {}).values():
                path = binary(private/capture['file'])
                need(fact(path) == {k:capture[k] for k in ('bytes','sha256')}, 'actual command capture')
            path=binary(private/(name+'.json'))
            need(CANON(json.loads(path.read_bytes()))==CANON(row), 'exact retained command row')
    def clean_decoder(phase):
        # Historical snapshots share one target. Invalidate only this package;
        # private retained archives/dep-info and dependency artifacts survive.
        return run('decoder-clean-'+phase, [builder.tools['cargo'], 'clean', '--release',
            '--package', 'li2-page-selected-decoder', '--manifest-path',
            directory/'tools/page-entry/selected/decoder/Cargo.toml',
            '--target-dir', ROOT/'target', '--locked', '--offline'],
            profile='build', env=builder.environment)
    def build_run(name, argv, profile='metadata', env=None, expected=0):
        before_default(name, argv, builder, pin, r['aliases'], run, r)
        if name == 'selected-build':
            clean_decoder('before')
        return run(name, argv, profile=profile, env=env, expected=expected)
    options = dict(extra_decoder_sources=('region.rs',), scalar_span=True, linked_epoch=True) if kind == 'positive' else {}
    builder = Build(r, private, pin, binary, build_run, **options)
    try:
        for name in ('/etc/ld.so.cache', '/etc/ld.so.preload'):
            r.setdefault('configuration_presence', {})[name] = os.path.lexists(name)
            if os.path.lexists(name):
                pin(name)
        need(not r['configuration_presence']['/etc/ld.so.preload'], 'no global preload')
        products = builder.prepare()
        if kind == 'unused':
            bridge = pair.build_bridge(builder, products, private, pin, binary, r['aliases'], run, r)
        else:
            from linked_epoch_build import build_bridge
            bridge = build_bridge(builder, products, private, pin, binary, r['aliases'], run, r, native_hint=True)
        (private/'external-inputs').mkdir()
        state = pair.prepare_workload('true', '/bin/true', [], bridge, builder, private, pin, binary, run, r, namespace)
        ns = private/'true-namespace'
        argv = [builder.tools['python'], '-B', state['carrier_tool'], 'exec-loader', '--library-root', '/usr/lib64',
                '--namespace', ns, state['carrier'], state['original'], '--', *state['argv']]
        row, out, err = run('true', argv, profile='program', env=pair.PROGRAM_ENV)
        need(out == b'' and err and row['stdout_provenance_before'] == row['stdout_provenance_after'],
             'actual complete empty TRUE output and stable parent descriptor')
        pair.namespace_join(state, ns, binary, r, namespace)
        r['context'] = dict(command='true', images=state['images'], carrier=fact(state['carrier']),
            external_files=[str((private/'external-inputs'/(x['sha256']+'.elf')).relative_to(output)) for x in state['images']],
            carrier_file=str(Path(state['carrier']).relative_to(output)))
        r['status'] = 'generated_input'
    except BaseException as exc:
        r['error'] = type(exc).__name__+': '+str(exc)
    finally:
        try:r['final_errors'].extend(builder.finish())
        except BaseException as exc:r['final_errors'].append('build finalization: '+repr(exc))
        if any(c['name'] == 'decoder-clean-before' for c in r['commands']):
            try:clean_decoder('after')
            except BaseException as exc:r['final_errors'].append('decoder package cleanup: '+repr(exc))
            # Retention precedes deletion; registry/configuration closure follows
            # the final Cargo command, including an unsuccessful cleanup attempt.
            try:r['final_errors'].extend(builder.finish())
            except BaseException as exc:r['final_errors'].append('post-clean build finalization: '+repr(exc))
        try:
            source_check(directory,spec);stable()
            r['executed_modules'] = modules(directory,spec)
            need(all(os.path.lexists(p) == present for p,present in r.get('configuration_presence',{}).items()),
                 'loader configuration presence unchanged')
            r['inputs_unchanged'] = True
        except BaseException as exc:
            r['inputs_unchanged'] = False;r['final_errors'].append('final closure: '+repr(exc))
        r['cleanup_complete'] = all(type(c.get('exit')) is int and c.get('reaped') is True and
            c.get('timed_out') is False and c.get('error') is None and c.get('cleanup_errors') == [] and
            all(d.get('closed') is True for d in c.get('descriptors',[])) for c in r['commands'])
        if r['error'] or r['final_errors'] or not r['inputs_unchanged'] or not r['cleanup_complete']:
            r['status'] = 'failed'
        save(private/'input.json', r)
    print(json.dumps(dict(kind=kind,status=r['status'],input=fact(private/'input.json'))))
    return 0 if r['status'] == 'generated_input' else 1


def input_data(output, kind):
    private = output/kind
    r = json.loads((private/'input.json').read_bytes())
    need(r['status'] == 'generated_input' and r['inputs_unchanged'] is True and r['cleanup_complete'] is True and
         r['error'] is None and r['final_errors'] == [] and r['source_revision'] == (OLD if kind == 'unused' else POSITIVE),
         'closed genuine input producer, exact historical runtime revision')
    need(r['native_qualification_credit'] is r['performance_credit'] is False, 'input generation gives no qualification/timing credit')
    rows = [c for c in r['commands'] if c['name'] == 'true']
    need(len(rows) == 1, 'exactly one actual TRUE per runtime domain')
    row = rows[0]
    need(CANON([row['exit'],row['expected_exit'],row['bounds']]) == CANON([0,0,PROGRAM]) and
         row['stdout_provenance_before'] == row['stdout_provenance_after'], 'exact typed TRUE outcome and bounds')
    captured = {}
    for stream in ('stdout','stderr'):
        path = private/row['captures'][stream]['file']
        need(fact(path) == {k:row['captures'][stream][k] for k in ('bytes','sha256')}, 'whole actual input capture')
        captured[stream] = path.read_bytes()
    need(captured['stdout'] == b'', 'genuine TRUE stdout')
    context = r['context']; images = context['images']
    need(CANON(images)==CANON(r['external_inputs']['true']) and
         context['carrier']==r['carriers']['true'], 'context joins the actual namespace/carrier producer')
    image_bytes = []
    for rel,image in zip(context['external_files'], images, strict=True):
        path = (output/rel).resolve();need(path.is_relative_to(private), 'retained external image location')
        need(fact(path) == {k:image[k] for k in ('bytes','sha256')}, 'whole actual external ELF')
        image_bytes.append(path.read_bytes())
    path = (output/context['carrier_file']).resolve();need(path.is_relative_to(private), 'retained carrier location')
    need(fact(path) == context['carrier'], 'whole actual carrier')
    args = (row['pid'],row['exit'],row['stdout_provenance_before'],images,image_bytes,context['carrier'],path.read_bytes())
    return captured['stdout'],captured['stderr'],args


def reader(name, output, manifest):
    need(name in SCHEDULE and len(os.sched_getaffinity(0)) == 1, 'fixed reader and reserved CPU')
    for key,value in ((resource.RLIMIT_CPU,3),(resource.RLIMIT_AS,256<<20),
                      (resource.RLIMIT_FSIZE,1<<20),(resource.RLIMIT_CORE,0)):
        need(resource.getrlimit(key) == (value,value), 'actual reader hard bounds')
    which = 'unused' if name == 'historical-unused' else 'candidate'
    kind = 'positive' if name == 'candidate-positive' else 'unused'
    out,err,args = input_data(output,kind)
    directory = output/'snapshots'/which; spec = manifest['snapshots'][which]
    enter_snapshot(directory,spec,reader=True)
    if kind == 'unused':
        import page_cost_reports as report
        parsed,summary = report.check(out,err,*args,workload='true')
        terminal = report._terminal_controls(err,*args,workload='true',read=functools.partial(report.check,out))
        controls = report.supplied_controls(out,err,*args,workload='true')
        names = controls['refusals']; unused = [x for x in names if x.startswith('unused_lease_')]
        need(len(names) == len(set(names)) == 218 and terminal['refusals'] == names[:-2] and
             len(terminal['refusals']) == 216 and len(unused) == 180 and unused == names[11:191],
             'all original218/180/216 names in their original order')
        result = dict(accepted=parsed,summary=summary,refusals=names,unused_refusals=unused,
                      terminal_refusals=terminal['refusals'],default_keywords_omitted=True)
    else:
        import linked_epoch_performance_reports as report
        default_error = None
        try:report.check(out,err,args,'true','linked',native_hint=True)
        except ValueError as exc:default_error = str(exc)
        need(default_error == 'entire unused REP report is canonical empty, with only initialization flags',
             'positive input still fails unchanged default unused domain')
        observed = report.check(out,err,args,'true','linked',native_hint=True,positive_true_repeat=True)
        controls = report.controls(out,err,args,'true','linked',native_hint=True,positive_true_repeat=True)
        names = controls['refusals']; positive = [x for x in names if x.startswith('positive_repeat.')]
        need(len(names) == len(set(names)) == 445 and len(positive) == 55 and
             not any('unused_lease_' in x for x in names), 'distinct445/55, no old180 credit')
        result = dict(accepted=observed,refusals=names,positive_refusals=positive,
                      default_refusal=default_error,profile=PROFILE)
    result.update(name=name,status='passed',native_subjects=0,native_qualification_credit=False,
        current_revision_credit=False,performance_credit=False,stdout_sha256=H(out),stderr_sha256=H(err),
        executed_modules=modules(directory,spec))
    source_check(directory,spec);input_data(output,kind)
    print(json.dumps(result,sort_keys=True,separators=(',',':'),allow_nan=False))


def parent(a):
    need(not sys.flags.optimize and len(os.sched_getaffinity(0)) == 1 and
         re.fullmatch('[0-9a-f]{40}',a.expect_revision) is not None, 'exact revision and one reserved CPU')
    need(Path(__file__).resolve() == ROOT/SCRIPT and git('rev-parse','HEAD').decode().strip() == a.expect_revision and
         git('show',a.expect_revision+':'+SCRIPT) == Path(__file__).read_bytes(), 'actual committed producer')
    output = a.output.resolve();need(output.is_relative_to(ROOT/'target') and not output.exists(), 'fresh output inside slot target')
    output.mkdir(parents=True,mode=0o700)
    target = (ROOT/'target').resolve();need(target == ROOT/'target', 'the single canonical slot Cargo target')
    manifest = dict(schema=1,producer_revision=a.expect_revision,producer=fact(__file__),cpu=next(iter(os.sched_getaffinity(0))),
        shared_cargo_target=str(target),snapshots={})
    for name,revision in (('unused',OLD),('positive',POSITIVE),('candidate',a.expect_revision)):
        manifest['snapshots'][name] = snapshot(revision,output/'snapshots'/name,target,project_build=name!='candidate')
    save(output/'SOURCES.json',manifest)
    r = dict(schema=1,profile='linked-true-reproducible-regression-v1',status='failed',producer_revision=a.expect_revision,
        producer=fact(__file__),sources=fact(output/'SOURCES.json'),cpu=manifest['cpu'],bounds=READER,
        generators=[],commands=[],errors=[],final_errors=[],native_input_subjects_planned=2,native_qualification_credit=False,
        current_revision_credit=False,performance_credit=False)
    # Every command inside a generator retains its own original limits and
    # process-group cleanup. Generators are serialized; no second Cargo target.
    for kind in ('unused','positive'):
        row = dict(name=kind,exit=None,reaped=False)
        r['generators'].append(row)
        row['argv']=[sys.executable,'-I','-S','-B',str(Path(__file__).resolve()),'--generate',kind,
                     '--output',str(output),'--sources-sha256',r['sources']['sha256']]
        environment=dict(PATH=os.environ['PATH'],LANG='C',LC_ALL='C',TZ='UTC',PYTHONDONTWRITEBYTECODE='1')
        for key in ('HOME','CARGO_HOME','RUSTUP_HOME'):
            if key in os.environ:environment[key]=os.environ[key]
        row['environment']=environment
        with (output/(kind+'-producer.stdout')).open('xb') as out,(output/(kind+'-producer.stderr')).open('xb') as err:
            proc = subprocess.Popen(row['argv'],stdin=subprocess.DEVNULL,stdout=out,stderr=err,
                cwd=ROOT,env=environment,start_new_session=True)
            row['pid']=proc.pid;row['exit']=proc.wait();row['reaped']=True
        row['captures']={s:fact(output/(kind+'-producer.'+s)) for s in ('stdout','stderr')}
        if row['exit'] != 0:r['errors'].append(kind+' input generation failed')
    for name in SCHEDULE:
        row = dict(name=name,exit=None,reaped=False,timed_out=False,cleanup_errors=[])
        r['commands'].append(row)
        def limits():
            for key,value in ((resource.RLIMIT_CPU,3),(resource.RLIMIT_AS,256<<20),
                              (resource.RLIMIT_FSIZE,1<<20),(resource.RLIMIT_CORE,0)):
                resource.setrlimit(key,(value,value))
        argv = [sys.executable,'-I','-S','-B',str(Path(__file__).resolve()),'--reader',name,
                '--output',str(output),'--sources-sha256',r['sources']['sha256']]
        row['argv']=argv
        proc=None
        try:
            with (output/(name+'.stdout')).open('xb') as out,(output/(name+'.stderr')).open('xb') as err:
                proc=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=err,cwd=ROOT,
                    env=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',PYTHONDONTWRITEBYTECODE='1'),
                    start_new_session=True,preexec_fn=limits)
                row['pid']=proc.pid
                try:row['exit']=proc.wait(timeout=10);row['reaped']=True
                except subprocess.TimeoutExpired:
                    row['timed_out']=True;os.killpg(proc.pid,signal.SIGKILL);row['exit']=proc.wait(timeout=5);row['reaped']=True
        except BaseException as exc:r['errors'].append(name+': '+repr(exc))
        finally:
            if proc is not None and proc.poll() is None:
                try:os.killpg(proc.pid,signal.SIGKILL);row['exit']=proc.wait(timeout=5);row['reaped']=True
                except BaseException as exc:row['cleanup_errors'].append(repr(exc))
            row['captures']={s:fact(output/(name+'.'+s)) for s in ('stdout','stderr')}
    try:
        values=[]
        for name,row in zip(SCHEDULE,r['commands'],strict=True):
            need(type(row['exit']) is int and row['exit']==0 and row['reaped'] is True and not row['timed_out'] and
                 row['cleanup_errors']==[] and (output/(name+'.stderr')).read_bytes()==b'', 'all three original bounded readers completed')
            values.append(json.loads((output/(name+'.stdout')).read_bytes()))
        old,new,positive=values
        need(all(CANON(old[k])==CANON(new[k]) for k in
             ('accepted','summary','refusals','unused_refusals','terminal_refusals')), 'whole old/default acceptance and controls remain equal')
        for name,spec in manifest['snapshots'].items():source_check(output/'snapshots'/name,spec)
        for kind in ('unused','positive'):input_data(output,kind)
        need(git('show',a.expect_revision+':'+SCRIPT)==Path(__file__).read_bytes() and
             git('rev-parse','HEAD').decode().strip()==a.expect_revision, 'producer committed source unchanged')
        r['inputs_unchanged']=True
        r['status']='passed' if not r['errors'] else 'failed'
    except BaseException as exc:r['final_errors'].append(repr(exc));r['inputs_unchanged']=False
    generated=[json.loads((output/k/'input.json').read_bytes()) if (output/k/'input.json').exists() else {}
               for k in ('unused','positive')]
    r['native_input_subjects']=sum(c.get('name')=='true' for g in generated for c in g.get('commands',[]))
    r['cleanup_complete']=all(x['reaped'] is True for x in r['generators']) and all(
        g.get('cleanup_complete') is True for g in generated) and all(
        c['reaped'] is True and c['cleanup_errors']==[] for c in r['commands'])
    if not r['cleanup_complete'] or r['final_errors']:r['status']='failed'
    r['inputs']={k:fact(output/k/'input.json') for k in ('unused','positive') if (output/k/'input.json').exists()}
    save(output/'RESULT.json',r)
    print(json.dumps(dict(status=r['status'],result=str(output/'RESULT.json'),native_qualification_credit=False)))
    return 0 if r['status']=='passed' else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-revision')
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--generate',choices=('unused','positive'))
    parser.add_argument('--reader',choices=SCHEDULE)
    parser.add_argument('--sources-sha256')
    a=parser.parse_args()
    if not a.generate and not a.reader:return parent(a)
    need(bool(a.generate) != bool(a.reader) and len(os.sched_getaffinity(0))==1, 'one literal child role and reserved CPU')
    output=a.output.resolve();need(output.is_relative_to(ROOT/'target'), 'private slot input directory')
    need(fact(output/'SOURCES.json')['sha256']==a.sources_sha256, 'same frozen source manifest')
    manifest=json.loads((output/'SOURCES.json').read_bytes())
    need(manifest['producer']==fact(__file__) and manifest['cpu']==next(iter(os.sched_getaffinity(0))), 'same exact producer and CPU')
    return generate(a.generate,output,manifest) if a.generate else reader(a.reader,output,manifest)


if __name__ == '__main__':
    raise SystemExit(main())
