"""Read-only authentication and report adapter for the reusable-effect ls mode.

The prerequisite is a fresh successful real-ls pair at this exact revision.
It supplies its retained unobserved bridge; this module never builds or runs it.
"""
import sys
sys.dont_write_bytecode = True
import importlib.util, json, os, re, shlex, shutil, tomllib
from pathlib import Path
from types import SimpleNamespace
from checks import admission
from page_selected import ENV, fact, need, interpreter
from page_selected_generic_build import ARTIFACTS, BUILD, PRODUCT, package_check
from page_selected_oneshot_build import commands as recipes
from page_selected_register_time_build import bridge_check
from page_selected_fast_memset import body_check
from page_selected_rseq_time import hidden_memset
import page_selected_effect_ls as producer
import page_selected_effect_ls_reports as effects
import page_default_ls_release_provenance as provenance
import page_default_ls_release_lease_reports as lease

ROOT = Path(__file__).resolve().parents[2]
PROFILE = 'page-default-ls-effect-provider-release-performance-v1'
NAMES = ('source-paths','resolve-cargo','resolve-rustc','resolve-cc1','resolve-collect2','resolve-as','resolve-ld',
    'version-cc','version-cargo','version-rustc','version-python','cargo-metadata','default-headers-0',
    'default-headers-1','selected-build','archive-text-exports','bridge-undefined','bridge-elf',
    'generic-observer-headers','generic-observer-link','release-bridge-headers','release-bridge-link',
    'release-bridge-undefined','release-objdump-version','release-bridge-symbols','release-bridge-memset',
    'native-libraries','ls-carrier','ls-native','ls-gated')
TOOLS = {'cc','sh','nm','readelf','git','cp','mkdir','python','rustup','cargo','rustc','cc1','collect2','as','ld'}
DECODER = {'tools/page-entry/selected/decoder/src/'+x for x in
    ('lib.rs','abi.rs','arena.rs','decode.rs','scan.rs','tf.rs','write_footprint.rs','admission_oneshot.rs')}

def unique(pairs):
    result = {}
    for k,v in pairs:
        need(k not in result, 'duplicate effect qualification key');result[k] = v
    return result

def decode(raw):
    return json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda x: need(False, 'nonfinite effect qualification constant'))

def authenticate(path, sha, current, pin, binary, record):
    path = pin(path);need(fact(path)['sha256'] == sha, 'explicit effect prerequisite hash')
    q = decode(path.read_bytes());directory = path.parent;b = q['build'];release = q['release_build']
    need(q['schema'] == 1 and q['profile'] == 'page-selected-effect-ls-v1' and q['status'] == 'passed' and
         q['expected_revision'] == current['revision'] and q['source'] == q['source_after'] == current and
         q['source_unchanged'] is True and q['cleanup_complete'] is True and q['error'] is None and
         q['final_errors'] == [], 'completed effect ls at the exact current committed source')
    need(type(q['cpu']) is int and q['cpu'] == record['cpu'] and q['hardware'] == record['hardware'],
         'same reserved CPU and full actual prerequisite hardware/process envelope')
    need(q['bounds'] == dict(producer.BUILD_PROFILES, **producer.BOUNDS), 'original effect prerequisite limits')
    for key in ('inputs','aliases','artifacts'):
        need(q[key+'_before'] and q[key+'_before'] == q[key+'_after'], 'complete effect final custody '+key)
    need(all(q['inputs_before'].get(p) == v for p,v in record['required_source_inputs'].items()),
         'every current runtime and evaluator source belongs to the prerequisite')
    need(q['configuration_presence'] == {p:os.path.lexists(p) for p in ('/etc/ld.so.cache','/etc/ld.so.preload')} and
         q['configuration_presence']['/etc/ld.so.preload'] is False, 'same loader configuration and no preload')
    for p,v in q['inputs_before'].items():need(fact(pin(p)) == v, 'actual prerequisite input')
    for p,v in q['aliases_before'].items():need(str(pin(p)) == v, 'actual prerequisite alias')
    for p,v in q['artifacts_before'].items():
        target = binary(pin(p));need(dict(fact(target),mode=target.stat().st_mode&0o777) == v, 'actual prerequisite artifact')

    need(b['status'] == 'passed' and b['started'] is True and b['command_completed'] is True and
         b['configuration_unchanged'] is True and b['final_errors'] == [] and
         b['registry_before'] == b['registry_after'] and set(b['tools']) == TOOLS and
         set(b['artifacts']) == set(ARTIFACTS)|{'generic-observe'}, 'complete original Build and artifact inventory')
    tools = {k:pin(v['path']) for k,v in b['tools'].items()}
    need(all(fact(tools[k]) == {n:v[n] for n in ('bytes','sha256')} for k,v in b['tools'].items()), 'actual Build tools')
    env = b['environment'];optional = {'HOME','CARGO_HOME','RUSTUP_HOME'}&set(env)
    need(set(env) == set(ENV)|optional|{'LI2_CC','LI2_CARGO','LI2_PYTHON','RUSTC','CARGO_TARGET_DIR',
         'CARGO_INCREMENTAL','CARGO_BUILD_JOBS','CARGO_NET_OFFLINE','RUSTFLAGS'} and
         all(env[k] == v for k,v in ENV.items()) and
         all(env[k] == str(tools[t]) for k,t in (('LI2_CC','cc'),('LI2_CARGO','cargo'),('LI2_PYTHON','python'),('RUSTC','rustc'))) and
         env['CARGO_TARGET_DIR'] == str(ROOT/'target') and env['CARGO_INCREMENTAL'] == '0' and
         env['CARGO_BUILD_JOBS'] == '1' and env['CARGO_NET_OFFLINE'] == 'true' and
         env['RUSTFLAGS'] == '-C relocation-model=pic -C panic=abort -C force-unwind-tables=no' and
         all(Path(env[k]).is_absolute() for k in optional), 'exact controlled Build environment')
    need(admission.cargo_configuration(env) == b['cargo_configuration'], 'actual prerequisite compiler configuration')
    artifacts = {}
    need(len(b['artifact_prefix']) == len(b['artifacts']), 'one actual retained copy per build artifact')
    for name,item in b['artifacts'].items():
        target = binary(pin(item['path']));value = fact(target)
        need(target == directory/'artifacts'/name and value == {k:item[k] for k in ('bytes','sha256')} and
             target.stat().st_mode&0o777 == item['mode'], 'actual retained Build output')
        copies = [c for c in b['artifact_prefix'] if c['name'] == name]
        need(len(copies) == 1 and copies[0]['copied'] is True and
             copies[0]['source_before'] == copies[0]['result'] == value and copies[0]['mode'] == item['mode'] and
             copies[0]['source'] == str(directory/'generic-observe' if name == 'generic-observe' else BUILD/name),
             'genuine complete artifact copy, not an old output-before fact')
        artifacts[name] = target
    archive = artifacts['decoder.a'];need(fact(archive) == q['archive'] == release['archive'], 'one current retained archive')
    need(set(b['dep_info']) == DECODER and all(fact(pin(ROOT/p)) == v for p,v in b['dep_info'].items()), 'all eight current decoder sources')
    dep = artifacts['decoder.d'].read_text().strip();prefix = str(ROOT/'target/release/libli2_page_selected_decoder.a')+': '
    need(dep.startswith(prefix) and '\n' not in dep and len(shlex.split(dep[len(prefix):])) == 8 and
         set(shlex.split(dep[len(prefix):])) == {str(ROOT/p) for p in DECODER}, 'complete actual archive dep-info')

    rows = q['commands'];need([c['name'] for c in rows] == list(NAMES), 'all thirty actual ordered prerequisite commands')
    actual = {c['name']:c for c in rows};captures = {}
    for c in rows:
        name = c['name']
        need(type(c['pid']) is int and c['pid'] > 0 and type(c['exit']) is int and c['exit'] == c['expected_exit'] == 0 and
             c['reaped'] is True and c['timed_out'] is False and c['error'] is None and c['cleanup_errors'] == [] and
             c['descriptors'] == [] and c['capture_limit'] == 16<<20 and set(c['captures']) == {'stdout','stderr'},
             'actual complete bounded prerequisite invocation')
        need(decode(pin(directory/(name+'.json')).read_bytes()) == c, 'exact retained prerequisite command row')
        for stream,item in c['captures'].items():
            target = pin(directory/(name+'.'+stream));need(item['file'] == target.name and
                fact(target) == {k:item[k] for k in ('bytes','sha256')} and item['bytes'] <= 16<<20, 'actual complete capture')
            captures[name,stream] = target.read_bytes()
    def command(name, argv, profile='metadata', environment=env):
        c = actual[name]
        need(c['argv'] == list(map(str,argv)) and c['profile'] == profile and c['bounds'] == q['bounds'][profile] and
             c['environment'] == environment, 'exact source-derived command/environment '+name)
    def stdout(name):return captures[name,'stdout']
    def quiet(name):need(not captures[name,'stderr'], 'actual empty inspection stderr '+name)
    command('source-paths',[tools['git'],'-C',ROOT,'ls-files','-z','tools/page-entry','evaluation/inprocess'],environment=ENV)
    quiet('source-paths');names = stdout('source-paths').split(b'\0')
    need(names[-1] == b'' and len(set(names[:-1])) == len(names)-1 and
         {str(ROOT/os.fsdecode(n)) for n in names[:-1] if not n.startswith(b'evaluation/inprocess/results/')} ==
         set(record['required_source_inputs']), 'complete actual current source enumeration')
    early = {k:v for k,v in env.items() if k in set(ENV)|optional}
    for name in ('cargo','rustc'):
        command('resolve-'+name,[tools['rustup'],'which',name],environment=early)
    for name in ('cc1','collect2','as','ld'):command('resolve-'+name,[tools['cc'],'-print-prog-name='+name])
    for name in ('cargo','rustc','cc1','collect2','as','ld'):
        quiet('resolve-'+name);raw = stdout('resolve-'+name).decode().strip()
        resolved = raw if Path(raw).is_absolute() else shutil.which(raw,path=ENV['PATH'])
        need(resolved is not None and pin(resolved) == tools[name], 'actual selected compiler tool')
    for name in ('cc','cargo','rustc','python'):
        command('version-'+name,[tools[name],'-vV' if name == 'rustc' else '--version']);quiet('version-'+name)
        version = stdout('version-'+name).decode().strip();number = re.search(r'\b([0-9]+)\.([0-9]+)\.([0-9]+)\b',version)
        need(version == b['versions'][name] and number is not None and
             [int(number[i]) for i in (1,2,3)] == b['numeric_versions'][name], 'actual tool version')
    for name,tool in (('decoder-rustc.txt','rustc'),('decoder-cargo.txt','cargo'),('cc-version.txt','cc')):
        need(artifacts[name].read_text().strip() == b['versions'][tool], 'compiler identity inside retained build')
    command('cargo-metadata',[tools['cargo'],'metadata','--manifest-path',PRODUCT/'decoder/Cargo.toml','--format-version','1','--locked','--offline'])
    quiet('cargo-metadata');metadata = decode(stdout('cargo-metadata'))
    locked = {(x['name'],x['version']):x for x in tomllib.loads(pin(PRODUCT/'decoder/Cargo.lock').read_text())['package']}
    need(Path(metadata['target_directory']).resolve() == ROOT/'target' and
         {(x['name'],x['version']) for x in metadata['packages']} == set(locked), 'actual locked Cargo closure')
    registry = []
    for item in metadata['packages']:
        name,version = item['name'],item['version'];lock = locked[name,version];manifest = pin(item['manifest_path'])
        if 'checksum' not in lock:
            need(manifest == PRODUCT/'decoder/Cargo.toml' and item['source'] is None, 'actual local decoder manifest')
        else:
            need(item['source'] == lock['source'], 'actual registry package identity')
            registry.append(package_check(dict(name=name,version=version,root=str(manifest.parent),checksum=lock['checksum'])))
    need(registry == b['registry_before'], 'all actual authenticated registry sources unchanged')

    builder = SimpleNamespace(tools=tools)
    default = recipes(pin(PRODUCT/'build.sh'),builder,BUILD,BUILD/'decoder.a',pin)
    def includes(label, argv, state, expected_units, used_archive):
        argv = list(map(str,argv));units = [x for x in argv if x.endswith(('.c','.S'))]
        need(units == list(map(str,expected_units)) and argv[0] == str(tools['cc']) and argv[-2] == '-o' and
             argv.count(str(used_archive)) == 1 and state['argv'] == argv, 'actual source-bound link and translation units')
        flags = [x for x in argv[1:-2] if x not in units and x != str(used_archive) and not x.startswith('-Wl,')]
        command(label,[tools['cc'],*flags,'-M','-MT','li2_timing',*units]);quiet(label)
        rules = stdout(label).decode().replace('\\\n',' ').splitlines();found = {}
        need(len(rules) == len(units) and all(x.startswith('li2_timing: ') for x in rules), 'one actual compiler include rule per TU')
        for rule in rules:
            for token in shlex.split(rule.split(':',1)[1]):
                target = pin(Path(token).absolute());found[str(target)] = fact(target)
        need(set(units) <= set(found) and found == state['headers'] and
             all(q['inputs_before'].get(p) == v for p,v in found.items()), 'complete actual compiler-M source/header closure')
    need(len(q['default_include_closure']) == 2, 'both original default compiler include observations')
    for i,(argv,state) in enumerate(zip(default,q['default_include_closure'],strict=True)):
        units = [PRODUCT.parent/x for x in producer.UNITS[:4]]+[PRODUCT/x for x in
            ('provider.c','step_owner.c','selected_selftest.S','support.c')] if i == 0 else [PRODUCT/'fixture_observe.c']
        includes('default-headers-'+str(i),argv,state,units,BUILD/'decoder.a')
    command('selected-build',[tools['sh'],PRODUCT/'build.sh'],'build')
    command('archive-text-exports',[tools['nm'],'-g','--defined-only',archive],'inspect');quiet('archive-text-exports')
    for symbol in ('rust_eh_personality','li2_decoder_tf_classify','li2_decoder_write_footprint'):
        found = [x.split() for x in stdout('archive-text-exports').splitlines() if x.split()[-1:] == [symbol.encode()]]
        need(len(found) == 1 and found[0][-2:] == [b'T',symbol.encode()] and b['archive_text_exports'].get(symbol) == 1,
             'one actual archive text definition')
    command('bridge-undefined',[tools['nm'],'-u',artifacts['bridge-selected.so']],'inspect')
    command('bridge-elf',[tools['readelf'],'-h','-l','-d','-r','-W',artifacts['bridge-selected.so']],'inspect');quiet('bridge-elf')
    need(stdout('bridge-undefined') == captures['bridge-undefined','stderr'] == b'' and
         bridge_check(artifacts['bridge-selected.so']) == b['bridge_elf'], 'actual default bridge ELF and no imports')
    observer = [tools['cc'],'-std=gnu11','-O2','-g','-Wall','-Wextra','-Werror','-I'+str(PRODUCT),
        '-Wl,--gc-sections,--exclude-libs,ALL,-z,noexecstack,--build-id=none',PRODUCT/'tests/generic/observe.c',archive,'-o',directory/'generic-observe']
    includes('generic-observer-headers',observer,q['generic_observer_headers'],[PRODUCT/'tests/generic/observe.c'],archive)
    command('generic-observer-link',observer)
    need(fact(pin(directory/'generic-observe')) == fact(artifacts['generic-observe']), 'actual copied generic observer')
    recipe = pin(PRODUCT/'build-effect-provider.sh');argv = recipes(recipe,builder,directory/'release',archive,pin)[0]
    bridge = binary(pin(directory/'release/bridge-effect-provider.so'))
    need(release['status'] == 'passed' and release['recipe'] == fact(recipe) and release['bridge'] == fact(bridge) and
         argv[-1] == str(bridge) and [x for x in argv if x.startswith('-DLI2_')] == ['-DLI2_'+x+'=1' for x in producer.MACROS] and
         all(x in argv for x in ('-O2','-g','-nostdlib','-shared','-fPIC','-fvisibility=hidden','-mgeneral-regs-only','-fno-builtin','-Werror')),
         'exact unobserved effect release recipe, with no diagnostic injection')
    includes('release-bridge-headers',argv,release,[PRODUCT.parent/x for x in producer.UNITS],archive)
    command('release-bridge-link',argv,'release_build')
    command('release-bridge-undefined',[tools['nm'],'-u',bridge],'inspect')
    need(stdout('release-bridge-undefined') == captures['release-bridge-undefined','stderr'] == b'' and
         bridge_check(bridge) == release['elf'] and bridge.stat().st_mode&0o111, 'actual executable effect ELF with no imports')
    objdump = pin(actual['release-objdump-version']['argv'][0]);need(q['inputs_before'].get(str(objdump)) == fact(objdump), 'actual objdump bytes')
    command('release-objdump-version',[objdump,'--version']);quiet('release-objdump-version');need(stdout('release-objdump-version'), 'actual objdump version')
    command('release-bridge-symbols',[tools['nm'],'-S','--defined-only',bridge],'inspect');quiet('release-bridge-symbols')
    command('release-bridge-memset',[objdump,'-d','-w','-M','att','--disassemble=memset',bridge],'inspect');quiet('release-bridge-memset')
    need(hidden_memset(bridge,body_check(bridge,stdout('release-bridge-symbols'),stdout('release-bridge-memset'),'fast',symbol_name='memset')) ==
         release['reset'], 'actual unchanged release reset body')

    original = pin('/bin/ls');interp = pin(interpreter(original));carrier = binary(pin(directory/'ls-carrier'))
    carrier_tool = pin(ROOT/'tools/page-entry/carrier.py');ns = directory/'ls-namespace'
    command('native-libraries',[interp,'--list',original],environment=producer.PROGRAM_ENV);quiet('native-libraries')
    command('ls-carrier',[tools['python'],'-B',carrier_tool,'make',original,bridge,carrier],'program',producer.PROGRAM_ENV);quiet('ls-carrier')
    command('ls-native',[original,'-d','.'],'program',producer.PROGRAM_ENV)
    command('ls-gated',[tools['python'],'-B',carrier_tool,'exec-loader','--library-root','/usr/lib64','--namespace',ns,
        carrier,original,'--',original,'-d','.'],'program',producer.PROGRAM_ENV)
    identities = decode(stdout('ls-carrier'))
    need(all(identities[k+'_sha256'] == fact(p)['sha256'] for k,p in
         (('original',original),('interpreter',interp),('bridge',bridge),('carrier',carrier))) and interpreter(carrier) == bridge,
         'actual prerequisite carrier and immutable original/interpreter/bridge identities')
    spec = importlib.util.spec_from_file_location('effect_performance_namespace',pin(ROOT/'tools/page-entry/namespace.py'))
    namespace = importlib.util.module_from_spec(spec);spec.loader.exec_module(namespace)
    objects,description = namespace.plan(original,[Path('/usr/lib64')],bytes.fromhex(fact(original)['sha256']),bytes.fromhex(fact(interp)['sha256']))
    need(description == q['namespace_plan'], 'same independently derived namespace plan')
    record['effect_namespace_plan'] = dict(description,objects=[dict(source=str(x['path']),names=x['names'],
        needed=x['info']['needed'],size=len(x['bytes']),sha256=producer.H(x['bytes']),seals=namespace.SEALS) for x in objects])
    expected = {interp:set()}
    for item in objects:
        target = pin(item['path']);need(target.read_bytes() == item['bytes'], 'actual dependency source bytes')
        expected.setdefault(target,set()).update(item['names'])
    producer.resolved_libraries(stdout('native-libraries'),expected,interp,pin)
    need(q['system_inputs'] == dict(original=fact(original),interpreter=fact(interp),
         dependencies=[dict(names=x['names'],**fact(x['path'])) for x in objects]), 'actual complete original/interpreter/dependency inputs')
    observed = decode(binary(pin(ns/'namespace.json')).read_bytes());launch = decode(binary(pin(ns/'launch.json')).read_bytes())
    need(all(observed[k] == v for k,v in description.items()) and observed['directory'] == str(ns) and
         observed['schema_version'] == 1 and observed['status'] == 'prepared_not_executed' and len(observed['objects']) == len(objects),
         'actual complete prerequisite namespace')
    fds = [];links = {}
    for obj,item in zip(observed['objects'],objects,strict=True):
        need(type(obj['fd']) is int and obj['fd'] > 2 and obj['fd'] not in fds and obj['source'] == str(item['path']) and
             obj['names'] == item['names'] and obj['needed'] == item['info']['needed'] and
             obj['descriptive_pt_interp'] == (str(item['info']['interpreter']) if item['info']['interpreter'] else None) and
             obj['sha256'] == producer.H(item['bytes']) and obj['size'] == len(item['bytes']) and obj['seals'] == namespace.SEALS and
             type(obj['device']) is int and obj['device'] > 0 and type(obj['inode']) is int and obj['inode'] > 0,
             'complete actual sealed dependency identity')
        fds.append(obj['fd'])
        for name in obj['names']:links[str(ns/name)] = '/proc/self/fd/'+str(obj['fd'])
    need(links == q['namespace_aliases'] and {p.name for p in ns.iterdir()} == {'namespace.json','launch.json'}|{Path(p).name for p in links},
         'all and only actual namespace entries')
    producer.finalize(q)
    launch_env = {k:v for k,v in producer.PROGRAM_ENV.items() if k != 'PYTHONDONTWRITEBYTECODE'}
    launch_env.update(LD_LIBRARY_PATH=str(ns),LI2_DEPENDENCY_FDS=','.join(map(str,fds)))
    need(launch == dict(schema_version=1,scope='first_entry_loader_candidate',status='prepared_not_executed',
         carrier_sha256=fact(carrier)['sha256'],carrier_size=fact(carrier)['bytes'],argv=[str(original),'-d','.'],
         environment=launch_env,dependency_fds=fds), 'exact actual default-rseq environment/argv/carrier/FD join')
    need(stdout('ls-native') == stdout('ls-gated') == b'.\n' and not captures['ls-native','stderr'], 'complete native/gated output')
    for name in ('ls-native','ls-gated'):
        row = actual[name];provenance.same(row['stdout_provenance_before'],row['stdout_provenance_after'])
    parsed,result = effects.check(captures['ls-gated','stderr'],actual['ls-gated']['pid'],actual['ls-gated']['exit'],
        actual['ls-gated']['stdout_provenance_before'])
    cases = []
    for name,lane in (('ls-native','native'),('ls-gated','gated')):
        row = actual[name];case = dict(lane=lane,status='passed',pid=row['pid'],exit=row['exit'],
            whole_process_ns=row['duration_ns'],stdout=fact(directory/(name+'.stdout')))
        if lane == 'gated':case['comparison'] = result
        cases.append(case)
    need(q['terminal_reports'] == parsed and q['cases'] == cases, 'all original strict reports and both actual prerequisite cases')
    record['effect_namespace_aliases'] = links
    record['prerequisite_configuration'] = dict(environment=env,cargo_configuration=b['cargo_configuration'])
    record['qualification'] = dict(receipt=fact(path),archive=fact(archive),bridge=fact(bridge),commands=len(rows),
        completed_subjects=2,source=current,result=result)
    return tools,bridge

def check(stderr, pid, exit_code, parent, old, base):
    parsed,result = effects.check(stderr,pid,exit_code,parent)
    return parsed['tcgets'],parsed,result['gate']

counters = lease.counters

def effect_counters(parsed):
    effects.extensions(parsed);effects.effect_exit(parsed)
    e,o = parsed['effect'],parsed['oneshot']
    return dict(selected=dict(attempts=e['attempts'],completed=e['completed'],classes=e['classes'],unreturned_exit=1),
        publication={k:o[k] for k in ('attempted','published','restored','completed','retired','refused','cpuid_patches',
            'syscall_patches','rdtsc_patches','rseq_attempts','rseq_retired','retained_records','generations')})

def project(value, receipt):
    need(receipt['profile'] == PROFILE, 'explicit effect-provider performance mode')
    for sample in receipt['samples']:
        if not sample['accepted'] or sample['lane'] != 'gated':continue
        parsed = receipt['terminal_reports']['ls-'+str(sample['sample'])+'-gated']
        need(sample['same_page_lease'] == counters(parsed) and sample['effect_provider'] == effect_counters(parsed),
             'accepted measured effect counters equal the actual complete terminal reports')
    q = receipt.get('qualification')
    if value['performance_credit']:
        need(q is not None and q['source']['revision'] == receipt['expected_revision'] and q['commands'] == 30 and
             q['completed_subjects'] == 2 and q['bridge'] == receipt['bridge'] and
             sum(s['accepted'] and s['lane'] == 'gated' for s in receipt['samples']) == 5,
             'complete current real-ls prerequisite and all five measured effect executions')
    value['profile'] = PROFILE
    value['effect_scope'] = ('Same-revision real-ls release qualification, not the old exhaustive finite-profile prerequisite. '
        'Original real ls and default inactive application rseq with the exact current unobserved effect bridge; '
        'all temporary patches restored and the final exit explicitly unreturned/unretired. Fresh-process latency is distinct '
        'from admission work; no full first-touch, steady-state instruction throughput, app9216 or full-B2 credit.')
    value['application_stress_qualification'] = False
    value['steady_state_throughput_credit'] = False
