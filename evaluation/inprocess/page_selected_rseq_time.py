"""Explicit rseq/fast timing composition; old readers and runtime stay unchanged."""
import hashlib
from pathlib import Path
import re
import shutil
import struct

from page_selected import fact, need
from page_selected_register_time_compare import decode
import page_selected_register_time_compare as timing
import page_selected_register_time_build as link
from page_selected_register_time_record import check
from page_selected_rseq_build import UNITS
from page_selected_rseq_prepare import validate as rseq_inputs
import page_selected_rseq_compare as rseq
import page_selected_fast_zero_link as fast
from page_selected_fast_memset import body_check

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
FAST = bytes.fromhex('4989f84889d189f0fcf3aa4c89c0c3')
FAST_SHA256 = '9b0962fabb10968cfa175213396b8a63e6e8b81cce83547aea6e90223d21ec9f'
REFERENCE = '20261028T035139.737337Z-page-selected-fast-memset-af08160895fb.json'
REFERENCE_FACT = dict(bytes=11600, sha256='5f5d5b5e9dea1beab60413866c985fef2233b94a693983bd0cadea237b0bf352')


def hidden_memset(path, inspected):
    """Authenticate the local function in the hidden-visibility timing DSO.

    The extracted relocatable helper still requires its original global symbol.
    This separate check joins the actual local symbol to the full ELF/objdump
    body already checked by body_check; no symbol or executable is rewritten.
    """
    data = Path(path).read_bytes()
    need(len(data) >= 64 and data[:7] == b'\x7fELF\x02\x01\x01', 'actual hidden ELF64 little endian')
    head = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    need(head[1:4] == (3,62,1) and head[11] == 64 and 0 < head[12] < 65536 and
         head[13] < head[12] and head[6]+64*head[12] <= len(data), 'whole hidden DSO section table')
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, head[6]+64*i) for i in range(head[12])]
    def content(index):
        section = sections[index]
        need(section[1] != 8 and section[4]+section[5] <= len(data), 'whole hidden file-backed section')
        return data[section[4]:section[4]+section[5]]
    found = []
    need(sum(section[1] == 2 for section in sections) == 1, 'one actual hidden static symbol table')
    for index, section in enumerate(sections):
        if section[1] not in (2,11):continue
        need(section[9] == 24 and section[5] % 24 == 0 and section[6] < len(sections) and
             sections[section[6]][1] == 3, 'complete hidden symbol table and strings')
        strings, symbols = content(section[6]), content(index)
        for offset in range(0,len(symbols),24):
            name, info, other, owner, address, size = struct.unpack_from('<IBBHQQ', symbols, offset)
            need(name < len(strings) and b'\0' in strings[name:], 'bounded hidden symbol name')
            if strings[name:strings.index(0,name)] == b'memset':
                need(section[1] == 2, 'hidden memset is not dynamically exported')
                found.append((info,other,owner,address,size))
    need(len(found) == 1, 'one actual hidden memset symbol')
    info, other, index, address, size = found[0]
    need(info == 0x02 and other == 0 and 0 < index < len(sections) and size == len(FAST),
         'exact local function binding, visibility and size')
    section = sections[index];offset = address-section[3]
    need(section[2]&6 == 6 and not section[2]&1 and 0 <= offset and offset+size <= section[5],
         'whole local function in executable readonly section')
    for relocation in sections:
        if relocation[1] in (4,9) and relocation[7] == index:
            need(relocation[5] == 0, 'local memset has no relocations')
    body = content(index)[offset:offset+size]
    need(body == FAST and hashlib.sha256(body).hexdigest() == FAST_SHA256 and
         (address,size,body.hex()) == (inspected['address'],inspected['bytes'],inspected['code_hex']),
         'hidden symbol, actual ELF, objdump and qualified primitive agree')
    return dict(binding='STB_LOCAL',type='STT_FUNC',visibility='STV_DEFAULT',
                address=address,bytes=size,sha256=FAST_SHA256)


def validate(pin):
    rseq_inputs(pin)
    manifest = decode(pin(HERE/'page_selected_rseq_time_inputs.json').read_bytes())
    need(manifest['schema'] == 1 and manifest['fast_function'] ==
         dict(bytes=len(FAST), code_hex=FAST.hex(), sha256=FAST_SHA256), 'exact qualified primitive reference')
    need(fact(pin(HERE/'results'/REFERENCE)) == REFERENCE_FACT, 'retained public primitive qualification')
    for row in manifest['sources']:
        need(fact(pin(ROOT/row['path'])) == {k: row[k] for k in ('bytes','sha256')}, 'exact rseq timing composition input')


def schema(pin):
    return decode(pin(HERE/'page_selected_rseq_schema.json').read_bytes())


def parse(data, expected_schema):
    need(type(data) is bytes and 0 < len(data) <= 65536 and data.endswith(b'\n'), 'complete bounded rseq timing report')
    lines = data.splitlines()
    first = next((i for i,line in enumerate(lines) if any(line.startswith(p) for p in timing.PREFIXES)), len(lines))
    need(first in (4,5) and first < len(lines), 'exact rseq/chain prefix before timing suffix')
    loader, repeat, run, chain, registration = rseq.reports(b'\n'.join(lines[:first])+b'\n', expected_schema)
    old = [line for line in lines[:first] if not line.startswith((b'LI2_RSEQ ', b'LI2_CHAIN '))]
    need(len(old) == first-2, 'remove exactly the independently validated rseq and chain rows')
    report = timing.parse(b'\n'.join(old+lines[first:])+b'\n')
    need((report['loader'],report['repeat'],report['run']) == (loader,repeat,run), 'both unchanged parsers bind identical original reports')
    report.update(chain=chain, rseq=registration)
    return report


def completed(report, pid, disabled):
    rseq.completed(report['loader'],report['repeat'],report['run'],report['chain'],report['rseq'],pid)
    if not disabled:
        need(report['rseq']['counts'][1] > 0, 'actual default-lane registration before real timing credit')


def gdb_runner(run, gdb, environment):
    def invoke(label, argv, **kwargs):
        if str(argv[0]) == str(gdb):
            argv = list(argv)
            if '-x' in argv:
                argv[1:1] = ['-iex','set index-cache enabled off']
            kwargs['env'] = environment
        return run(label, argv, **kwargs)
    return invoke


def tools(builder, private, pin, run, receipt):
    for key in ('objdump','objcopy'):
        builder.tools[key] = pin(shutil.which(key, path=builder.environment['PATH']))
        _, out, err = run('version-'+key, [builder.tools[key], '--version'], profile='metadata', env=builder.environment)
        need(out and not err, 'actual inspection tool identity')
        receipt['build']['versions'][key] = out.decode().strip()
        receipt['build']['tools'][key] = dict(path=str(builder.tools[key]), **fact(builder.tools[key]))
        version = re.search(r'\b([0-9]+)\.([0-9]+)(?:\.([0-9]+))?\b', out.decode())
        need(version is not None, 'actual numeric inspection tool version')
        receipt['build']['numeric_versions'][key] = [int(version[1]),int(version[2]),int(version[3] or 0)]


def qualify_fast(builder, products, root, private, pin, binary, run, receipt, inputs, outcomes, pending):
    """The same three finite C/record predicates with the actual product body."""
    tools(builder, private, pin, run, receipt)
    leaf, body = fast.extract(builder,products,root,private,pin,binary,run,receipt,pending)
    need(body == FAST and hashlib.sha256(body).hexdigest() == FAST_SHA256, 'exact actually qualified fast primitive bytes')
    receipt['fast_memset_body'] = dict(bytes=len(body), sha256=hashlib.sha256(body).hexdigest())
    selected = root/'tools/page-entry/selected';fixture = selected/'tests/register_timing'
    output = private/'fast-finite';output.mkdir()
    state = receipt['fast_finite_build'] = dict(status='failed', generated={}, units=[])
    recipe = pin(fixture/'build.sh');state['recipe'] = fact(recipe)
    values = {'$python_bin':builder.tools['python'], '$cc_bin':builder.tools['cc'], '$selected':selected,
              '$fixture':fixture, '$parent':selected.parent, '$archive':products['archive'], '$output':output}
    generators = link.recipe(recipe, '"$python_bin"');need(len(generators) == 3, 'same three finite support generators')
    for index, words in enumerate(generators):
        target = output/inputs['generators'][index]['file'];pending.append(target)
        _, out, err = run('fast-timing-generate-'+str(index), link.expand(words,values), profile='metadata', env=builder.environment)
        need(not err and decode(out) == inputs['generators'][index]['stdout'], 'exact generated support observation')
        need(fact(pin(target)) == inputs['generators'][index]['fact'], 'exact generated support bytes')
        binary(target);state['generated'][target.name] = fact(target)
    include = output/'include';include.mkdir()
    before = pin(output/'run_support.inc').read_bytes()
    need(fact(output/'run_support.inc') == inputs['generators'][1]['fact'] and before.count(fast.OLD) == 1,
         'one exact original scalar definition in maps-adapted generic support')
    after = before.replace(fast.OLD,fast.NEW)
    need(after.count(fast.NEW) == 1 and after.replace(fast.NEW,fast.OLD) == before, 'sole definition-only fast helper adapter')
    for name, data in (('run_support.inc',after), ('timing_support.inc',pin(output/'timing_support.inc').read_bytes())):
        target = include/name;pending.append(target)
        with target.open('xb') as f:f.write(data)
        binary(target);pin(target)
    state['adapter'] = dict(before=fact(output/'run_support.inc'),after=fact(include/'run_support.inc'),
                           timing_support=fact(include/'timing_support.inc'))
    commands = link.recipe(recipe, '"$cc_bin"');need(len(commands) == 1, 'one unchanged finite link template')
    layouts = []
    for mode, expected in enumerate(outcomes['commands']):
        path = output/('register-timing-'+str(mode));name = 'fast-register-timing-'+str(mode)
        argv = link.expand(commands[0],dict(values, **{'$control':mode}), ['-DLI2_RUN_TIMING_TEST=1'] if mode == 1 else [])
        need(argv.count('-I'+str(output)) == 1 and argv[-1] == str(path) and
             argv.count('-DLI2_RUN_TIMING_TEST=1') == int(mode == 1), 'same finite recipe/control with unique adapted include')
        original = list(argv);argv[argv.index('-I'+str(output))] = '-I'+str(include);argv.insert(-2,str(leaf))
        unit = dict(mode=mode,original_argv=original,argv=argv);state['units'].append(unit)
        deps = fast.headers(name+'-headers',argv,builder,pin,run,unit,[include/'run_support.inc',include/'timing_support.inc'])
        need(str(output/'run_support.inc') not in deps and str(output/'timing_support.inc') not in deps,
             'only exact adapted support was consumed')
        fast.compile_retained(name+'-link',argv,run,binary,builder,pending,receipt['final_errors'])
        unit['artifact'] = link.inspect(name,path,builder,binary,run)
        need(fast.memset_body(path)['body'] == body, 'final finite ELF has actual extracted product body')
        need(unit['artifact']['test_clock_symbols'] == int(mode == 1), 'actual normal/test object distinction')
        _, out, err = run(name+'-dwarf',[builder.tools['gdb'],'-q','-nx','-batch','-iex','set auto-load off',
            '-iex','set debuginfod enabled off','-iex','maintenance set worker-threads 1','--readnow',
            '--se='+str(path),'-x',pin(root/'evaluation/inprocess/page_selected_register_time_dwarf.py')],
            profile='metadata',env=builder.environment)
        need(not err, 'file-only DWARF stderr');layout = decode(out)
        need(set(layout) == link.ROOTS and all(layout[k]['bytes'] == v['bytes'] for k,v in unit['artifact']['symbols'].items()),
             'actual ELF and DWARF agree for every complete record')
        layouts.append(layout);unit['layout'] = layout
        item = dict(name='fast-'+expected['name'], status='failed');receipt['qualification'].append(item)
        command, out, err = run(item['name']+'-native',[path],expected=expected['exit_code'],
                                profile='finite',env=builder.environment,record=True,step=True)
        item['exit'] = command['exit']
        need(out == expected['stdout'].encode() and err == expected['stderr'].encode(), 'exact finite stdout/stderr')
        capture = command['captures']['record'];record_path = binary(private/capture['file'])
        need(fact(record_path) == {k:capture[k] for k in ('bytes','sha256')}, 'complete retained actual state record')
        item['record'] = fact(record_path);value = check(record_path.read_bytes(),layout,mode)
        for k in ('operation','completed','retained_full_records','native_references','clock_calls'):
            need(value[k] == expected[k], 'actual finite operation count '+k)
        item.update(status='accepted_observation',outcome=value)
    need(len(layouts) == 3 and all(x == layouts[0] for x in layouts), 'identical actual layout across three controls')
    need(len(receipt['qualification']) == 6 and all(x['status'] == 'accepted_observation' for x in receipt['qualification']),
         'all three original and three actual fast observer qualifications before discovery')
    state['status'] = 'passed'


def interpreter(name, configuration, builder, products, root, private, pin, binary, aliases, run, receipt):
    selected = root/'tools/page-entry/selected';output = private/name;output.mkdir()
    header = output/'register_timing_config.h'
    with header.open('xb') as f:f.write(configuration)
    binary(header)
    recipe = pin(selected/'build-rseq-timing.sh')
    state = dict(name=name,status='failed',recipe=fact(recipe),configuration=fact(header),archive=fact(products['archive']))
    receipt.setdefault('timing_builds',[]).append(state)
    commands = link.recipe(recipe, '"$cc_bin"');need(len(commands) == 1, 'one explicit rseq timing recipe')
    argv = link.expand(commands[0],{'$cc_bin':builder.tools['cc'],'$selected_dir':selected,
        '$parent_dir':selected.parent,'$archive':products['archive'],'$output':output})
    sources = [str(selected.parent/n) for n in (*UNITS,'selected/register_run_timing.c')]
    need(len(sources) == 14 and argv[-1] == str(output/'bridge-rseq-timing.so') and all(argv.count(x) == 1 for x in
         ('-O2','-nostdlib','-shared','-fPIC','-DLI2_TF_HANDOFF=1','-DLI2_REGISTER_RUN=1',
          '-DLI2_MAPS_PHASE_REUSE=1','-DLI2_RSEQ_INACTIVE=1','-DLI2_RUN_TIMING=1','-DLI2_FAST_MEMSET=1')) and
         not any('LI2_PHASE_IDENTITY_REUSE' in x or 'LI2_RUN_TIMING_TEST' in x for x in argv),
         'exact explicit rseq/fast/clock composition without identity reuse or test clock')
    state['argv'] = argv
    link.headers(name+'-headers',argv,sources,products['archive'],builder,pin,aliases,run,state)
    path = Path(argv[-1])
    try:
        run(name+'-link',argv,profile='build',env=builder.environment)
    finally:
        try:
            if path.is_file():state['artifact'] = fact(binary(path))
        except BaseException as exc:receipt['final_errors'].append('timing bridge partial retention: '+repr(exc))
    state['elf'] = link.inspect(name,path,builder,binary,run,bridge=True)
    _, symbols, err = run(name+'-symbols',[builder.tools['nm'],'-a',path],profile='inspect',env=builder.environment)
    need(not err and not any(line.split()[-1].startswith(b'application_') or line.split()[-1] == b'li2_run_timing_test_bad_clock'
         for line in symbols.splitlines() if line.split()), 'unobserved production bridge without injection adapter')
    _, symbols, err = run(name+'-memset-symbols',[builder.tools['nm'],'-S','--defined-only',path],profile='inspect',env=builder.environment)
    need(not err, 'actual reset symbols')
    _, assembly, err = run(name+'-memset-body',[builder.tools['objdump'],'-d','-w','-M','att','--disassemble=memset',path],
                            profile='inspect',env=builder.environment)
    need(not err, 'actual reset body')
    state['fast_memset_body'] = body_check(path,symbols,assembly,'fast',symbol_name='memset')
    state['hidden_memset'] = hidden_memset(path,state['fast_memset_body'])
    state.update(status='passed',artifact=fact(path));return path
