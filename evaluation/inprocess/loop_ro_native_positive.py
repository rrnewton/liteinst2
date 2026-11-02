#!/usr/bin/env python3
"""Three fresh paired-v2 subjects for RO certificate setup/positive diagnosis.

The historical fixture, policy and seed stay separate from an optional exact
current archive build receipt. Native, release and certificate-DIFF subjects
all execute now. Both causal mutation
suites, owner captures and the original full qualification remain pending.
"""
import argparse
import hashlib
import io
import tarfile
import json
import os
from pathlib import Path
import re
import shutil
import sys
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path.cwd().resolve()
sys.path[:0] = [str(ROOT/'evaluation/inprocess'), str(ROOT/'tools/page-entry')]
from checks import source
from run import hardware
from page_selected import ENV, fact, need, save
from page_selected_process import invoke
from page_selected_effect_ls import program_invoke
from persistent_dynamic import BOUNDS, digest, imported_sources, load, seed_prerequisite
from persistent_loop_effects_build import ACTIVE_PROVIDERS, FEATURES
from persistent_loop_effects_native import SCHEDULE as NATIVE_SCHEDULE, summary
from persistent_loop_effects_native_prerequisite import require_seed_record, SOURCES
from persistent_loop_native_build import (FIXTURE, application, reader_support,
    native_namespace, native_preparation, preparation)
from direct_frontier_loop_helpers import prepare_inputs
from page_selected_register_time_build import recipe, expand, headers
from page_selected import bridge_check
from page_selected_shared_decoder import source_key
from persistent_epoch_build import dynamic_original_image
from persistent_loop_effects_counter_terminal import counters, completed_choice
from persistent_fused_counter_terminal import completed
import loop_ro_certificate_reports as reports

SELECTED = ROOT/'tools/page-entry/selected'
LANES = ('release', 'differential')
SCHEDULE = (('historical-decoder-recipe', 'metadata'), ('subject-native-0-0', 'program')) + tuple(
    (lane+'-'+name, profile) for lane in LANES for name, profile in (
        ('build', 'release_build'), ('headers', 'metadata'),
        ('undefined', 'inspect'), ('symbols', 'inspect'), ('carrier', 'program'))
) + tuple(('subject-'+lane+'-0-0', 'program') for lane in LANES)
PAIR_KEYS = ('hardware', 'facts', 'seed', 'machine', 'source', 'data', 'stack',
             'base', 'page', 'entry', 'predecessor', 'endpoint', 'before', 'after', 'live')
H = lambda data: hashlib.sha256(data).hexdigest()


def historical_sources(raw, expected):
    """Authenticate a bounded Git archive; no extraction or current-source substitution."""
    need(type(raw) is bytes and len(raw) <= 16 << 20 and len(expected) == 16,
         'exact historical thirteen Rust sources, two manifests and recipe')
    allowed_directories = {str(parent)+'/' for name in expected for parent in Path(name).parents
                           if str(parent) != '.'}
    seen = set(); files = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as bundle:
        for member in bundle:
            name = member.name
            need(name not in seen and not Path(name).is_absolute() and '..' not in Path(name).parts,
                 'unique relative historical archive member')
            seen.add(name)
            if member.isdir():
                need(name.rstrip('/')+'/' in allowed_directories, 'only exact ancestor directories')
                continue
            need(member.isfile() and name in expected and member.size == expected[name]['bytes'],
                 'only expected whole regular source files')
            data = bundle.extractfile(member).read()
            value = dict(bytes=len(data), sha256=H(data))
            need(value == expected[name], 'whole historical source equals actual original compiler input')
            files[name] = value
    need(files == expected, 'every original historical source is authenticated without omission')
    return files


def retained_support(path, expected_sha, r, pin, binary, aliases, complete, run, *, current_build=None):
    """Replay only the exact 34 closed setup rows, never an old subject."""
    path = pin(path)
    need(path.name == 'receipt.json' and path.parent.parent == ROOT/'target/evaluation/inprocess'
         and fact(path)['sha256'] == expected_sha, 'explicit whole historical producer receipt')
    n = json.loads(path.read_bytes()); directory = path.parent
    need(n['profile'] == 'persistent-loop-effects-native-v1' and n['status'] == 'observed_native_references'
         and re.fullmatch('[0-9a-f]{40}', n['revision'])
         and n['revision'] == n['source']['revision'] and n['cpu'] == r['cpu']
         and n['hardware'] == r['hardware'] and n['bounds'] == BOUNDS
         and n['error'] is None and n['final_errors'] == []
         and all(n[k] is True for k in ('source_unchanged', 'inputs_unchanged', 'cleanup_complete'))
         and all(n[k] is False for k in ('owner_validated', 'mixed_policy_validated',
                                       'qualification_credit', 'performance_credit')),
         'closed historical producer and exact CPU/hardware, without current native credit')
    need(tuple((x['name'], x['profile']) for x in n['commands']) == NATIVE_SCHEDULE
         and len(n['commands']) == 82, 'complete original native82 source-owned schedule')
    for row in n['commands']: complete(row)
    rows = {x['name']: x for x in n['commands']}; used = []

    def retained(path):
        p = pin(path); key = str(p); value = fact(p)
        need(key in n['inputs'] or key in n['artifacts'], 'producer owns each reused input/artifact')
        if key in n['inputs']: need(value == n['inputs'][key], 'current whole input equals historical compiler input')
        if key in n['artifacts']:
            need(dict(fact(binary(p)), mode=p.stat().st_mode & 0o777) == n['artifacts'][key],
                 'actual retained artifact byte/mode identity')
        return p

    def capture(row, stream):
        value = row['captures'][stream]; p = retained(directory/value['file'])
        need(p.parent == directory and fact(p) == {k: value[k] for k in ('bytes', 'sha256')}
             and 0 <= value['bytes'] <= row['capture_limit'], 'whole bounded retained capture')
        return p.read_bytes()

    def recorded(name, argv, profile='metadata', expected=0, env=None, record=False):
        need(name in rows and name not in used and record is False
             and name in dict(NATIVE_SCHEDULE[20:54]), 'one closed setup replay, never a subject')
        row = rows[name]
        need(row['argv'] == list(map(str, argv)) and row['environment'] == dict(ENV if env is None else env)
             and row['profile'] == profile and row['expected_exit'] == expected == 0
             and json.loads(retained(directory/(name+'.json')).read_bytes()) == row,
             'whole actual historical argv/environment/profile/outcome')
        used.append(name); return row, capture(row, 'stdout'), capture(row, 'stderr')

    b = n['build']; tools = {name: retained(value['path']) for name, value in b['tools'].items()}
    need(all(fact(tools[name]) == {k: value[k] for k in ('bytes', 'sha256')}
             for name, value in b['tools'].items()) and Path(sys.executable).resolve() == tools['python'],
         'whole original tool identities and actual Python')
    need(b['status'] == 'passed' and b['command_completed'] is True and b['final_errors'] == []
         and b['configuration_unchanged'] is True and b['registry_before'] == b['registry_after']
         and b['decoder_features'] == list(FEATURES), 'closed original effects archive build')
    archive = retained(b['artifacts']['decoder.a']['path'])
    need(archive == directory/'artifacts/decoder.a' and fact(archive) == n['archive']
         and fact(archive) == {k: b['artifacts']['decoder.a'][k] for k in ('bytes', 'sha256')}
         and archive.read_bytes()[:8] == b'!<arch>\n', 'whole retained actual archive')
    need(set(b['dep_info']) == {'tools/page-entry/selected/decoder/src/'+name for name in SOURCES},
         'exact thirteen-source effects archive domain')
    recipe_path = pin(SELECTED/'build-loop-effects-decoder.sh')
    historical_recipe = n['inputs'][str(recipe_path)]
    if current_build is None:
        for name, value in b['dep_info'].items():
            need(fact(retained(ROOT/name)) == value, 'current Rust source equals actual retained compiler input')
        for name in ('decoder/Cargo.toml', 'decoder/Cargo.lock'):
            retained(SELECTED/name)
        _, recipe_bytes, recipe_error = run('historical-decoder-recipe', [tools['git'], '-c',
            'index.threads=1', '-c', 'core.preloadIndex=false', 'show',
            n['revision']+':tools/page-entry/selected/build-loop-effects-decoder.sh'])
        need(not recipe_error and dict(bytes=len(recipe_bytes), sha256=H(recipe_bytes)) == historical_recipe,
             'whole actual historical Git recipe equals the retained archive producer input')
    else:
        # These bytes authenticate only the old fixture/policy archive. The
        # production links below must use the separately validated current one.
        expected_sources = dict(b['dep_info'])
        for name in ('decoder/Cargo.toml', 'decoder/Cargo.lock', 'build-loop-effects-decoder.sh'):
            relative = 'tools/page-entry/selected/'+name
            expected_sources[relative] = n['inputs'][str(ROOT/relative)]
        need(all(n['inputs'][str(ROOT/name)] == value for name,value in expected_sources.items()),
             'all historical Rust/config/recipe facts belong to the original producer')
        _, raw, error = run('historical-decoder-recipe', [tools['git'], '-C', ROOT, '-c', 'index.threads=1',
            '-c', 'core.preloadIndex=false', 'archive', '--format=tar', n['revision'], '--', *sorted(expected_sources)])
        need(not error, 'bounded historical source archive command')
        historical_sources(raw, expected_sources)
    for name in ('/etc/ld.so.cache', '/etc/ld.so.preload'):
        r['presence'][name] = os.path.lexists(name)
        need(r['presence'][name] == n['presence'][name], 'original loader configuration presence')
        if r['presence'][name]: retained(name)
    need(r['presence']['/etc/ld.so.preload'] is False, 'no global preload')
    builder = SimpleNamespace(tools=tools, environment=b['environment'], record=b,
        retained=directory/'artifacts', paths=dict(archive=archive), mov_guard=True,
        linked_epoch=True, scalar_span=True,
        extra_decoder_sources=('region.rs', 'mov_guard.rs', 'scalar_read.rs', 'loop_scalar.rs', 'byte_mov_guard.rs'),
        decoder_features=FEATURES)
    holder = {}; original = application(builder, directory, retained, retained, aliases, recorded, holder)
    need(holder['application_build'] == n['application_build'], 'whole unchanged fixture recipe/headers/ELF/helper facts')
    reader, _, policy = reader_support(builder, directory, retained, retained, recorded, holder)
    need(holder['reader_support'] == n['reader_support'], 'whole retained native-policy build')
    gdb = retained(shutil.which('gdb', path=ENV['PATH'])); layout_script = retained(FIXTURE/'layout.py')
    _, out, err = recorded('layout-gdb-version', [gdb, '--version'], env=builder.environment)
    need(out and not err, 'actual native layout tool identity')
    _, out, err = recorded('native-layout', [gdb, '-q', '-nx', '-nh', '-batch', '-iex', 'set auto-load off',
        '-iex', 'set debuginfod enabled off', '-iex', 'set index-cache enabled off',
        '-iex', 'maintenance set worker-threads 1', '--readnow', '--se='+str(original), '-x', layout_script],
        profile='inspect', env=dict(builder.environment, MALLOC_ARENA_MAX='1'))
    layout_path = retained(directory/'native-dwarf-layout.json'); layout = json.loads(out)
    need(not err and out.endswith(b'\n') and out.count(b'\n') == 1 and layout_path.read_bytes() == out
         and n['native_layout'] == dict(path=str(layout_path), artifact=fact(layout_path),
             application=fact(original), observer=fact(layout_script)), 'whole original native DWARF observation')
    image = reader.elf(original.read_bytes(), policy, layout, holder['application_build']['headers'])
    native_namespace(original, holder['application_build'], retained, holder)
    need(holder['native_namespace'] == n['native_namespace'], 'whole original empty native namespace')
    holder.update(cpu=r['cpu'], commands=n['commands'][:54], seed_prerequisite=dict(planned=1,
        status='unexecuted', launched=False, expected_exit=0, bounds=BOUNDS['seed'],
        completed_applications=0, owner_subjects=0, performance_credit=False))
    seed = seed_prerequisite(builder, directory, retained, retained, recorded, holder)
    require_seed_record(holder['seed_prerequisite'], n['seed_prerequisite'])
    seed = (*seed, capture(rows['seed-prerequisite'], 'stdout'))
    need(tuple(used) == tuple(name for name, _ in NATIVE_SCHEDULE[20:54]), 'all 34 exact setup replay rows')
    r['retained_inputs'] = dict(receipt=fact(path), revision=n['revision'], source=n['source'],
        cpu=n['cpu'], hardware=n['hardware'], archive=fact(archive), original=fact(original),
        recorded_setup=used, current_decoder_and_fixture_compiled_sources_equal=True,
        archive_build_recipe=dict(historical=historical_recipe, historical_revision=n['revision'],
            current=fact(recipe_path), current_used_to_rebuild=False), old_subjects_replayed=0,
        historical_qualification_credit=False)
    if current_build is not None:
        current, current_archive, proof = current_build
        need(current.tools == builder.tools, 'actual current and historical compiler/tool identities remain exact')
        r['retained_inputs']['current_decoder_and_fixture_compiled_sources_equal'] = False
        r['retained_inputs'].update(current_fixture_compiled_sources_equal=True,
            historical_decoder_sources_authenticated=True, current_archive=proof,
            production_archive_is_historical=False)
        builder, archive = current, current_archive
    return builder, archive, original, reader, image, seed, holder['application_build']


def build_ro(builder, archive, original, directory, pin, binary, aliases, run, state, mode):
    """Execute the real source-owned recipe, then bind its exact compiler closure."""
    output = directory/'build'; output.mkdir()
    script = pin(SELECTED/'build-persistent-loop-ro-certificate.sh')
    dependencies = ('persistent_epoch_binding', 'persistent_group_binding',
        'persistent_retained_two_binding', 'persistent_active_domain_binding',
        'persistent_startup_binding', 'persistent_loop_binding')
    selected = SELECTED.resolve(strict=True)
    paths = {name: pin(selected/(name+'.py')) for name in dependencies}
    for name, path in paths.items():
        need(name not in sys.modules or Path(sys.modules[name].__file__).resolve(strict=True) == path,
             'preexisting binding dependency has its canonical selected source')
    previous_path = list(sys.path)
    try:
        sys.path.insert(0, str(selected))
        binder = load('finite_ro_binding', selected/'persistent_loop_ro_certificate_binding.py', pin)
    finally:
        sys.path[:] = previous_path
    need(all(name in sys.modules and Path(sys.modules[name].__file__).resolve(strict=True) == path
             for name, path in paths.items()), 'all six actual canonical binding dependencies loaded')
    imported_sources(pin)
    values = [dict(path=name, **fact(pin(SELECTED/name))) for name in binder.LEAVES]
    need(len(values) == len({v['path'] for v in values}), 'distinct complete RO source binding')
    for value in values:
        if value['path'].endswith('.rs'):
            need(builder.record['dep_info'][source_key(ROOT, SELECTED, value['path'])]
                 == {k: value[k] for k in ('bytes', 'sha256')}, 'bound Rust belongs to retained archive')
    image = dynamic_original_image(original)
    policy = digest(dict(sources=values, original=image, mode=mode))
    environment = dict(builder.environment, LI2_CC=str(builder.tools['cc']), LI2_PYTHON=str(builder.tools['python']))
    _, out, err = run('build', [builder.tools['sh'], script, archive, original, output, mode],
                      profile='release_build', env=environment)
    need(out == err == b'', 'actual RO recipe has no diagnostics')
    manifest = binary(output/'persistent_loop_ro_certificate_binding.json')
    binding = json.loads(manifest.read_bytes())
    constants = dict(version=1, native_probe=True, parse_memo=True, unregistered=True,
        subentry=True, cross_pair=True, direct_frontier=True, bounded_fused=True,
        bounded_loop=True, policy_version=12, fallback_policy=11,
        encoding_domain=dict(version=2, policies=[11, 12, 13], near_record=1, far_record=2,
            miss='source-derived-rel32-or-rip-indirect-u64', literal_bytes=8,
            literal_boundaries=0, old_pf_api=False), header_version=2, chooser_version=12,
        decoder_read_version=2, effects=dict(binding_version=1, policy_version=13,
            scalar_version=3, mov_version=2, selection_order=[12, 13, 11]), capture_version=None,
        pf_refusals=dict(version=1, reason=256, shared_reasons=18, abi2=False))
    need(set(binding) == set(constants) | {'profile', 'mode', 'archive', 'policy_sha256',
             'original', 'sources', 'headers', 'byte_certificate', 'history_certificate'}
         and digest({key: binding[key] for key in constants}) == digest(constants)
         and binding['profile'] == 'persistent-loop-ro-certificate-'+mode+'-v1'
         and binding['mode'] == mode and binding['archive'] == fact(archive)
         and binding['original'] == image and binding['sources'] == values
         and binding['policy_sha256'] == policy and binding['capture_version'] is None
         and binding['byte_certificate'] == dict(version=1, sealed_generation=True, source_lease=False,
             mirror='isolated-anonymous-RO', root='isolated-anonymous-RO', mirror_pages=89, slots=2,
             full_scan_fallback=True, every_hit_full_scan=mode=='differential',
             old_capture_compatible=False, qualification_credit=False)
         and binding['history_certificate'] == dict(version=1, cells=3, saved_completion='isolated-anonymous-RO',
             witnesses='isolated-anonymous-RO', complete_live_predicates=True,
             every_hit_reconstruction=mode=='differential', qualification_credit=False),
         'exact source/archive/image/mode certificate binding, never old capture ABI')
    need(set(binding['headers']) == {'linked_epoch_config.h', 'persistent_group_config.h', 'loop_ro_certificate_config.h'},
         'all three actual configuration headers')
    for name, value in binding['headers'].items():
        need(fact(binary(output/name)) == value, 'whole generated immutable header')
    expected_config = ('#ifndef LI2_LOOP_RO_CERTIFICATE_CONFIG_H\n#define LI2_LOOP_RO_CERTIFICATE_CONFIG_H\n'
        '#define LI2_LOOP_RO_CERTIFICATE 1\n#define LI2_SEALED_BYTE_CERTIFICATE 1\n'
        '#define LI2_PERSISTENT_SEALED_GENERATION 1\n'+
        ('#define LI2_SEALED_BYTE_CERTIFICATE_DIFFERENTIAL 1\n' if mode=='differential' else '')+'#endif\n').encode()
    need((output/'loop_ro_certificate_config.h').read_bytes() == expected_config, 'exact certificate mode, maintained maps unchanged')
    literal = lambda value: '{'+','.join('0x'+value[i:i+2] for i in range(0, 64, 2))+'}'
    expected_linked = ('#ifndef LI2_LINKED_EPOCH_CONFIG_H\n#define LI2_LINKED_EPOCH_CONFIG_H\n'
        '#define LI2_LINK_BINDING_VERSION 1\n#define LI2_LINK_ARCHIVE_SHA256 '+literal(fact(archive)['sha256'])+
        '\n#define LI2_LINK_POLICY_SHA256 '+literal(policy)+'\n#endif\n').encode()
    expected_persistent = ('#ifndef LI2_PERSISTENT_GROUP_CONFIG_H\n#define LI2_PERSISTENT_GROUP_CONFIG_H\n'
        '#define LI2_PG_BINDING_VERSION 1\n#define LI2_PG_GROUP_BINDING_VERSION 4\n'
        '#define LI2_PG_LOOP_RO_BINDING_VERSION 1\n'
        '#define LI2_PG_LOOP_BINDING_VERSION 1\n#define LI2_PG_LOOP_POLICY_VERSION 12\n'
        '#define LI2_PG_LOOP_FALLBACK_VERSION 11\n#define LI2_PG_LOOP_ENCODING_VERSION 2\n'
        '#define LI2_PG_LOOP_EFFECTS_BINDING_VERSION 1\n#define LI2_PG_LOOP_EFFECTS_POLICY_VERSION 13\n'
        '#define LI2_PG_LOOP_EFFECTS_SCALAR_VERSION 3\n#define LI2_PG_LOOP_EFFECTS_MOV_VERSION 2\n'
        '#define LI2_PG_ARCHIVE_SHA256 '+literal(fact(archive)['sha256'])+
        '\n#define LI2_PG_POLICY_SHA256 '+literal(policy)+'\n#endif\n').encode()
    need((output/'linked_epoch_config.h').read_bytes() == expected_linked
         and (output/'persistent_group_config.h').read_bytes() == expected_persistent,
         'whole independently reconstructed source/archive/image policy headers')
    rows = recipe(script, '"$cc_bin"'); need(len(rows) == 1, 'one actual RO link command')
    substitutions = {'$cc_bin': builder.tools['cc'], '$selected_dir': SELECTED,
        '$parent_dir': SELECTED.parent, '$archive': archive, '$output': output}
    argv = expand(rows[0], substitutions)
    old = recipe(pin(SELECTED/'build-persistent-loop-effects.sh'), '"$cc_bin"')
    need(len(old) == 1, 'one unchanged effects release recipe')
    expected = expand(old[0], substitutions)
    expected[expected.index('-Werror')+1:expected.index('-Werror')+1] = ['-include', str(output/'loop_ro_certificate_config.h')]
    expected.insert(expected.index('-Wl,-e,_start,-Bsymbolic,-z,now,-z,relro,-z,noexecstack,--build-id=none,--no-undefined'),
        '-Wl,--undefined=li2_lifecycle_sealed_code_query,--undefined=li2_pg_storage_query')
    expected[-1] = str(output/'bridge-persistent-loop-ro-certificate.so')
    need(argv == expected, 'whole old production flags/TUs/link roots, plus exact RO include and providers only')
    units = [x for x in argv if x.endswith(('.c', '.S'))]
    state.update(recipe=fact(script), argv=argv, binding=binding, manifest=fact(manifest))
    headers('headers', argv, units, archive, builder, pin, aliases, run, state)
    for value in values:
        if value['path'].endswith(('.c', '.h', '.inc')):
            need(state['headers'].get(str((SELECTED/value['path']).resolve()))
                 == {k: value[k] for k in ('bytes', 'sha256')}, 'every bound C leaf is in actual compiler-M closure')
    for name, value in binding['headers'].items():
        need(state['headers'].get(str(output/name)) == value, 'actual compiled config bytes')
    bridge = binary(Path(argv[-1])); state['elf'] = bridge_check(bridge)
    _, out, err = run('undefined', [builder.tools['nm'], '-u', bridge], profile='inspect', env=builder.environment)
    need(out == err == b'', 'no unresolved imports')
    _, out, err = run('symbols', [builder.tools['nm'], '-S', '--defined-only', bridge], profile='inspect', env=builder.environment)
    need(not err, 'complete actual compiled symbols')
    for name in ACTIVE_PROVIDERS + ('li2_lifecycle_sealed_code_query', 'li2_pg_storage_query'):
        found = [line.split() for line in out.splitlines() if line.split()[-1:] == [name.encode()]]
        need(len(found) == 1 and len(found[0]) == 4 and found[0][2] in (b't', b'T')
             and int(found[0][1], 16) > 0, 'one actual complete provider '+name)
    for name in ('pe', 'sg_owner', 'lhc'):
        found = [line.split() for line in out.splitlines() if line.split()[-1:] == [name.encode()]]
        need(len(found) == 1 and len(found[0]) == 4 and found[0][2] in (b'b', b'B')
             and int(found[0][0], 16) % 4096 == 0 and int(found[0][1], 16) % 4096 == 0,
             'actual isolated page-aligned certificate/owner storage '+name)
    state.update(bridge=fact(bridge), status='compiled_diagnostic_only')
    return bridge


def app_pair(reader, native, actual):
    need(native['lane'] == 0 and actual['lane'] == 1 and native['mode'] == actual['mode'] == 0
         and native['placement'] == actual['placement'] == 0
         and native['native_reference_complete'] is True and native['application_complete'] is True
         and native['actual_fault'] is False and native['native_frames'] == 107
         and native['native_instructions'] == 106 and actual['application_complete'] is True
         and actual['native_reference_complete'] is False and actual['actual_fault'] is False
         and actual['native_frames'] == actual['native_instructions'] == 0 and actual['frames'] == [],
         'fresh complete native reference and complete runtime application, no invented runtime frames')
    need(all(reader.identical(native[key], actual[key]) for key in PAIR_KEYS),
         'whole actual source/data/stack/seed/GPR/flags/vector/selector application state equals fresh native')
    return dict(native_frames=107, native_instructions=106, compared_fields=list(PAIR_KEYS),
        source_bytes=8192, data_bytes=8192, stack_bytes=224, app_boundary_state_equal=True,
        interior_owner_state_observed=False, focal_certificate_attribution=False)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    ap.add_argument('--native-receipt', type=Path, required=True)
    ap.add_argument('--native-receipt-sha256', required=True)
    ap.add_argument('--current-build-receipt', type=Path)
    ap.add_argument('--current-build-sha256')
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args(); affinity = os.sched_getaffinity(0)
    need(sys.version_info[:2] == (3, 12) and not sys.flags.optimize and len(affinity) == 1
         and re.fullmatch('[0-9a-f]{40}', a.expect_revision)
         and re.fullmatch('[0-9a-f]{64}', a.native_receipt_sha256), 'Python3.12/assertions, reserved singleton and exact identities')
    need((a.current_build_receipt is None) == (a.current_build_sha256 is None),
         'explicit current build receipt and whole hash are supplied together')
    cpu = next(iter(affinity)); private = a.output.absolute()
    need(private.parent == ROOT/'target/evaluation/inprocess' and not private.exists(), 'fresh output direct child')
    private.mkdir(); pins, artifacts, aliases = {}, {}, {}
    r = dict(schema=1, profile='loop-ro-native-positive-v1', status='failed', revision=a.expect_revision,
        cpu=cpu, hardware=hardware(cpu), source=None, argv=[sys.executable, '-B', *sys.argv],
        bounds=dict(BOUNDS), commands=[], builds={}, namespace_aliases={}, presence={},
        error=None, final_errors=[], source_unchanged=False, inputs_unchanged=False, cleanup_complete=False,
        causal_suites='pending_unexecuted', owner_credit=False, qualification_credit=False, performance_credit=False,
        cases=[dict(label='subject-'+lane+'-0-0', lane=0 if lane=='native' else 1,
            build_lane=lane, mode=0, placement=0, control=0, cpu=cpu, expected_exit=0,
            status='unexecuted', launched=False) for lane in ('native', *LANES)])

    def pin(path):
        lexical = Path(os.path.abspath(path)); p = lexical.resolve(strict=True); value = fact(p)
        need(str(p) not in pins or pins[str(p)] == value, 'stable whole input')
        need(str(lexical) not in aliases or aliases[str(lexical)] == str(p), 'stable input alias')
        pins[str(p)] = value; aliases[str(lexical)] = str(p); return p

    def binary(path):
        p = pin(path); value = dict(fact(p), mode=p.stat().st_mode & 0o777)
        need(str(p) not in artifacts or artifacts[str(p)] == value, 'stable artifact bytes/mode')
        artifacts[str(p)] = value; return p

    def closure():
        need(source() == r['source'] and os.sched_getaffinity(0) == {cpu}, 'same clean source and reserved CPU')
        need(all(fact(p) == v for p, v in pins.items()), 'whole input closure')
        need(all(dict(fact(p), mode=Path(p).stat().st_mode & 0o777) == v for p, v in artifacts.items()), 'whole artifact closure')
        need(all(str(Path(p).resolve(strict=True)) == v for p, v in aliases.items()), 'input alias closure')
        need(all(os.path.lexists(p) == v for p, v in r['presence'].items()), 'loader configuration presence')
        need(all(Path(p).is_symlink() and os.readlink(p) == v for p, v in r['namespace_aliases'].items()), 'namespace alias closure')

    def complete(row):
        need(type(row['exit']) is int and row['exit'] == row['expected_exit']
             and row['timed_out'] is False and row['error'] is None and row['reaped'] is True
             and row['cleanup_errors'] == [] and type(row['descriptors']) is list
             and all(d.get('closed') is True for d in row['descriptors'])
             and row['bounds'] == BOUNDS[row['profile']] and row['capture_limit'] == 16 << 20,
             'exact bounded outcome and process/descriptor closure')

    def run(name, argv, profile='metadata', expected=0, env=None, record=False):
        closure()
        need(len(r['commands']) < len(SCHEDULE) and (name, profile) == SCHEDULE[len(r['commands'])]
             and expected == 0 and record is name.startswith(('subject-release-', 'subject-differential-')),
             'fixed14 schedule, zero exits, only runtime subjects have private observer descriptors')
        row = dict(name=name, argv=list(map(str, argv)), environment=dict(ENV if env is None else env),
            profile=profile, bounds=BOUNDS[profile], capture_limit=16 << 20, expected_exit=0)
        r['commands'].append(row)
        try:
            out, err = (program_invoke if record else invoke)(row, private, cpu, record=record)
            complete(row); return row, out, err
        finally:
            for value in row.get('captures', {}).values():
                try: need(fact(binary(private/value['file'])) == {k: value[k] for k in ('bytes', 'sha256')}, 'whole fresh capture')
                except BaseException as error: r['final_errors'].append(repr(error))
            p = private/(name+'.json')
            if p.exists():
                try: need(json.loads(binary(p).read_bytes()) == row, 'whole fresh command row')
                except BaseException as error: r['final_errors'].append(repr(error))
            save(private/'receipt.json', r)
            print(json.dumps(dict(command=name, exit=row.get('exit'), duration_ns=row.get('duration_ns'))), flush=True)

    try:
        r['source'] = source(); need(r['source']['revision'] == a.expect_revision, 'exact clean current source')
        pin(__file__); imported_sources(pin)
        current = None
        if a.current_build_receipt is not None:
            from loop_ro_current_archive import current_archive
            current = current_archive(a.current_build_receipt, a.current_build_sha256, ROOT, pin, binary, aliases)
        builder, archive, original, reader, image, seed, app = retained_support(
            a.native_receipt, a.native_receipt_sha256, r, pin, binary, aliases, complete, run, current_build=current)
        launch = pin(FIXTURE/'launch.py')
        first = r['cases'][0]; directory = private/first['label']; directory.mkdir()
        first.update(status='failed', launched=True)
        row, out, err = run(first['label'], [builder.tools['python'], '-B', launch, '--root', ROOT,
            '--role', 'native', '--case', 0, '--placement', 0, '--control', 0, '--original', original,
            '--library-root', original.parent, '--preparation', directory/'preparation.json'], profile='program')
        need(err == b'' and set(row['captures']) == {'stdout', 'stderr'}, 'fresh native whole output and empty stderr')
        native_preparation(directory/'preparation.json', row, original, 0, 0, cpu, binary)
        native = reader.read(out, 0, 0, 0, row['exit'], image, row['pid'], cpu, seed)
        first.update(status='observed_fresh_native_reference', native=summary(native, 0, 0))
        subjects = {}
        for lane in LANES:
            directory = private/(lane+'-build'); directory.mkdir(); state = r['builds'][lane] = {}
            def lane_run(name, argv, profile='metadata', expected=0, env=None, record=False):
                return run(lane+'-'+name, argv, profile, expected, env, record)
            bridge = build_ro(builder, archive, original, directory, pin, binary, aliases, lane_run, state, lane)
            subjects[lane] = prepare_inputs(original, bridge, builder, directory, pin, binary, lane_run, state, app)
        imported_sources(pin)
        for case in r['cases'][1:]:
            lane, label = case['build_lane'], case['label']; case.update(status='failed', launched=True)
            directory = private/label; directory.mkdir()
            _, roots, objects, description, _, _, carrier = subjects[lane]
            try:
                row, out, err = run(label, [builder.tools['python'], '-B', launch, '--root', ROOT,
                    '--role', 'gated', '--case', 0, '--placement', 0, '--control', 0, '--original', original,
                    '--library-root', original.parent, '--preparation', directory/'preparation.json',
                    '--carrier', carrier, '--namespace', directory/'namespace', '--record-fd', '{record_fd}'],
                    profile='program', record=True)
                preparation(case, row, directory, original, roots, objects, description, carrier, private, binary, r)
                need(row['captures']['record']['bytes'] == 0, 'plain profile emits no old owner capture')
                actual = reader.read(out, 1, 0, 0, row['exit'], image, row['pid'], cpu, seed)
                case['pair'] = app_pair(reader, native, actual)
                certificate, remaining = reports.split(err, lane)
                raw = counters(remaining); completed(raw)
                loop, effects, domain, sub = (raw[k] for k in ('LI2_LOOP_RUNTIME', 'LI2_LOOP_EFFECTS',
                    'LI2_PERSISTENT_UNREGISTERED', 'LI2_PERSISTENT_SUBENTRY'))
                need(loop['status'] == loop['failure_code'] == loop['scope'] == 0, 'successful actual LOOP terminal')
                completed_choice(loop, effects, dict(persistent=domain, subentry=sub))
                byte, history = certificate['byte_certificate'], certificate['history_certificate']
                need(byte['issues'] == domain['publications'] > 0 and byte['hits'] > 0 and byte['postseal_bytes'] > 0
                     and byte['live_queries'] > 0 and history['issues'] == domain['completed'] > 0
                     and history['hits'] > 0 and history['full_calls'] > 0,
                     'genuine global first proofs and actual byte/history hits, no focal attribution')
                case.update(status='observed_positive_application_pair', raw_sha256=actual['raw_sha256'],
                    certificate=certificate, terminal_counters=raw,
                    terminal_scope='typed actual certificate/LOOP/PF counters; no full owner capture or original reader-controls credit')
            except Exception as error: case['error'] = type(error).__name__+': '+str(error)
        need(len(r['commands']) == 14 and [c['status'] for c in r['cases']] ==
             ['observed_fresh_native_reference', 'observed_positive_application_pair', 'observed_positive_application_pair'],
             'all three fresh subjects and both complete positive pairs required')
        r['status'] = 'observed_positive_application_pairs'
    except BaseException as error: r['error'] = type(error).__name__+': '+str(error)
    finally:
        for case in r['cases']:
            rows = [x for x in r['commands'] if x['name'] == case['label']]
            if rows:
                row = rows[0]; case.update(exit=row.get('exit'), timed_out=row.get('timed_out'),
                    duration_ns_validation_only=row.get('duration_ns'),
                    captures={k: {j: v[j] for j in ('bytes', 'sha256')} for k, v in row.get('captures', {}).items()})
        try:
            imported_sources(pin); closure(); r['source_unchanged'] = r['inputs_unchanged'] = True
            for row in r['commands']:
                need(json.loads(binary(private/(row['name']+'.json')).read_bytes()) == row, 'final whole command row')
                for value in row.get('captures', {}).values():
                    need(fact(binary(private/value['file'])) == {k: value[k] for k in ('bytes', 'sha256')}, 'final whole capture')
        except BaseException as error: r['final_errors'].append(type(error).__name__+': '+str(error))
        r['cleanup_complete'] = bool(r['commands']) and all(x.get('reaped') is True and x.get('cleanup_errors') == []
            and type(x.get('descriptors')) is list and all(d.get('closed') is True for d in x['descriptors']) for x in r['commands'])
        if r['error'] or r['final_errors'] or not r['cleanup_complete']: r['status'] = 'failed'
        r.update(inputs=pins, artifacts=artifacts, aliases=aliases); save(private/'receipt.json', r)
        public = {k: r[k] for k in ('schema', 'profile', 'status', 'revision', 'cpu', 'bounds',
            'source_unchanged', 'inputs_unchanged', 'cleanup_complete', 'causal_suites', 'owner_credit',
            'qualification_credit', 'performance_credit')}
        public.update(receipt=fact(private/'receipt.json'), hardware=r['hardware'],
            commands=[{k: x.get(k) for k in ('name', 'expected_exit', 'exit', 'timed_out', 'duration_ns')} for x in r['commands']],
            cases=[{k: c[k] for k in ('label', 'status', 'launched', 'exit', 'timed_out', 'duration_ns_validation_only',
                'captures', 'native', 'pair', 'certificate') if k in c} for c in r['cases']],
            reproduction_argv=['python3.12', '-B', 'evaluation/inprocess/loop_ro_native_positive.py',
                '--expect-revision', a.expect_revision, '--native-receipt', '<retained-native-receipt.json>',
                '--native-receipt-sha256', a.native_receipt_sha256,
                *(['--current-build-receipt', '<closed-current-program-build-receipt.json>',
                   '--current-build-sha256', a.current_build_sha256] if a.current_build_receipt is not None else []),
                '--output', 'target/evaluation/inprocess/<fresh-positive-output>'],
            scope='Positive setup diagnostic only: fresh native/app boundary pairs and global certificate hits. Causal mutations, interior owner capture and original qualification remain pending.')
        text = json.dumps(public, sort_keys=True, indent=2)+'\n'
        need(len(text.encode()) < 24 << 10 and '/home/' not in text and str(ROOT) not in text,
             'bounded public observation without host paths or raw logs')
        save(private/'summary.json', public)
    print(json.dumps(dict(status=r['status'], receipt=str((private/'receipt.json').relative_to(ROOT)))), flush=True)
    return int(r['status'] != 'observed_positive_application_pairs')


if __name__ == '__main__': raise SystemExit(main())
