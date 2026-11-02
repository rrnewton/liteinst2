"""Actual source-owned RO reason release build; no archive or subject authority."""
import json
from pathlib import Path
import sys
from page_selected import fact, need, bridge_check
from persistent_dynamic import load, imported_sources, digest
from persistent_loop_effects_build import ACTIVE_PROVIDERS
from persistent_epoch_build import dynamic_original_image
from page_selected_register_time_build import recipe, expand, headers
from page_selected_shared_decoder import source_key

ROOT = Path(__file__).resolve().parents[2]
SELECTED = ROOT/'tools/page-entry/selected'
REASON_MACROS = ('LOOP_RO_REASONS', 'PERSISTENT_GROUP_COUNTERS', 'PERSISTENT_RETAINED_TWO_COUNTERS', 'PERSISTENT_LOOP_COUNTERS', 'PERSISTENT_LOOP_EFFECTS_COUNTERS')


def build_ro_reasons(builder, archive, original, directory, pin, binary, aliases, run, state, mode="release"):
    """Execute the real source-owned recipe, then bind its exact compiler closure."""
    need(mode == 'release', 'ABI5 reason observer is a separate release-only profile')
    output = directory/'build'; output.mkdir()
    script = pin(SELECTED/'build-persistent-loop-ro-reasons.sh')
    dependencies = ('persistent_epoch_binding', 'persistent_group_binding',
        'persistent_retained_two_binding', 'persistent_active_domain_binding',
        'persistent_startup_binding', 'persistent_loop_binding', 'persistent_loop_ro_certificate_binding')
    selected = SELECTED.resolve(strict=True)
    paths = {name: pin(selected/(name+'.py')) for name in dependencies}
    for name, path in paths.items():
        need(name not in sys.modules or Path(sys.modules[name].__file__).resolve(strict=True) == path,
             'preexisting binding dependency has its canonical selected source')
    previous_path = list(sys.path)
    try:
        sys.path.insert(0, str(selected))
        binder = load('ro_reason_binding', selected/'persistent_loop_ro_reasons_binding.py', pin)
    finally:
        sys.path[:] = previous_path
    need(all(name in sys.modules and Path(sys.modules[name].__file__).resolve(strict=True) == path
             for name, path in paths.items()), 'all seven actual canonical binding dependencies loaded')
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
    manifest = binary(output/'persistent_loop_ro_reasons_binding.json')
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
             'original', 'sources', 'headers', 'byte_certificate', 'history_certificate', 'counter'}
         and digest({key: binding[key] for key in constants}) == digest(constants)
         and binding['profile'] == 'persistent-loop-ro-reasons-'+mode+'-v1'
         and binding['counter'] == dict(version=5,bytes=1696,page=4096)
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
    expected[expected.index('-Werror')+1:expected.index('-Werror')+1] = [
        '-DLI2_'+name+'=1' for name in REASON_MACROS]
    expected[-1] = str(output/'bridge-persistent-loop-ro-reasons.so')
    need(argv == expected, 'whole old production flags/TUs/link roots plus exact RO and ABI5 reason selectors')
    units = [x for x in argv if x.endswith(('.c', '.S'))]
    state.update(recipe=fact(script), argv=argv, binding=binding, manifest=fact(manifest))
    headers('headers', argv, units, archive, builder, pin, aliases, run, state)
    for value in values:
        if value['path'].endswith(('.c', '.h', '.inc')):
            need(state['headers'].get(str((SELECTED/value['path']).resolve()))
                 == {k: value[k] for k in ('bytes', 'sha256')}, 'every bound C leaf is in actual compiler-M closure')
    for name, value in binding['headers'].items():
        need(state['headers'].get(str(output/name)) == value, 'actual compiled config bytes')
    need(not {Path(name).name for name in state['headers']}.intersection({
        'persistent_group_counters.inc', 'persistent_loop_counters.inc',
        'persistent_loop_counter_owner.inc', 'persistent_loop_effects_counters.inc',
        'persistent_loop_effects_counter_owner.inc'}),
        'ABI5 compiles its own bootstrap and exact prefix owner, never an old ABI writer')
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
