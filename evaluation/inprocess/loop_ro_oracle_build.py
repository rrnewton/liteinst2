"""Exact separately bound actual-subject causal recipe; no production mode alias."""
import json
from pathlib import Path
import sys

from page_selected import fact, need, bridge_check
from persistent_dynamic import load, imported_sources, digest
from persistent_loop_effects_build import ACTIVE_PROVIDERS
from persistent_epoch_build import dynamic_original_image
from page_selected_register_time_build import recipe, expand, headers

ROOT = Path.cwd().resolve()
SELECTED = ROOT/'tools/page-entry/selected'


def build_control(builder, archive, original, directory, pin, binary, aliases, run, state, mode):
    """Bind the distinct causal suite through the actual original production flags."""
    output = directory/'build'; output.mkdir()
    script = pin(SELECTED/'build-loop-ro-oracle.sh')
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
        binder = load('finite_ro_control_binding', selected/'loop_ro_oracle_binding.py', pin)
    finally:
        sys.path[:] = previous_path
    need(all(name in sys.modules and Path(sys.modules[name].__file__).resolve(strict=True) == path
             for name, path in paths.items()), 'all six actual canonical binding dependencies loaded')
    imported_sources(pin)
    values = [dict(path=name, **fact(pin(SELECTED/name))) for name in binder.LEAVES]
    need(len(values) == len({v['path'] for v in values}), 'distinct complete RO source binding')
    for value in values:
        if value['path'].endswith('.rs'):
            need(builder.record['dep_info']['tools/page-entry/selected/'+value['path']]
                 == {k: value[k] for k in ('bytes', 'sha256')}, 'bound Rust belongs to retained archive')
    image = dynamic_original_image(original)
    policy = digest(dict(sources=values, original=image, mode=mode))
    environment = dict(builder.environment, LI2_CC=str(builder.tools['cc']), LI2_PYTHON=str(builder.tools['python']))
    _, out, err = run('build', [builder.tools['sh'], script, archive, original, output, mode],
                      profile='release_build', env=environment)
    need(out == err == b'', 'actual RO recipe has no diagnostics')
    manifest = binary(output/'loop_ro_oracle_binding.json')
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
    need(set(binding) == set(constants) | {'profile', 'mode', 'archive', 'policy_sha256', 'causal_oracle',
             'original', 'sources', 'headers', 'byte_certificate', 'history_certificate'}
         and digest({key: binding[key] for key in constants}) == digest(constants)
         and binding['profile'] == 'loop-ro-causal-oracle-'+mode+'-v1'
         and binding['mode'] == mode and binding['archive'] == fact(archive)
         and binding['original'] == image and binding['sources'] == values
         and binding['policy_sha256'] == policy and binding['capture_version'] is None
         and binding['byte_certificate'] == dict(version=1, sealed_generation=True, source_lease=False,
             mirror='isolated-anonymous-RO', root='isolated-anonymous-RO', mirror_pages=89, slots=2,
             full_scan_fallback=True, every_hit_full_scan=True,
             old_capture_compatible=False, qualification_credit=False)
         and binding['history_certificate'] == dict(version=1, cells=3, saved_completion='isolated-anonymous-RO',
             witnesses='isolated-anonymous-RO', complete_live_predicates=True,
             every_hit_reconstruction=True, qualification_credit=False),
         'exact source/archive/image/mode certificate binding, never old capture ABI')
    need(mode in ('byte', 'history') and binding['causal_oracle'] == dict(version=1,
        control=1 if mode=='byte' else 2, actual_predicates=True, recursive_hook_suppression=True,
        expected_exit=125, expected_detail=8801 if mode=='byte' else 8802, qualification_credit=False),
        'exact source-bound causal suite, real outcomes and deliberate final refusal')
    need(set(binding['headers']) == {'linked_epoch_config.h', 'persistent_group_config.h', 'loop_ro_oracle_config.h'},
         'all three actual configuration headers')
    for name, value in binding['headers'].items():
        need(fact(binary(output/name)) == value, 'whole generated immutable header')
    expected_config = ('#ifndef LI2_LOOP_RO_ORACLE_CONFIG_H\n#define LI2_LOOP_RO_ORACLE_CONFIG_H\n'
        '#define LI2_LOOP_RO_CERTIFICATE 1\n#define LI2_SEALED_BYTE_CERTIFICATE 1\n'
        '#define LI2_PERSISTENT_SEALED_GENERATION 1\n'+
        '#define LI2_SEALED_BYTE_CERTIFICATE_DIFFERENTIAL 1\n#define LI2_LOOP_RO_TEST 1\n'+
        '#define LI2_LOOP_RO_CONTROL '+str(1 if mode=='byte' else 2)+'\n'+'#endif\n').encode()
    need((output/'loop_ro_oracle_config.h').read_bytes() == expected_config, 'exact certificate mode, maintained maps unchanged')
    literal = lambda value: '{'+','.join('0x'+value[i:i+2] for i in range(0, 64, 2))+'}'
    expected_linked = ('#ifndef LI2_LINKED_EPOCH_CONFIG_H\n#define LI2_LINKED_EPOCH_CONFIG_H\n'
        '#define LI2_LINK_BINDING_VERSION 1\n#define LI2_LINK_ARCHIVE_SHA256 '+literal(fact(archive)['sha256'])+
        '\n#define LI2_LINK_POLICY_SHA256 '+literal(policy)+'\n#endif\n').encode()
    expected_persistent = ('#ifndef LI2_PERSISTENT_GROUP_CONFIG_H\n#define LI2_PERSISTENT_GROUP_CONFIG_H\n'
        '#define LI2_PG_BINDING_VERSION 1\n#define LI2_PG_GROUP_BINDING_VERSION 4\n'
        '#define LI2_PG_LOOP_RO_BINDING_VERSION 1\n#define LI2_PG_LOOP_RO_ORACLE_BINDING_VERSION 1\n'
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
    expected[expected.index('-Werror')+1:expected.index('-Werror')+1] = ['-include', str(output/'loop_ro_oracle_config.h')]
    expected.insert(expected.index('-Wl,-e,_start,-Bsymbolic,-z,now,-z,relro,-z,noexecstack,--build-id=none,--no-undefined'),
        '-Wl,--undefined=li2_lifecycle_sealed_code_query,--undefined=li2_pg_storage_query')
    expected[-1] = str(output/'bridge-loop-ro-oracle.so')
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
