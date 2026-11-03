"""Actual existing LOOP compiler recipe with a distinct RX lifetime contract."""
import json
from pathlib import Path
import sys
from page_selected import fact, need, bridge_check, elf
from persistent_dynamic import load, imported_sources, digest
from persistent_loop_effects_build import ACTIVE_PROVIDERS
from persistent_epoch_build import dynamic_original_image
from page_selected_register_time_build import recipe, expand, headers
from page_selected_shared_decoder import source_key
ROOT=Path(__file__).resolve().parents[2]
SELECTED=ROOT/'tools/page-entry/selected'
RX_LIFETIME=dict(version=1,slots=2,source_release_version=1,
    continuation='at-most-two-authenticated-original-DIRECT-TF-steps',branch_limit=2,
    unsafe_handoff='revoke-all-before-original-route',original_domain_preserved=True,
    old_capture_compatible=False,code_permission_counts='actual-pe_permission-calls',
    metadata_permission_counts='actual-pe_permission-calls-only',qualification_credit=False)


def build_rx(builder, archive, original, directory, pin, binary, aliases, run, state, mode, *, control=None, selected=None, root=None, recurrence=False, cache8=False, cache8_observe=None):
    """Execute the real source-owned recipe, then bind its exact compiler closure."""
    need(mode in ('release','differential') and
         (control is None or type(control)is int and control in (0,1)) and
         (control!=1 or mode=='differential'), 'explicit production or finite RX mode')
    need(type(recurrence)is bool and (not recurrence or mode=='release' and control is None),
         'distinct release-only passive recurrence build')
    need(cache8_observe is None or type(cache8_observe)is int and cache8_observe in (0,1) and
         cache8 and (cache8_observe==0 or mode=='differential'),'literal cache8 positive or differential predicate controls')
    need(type(cache8)is bool and (not cache8 or not recurrence and control is None),
         'cache8 has its exact separate member and capture layout')
    root=ROOT if root is None else Path(root).resolve(strict=True)
    selected=SELECTED if selected is None else Path(selected).resolve(strict=True)
    need(selected.is_dir(), 'actual explicit selected compiler source context')
    stem='persistent-loop-resident-rx'+('-oracle' if control is not None else '')
    if recurrence:stem='persistent-loop-rx-recurrence'
    if cache8:stem='persistent-loop-cache8'
    if cache8_observe is not None:stem+='-observe'
    binder_name=stem.replace('-','_')+'_binding'
    output = directory/'build'; output.mkdir()
    script = pin(selected/('build-'+stem+'.sh'))
    dependencies = ('persistent_epoch_binding', 'persistent_group_binding',
        'persistent_retained_two_binding', 'persistent_active_domain_binding',
        'persistent_startup_binding', 'persistent_loop_binding', 'persistent_loop_ro_certificate_binding') + (
        ('persistent_loop_resident_rx_binding',) if recurrence or cache8 else ())
    selected = selected.resolve(strict=True)
    paths = {name: pin(selected/(name+'.py')) for name in dependencies}
    for name, path in paths.items():
        need(name not in sys.modules or Path(sys.modules[name].__file__).resolve(strict=True) == path,
             'preexisting binding dependency has its canonical selected source')
    previous_path = list(sys.path)
    try:
        sys.path.insert(0, str(selected))
        binder = load('loop_rx_binding_'+str(control), selected/(binder_name+'.py'), pin)
    finally:
        sys.path[:] = previous_path
    need(all(name in sys.modules and Path(sys.modules[name].__file__).resolve(strict=True) == path
             for name, path in paths.items()), 'all actual canonical binding dependencies loaded')
    imported_sources(pin)
    values = [dict(path=name, **fact(pin(selected/name))) for name in binder.LEAVES]
    need(len(values) == len({v['path'] for v in values}), 'distinct complete RO source binding')
    for value in values:
        if value['path'].endswith('.rs'):
            need(builder.record['dep_info'][source_key(root, root/'tools/page-entry/selected', value['path'])]
                 == {k: value[k] for k in ('bytes', 'sha256')}, 'bound Rust belongs to retained archive')
    image = dynamic_original_image(original)
    policy_value=dict(sources=values, original=image, mode=mode)
    if control is not None:policy_value['control']=control
    if cache8_observe is not None:policy_value['cache8_control']=cache8_observe
    policy = digest(policy_value)
    environment = dict(builder.environment, LI2_CC=str(builder.tools['cc']), LI2_PYTHON=str(builder.tools['python']))
    _, out, err = run('build', [builder.tools['sh'], script, archive, original, output, mode]+
                      ([] if control is None else [str(control)])+
                      ([] if cache8_observe is None else [str(cache8_observe)]),
                      profile='release_build', env=environment)
    need(out == err == b'', 'actual RO recipe has no diagnostics')
    manifest = binary(output/(binder_name+'.json'))
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
             'original', 'sources', 'headers', 'byte_certificate', 'history_certificate', 'rx_lifetime'} |
             (set() if control is None else {'control','oracle'}) |
             ({'recurrence'} if recurrence else set()) | ({'cache8'} if cache8 else set()) | ({'cache8_observer'} if cache8_observe is not None else set())
         and digest({key: binding[key] for key in constants}) == digest(constants)
         and binding['profile'] == stem+'-'+mode+'-v1'
         and binding['mode'] == mode and binding['archive'] == fact(archive)
         and binding['original'] == image and binding['sources'] == values
         and binding['policy_sha256'] == policy and binding['capture_version'] is None
         and binding['byte_certificate'] == dict(version=1, sealed_generation=True, source_lease=False,
             mirror='isolated-anonymous-RO', root='isolated-anonymous-RO', mirror_pages=89, slots=8 if cache8 else 2,
             full_scan_fallback=True, every_hit_full_scan=mode=='differential',
             old_capture_compatible=False, qualification_credit=False)
         and binding['history_certificate'] == dict(version=1, cells=9 if cache8 else 3, saved_completion='isolated-anonymous-RO',
             witnesses='isolated-anonymous-RO', complete_live_predicates=True,
             every_hit_reconstruction=mode=='differential', qualification_credit=False),
         'exact source/archive/image/mode certificate binding, never old capture ABI')
    if recurrence:
        need(binding['recurrence']==dict(version=7,bytes=12382208,storage_bytes=12582912,capacity=1024,
             row_bytes=12088,source_bytes=8760,initial_seals=6,final_seals=23,
             denominator='actual-pe_build-after-coarse-and-negative-hint',stop_detail=8960,
             observation_authority=False,qualification_credit=False), 'exact passive observation schema')
    expected_lifetime=dict(RX_LIFETIME,version=2,slots=8) if cache8 else RX_LIFETIME
    if cache8:
        need(binding['cache8']==dict(version=1,slots=8,members=8,completion_cells=9,source_pages=2,
             placement_banks=2,aggregate_heads=256,aggregate_boundaries=8,rx_receipt_version=2,
             selection='exact-root-or-head-then-empty-or-oldest-completion',
             activation='post-publication-DIRECT-connected-claimed-closure',
             inactive_heads_exposed=False,qualification_credit=False),'exact cache/activation limits')
    if cache8_observe is not None:
        need(binding['cache8_observer']==dict(version=1,control=cache8_observe,reference='cache8-abc169',
             observation_authority=False,qualification_credit=False),'exact distinct cache8 observer schema')
    need(binding['rx_lifetime']==expected_lifetime and
         (control is None or binding['control']==control and binding['oracle']==dict(
             version=1,control=control,epochs=3,controls=32 if control else 0,
             source_entries=[0x410200,0x412400,0x410200],reference='direct44',
             transit=dict(branch_limit=2,controls=16 if control else 0,pc=0x413ffa,target=0x410200),
             observation_authority=False,qualification_credit=False)),
         'distinct typed RX lifetime and exact optional finite observer')
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
        '#define LI2_PG_LOOP_RO_BINDING_VERSION 1\n#define LI2_PG_LOOP_RESIDENT_RX_BINDING_VERSION 1\n'+
        ('#define LI2_PG_LOOP_RX_RECURRENCE_BINDING_VERSION 1\n' if recurrence else '')+
        ('#define LI2_PG_LOOP_CACHE8_BINDING_VERSION 1\n' if cache8 else '')+
        ('#define LI2_PG_LOOP_CACHE8_OBSERVE_BINDING_VERSION 1\n' if cache8_observe is not None else '')+
        ('#define LI2_PG_LOOP_RESIDENT_RX_ORACLE_BINDING_VERSION 1\n' if control is not None else '')+
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
    substitutions = {'$cc_bin': builder.tools['cc'], '$selected_dir': selected,
        '$parent_dir': selected.parent, '$archive': archive, '$output': output,
        '$control':str(cache8_observe if cache8_observe is not None else control)}
    argv = expand(rows[0], substitutions)
    old = recipe(pin(selected/'build-persistent-loop-effects.sh'), '"$cc_bin"')
    need(len(old) == 1, 'one unchanged effects release recipe')
    expected = expand(old[0], substitutions)
    expected[expected.index('-Werror')+1:expected.index('-Werror')+1] = (['-include', str(output/'loop_ro_certificate_config.h'), '-DLI2_LOOP_RESIDENT_RX=1']+
        (['-DLI2_LOOP_RX_RECURRENCE=1'] if recurrence else [])+
        (['-DLI2_LOOP_CACHE8=1'] if cache8 else [])+
        ([] if cache8_observe is None else ['-DLI2_LOOP_CACHE8_OBSERVE=1','-DLI2_LOOP_CACHE8_CONTROL='+str(cache8_observe)])+
        ([] if control is None else ['-DLI2_LOOP_RESIDENT_RX_ORACLE=1','-DLI2_LOOP_RESIDENT_RX_CONTROL='+str(control)]))
    if cache8:
        expected.insert(expected.index('-Wl,-e,_start,-Bsymbolic,-z,now,-z,relro,-z,noexecstack,--build-id=none,--no-undefined'),
            '-Wl,--undefined=li2_loop_cache8_progress')
    if recurrence:
        expected.insert(expected.index('-Wl,-e,_start,-Bsymbolic,-z,now,-z,relro,-z,noexecstack,--build-id=none,--no-undefined'),
            '-Wl,--undefined=li2_lrc_layout')
    expected.insert(expected.index('-Wl,-e,_start,-Bsymbolic,-z,now,-z,relro,-z,noexecstack,--build-id=none,--no-undefined'),
        '-Wl,--undefined=li2_lifecycle_sealed_code_query,--undefined=li2_pg_storage_query')
    expected[-1] = str(output/('bridge-'+stem+'.so'))
    need(argv == expected, 'whole old production flags/TUs/link roots, plus exact RO include and providers only')
    units = [x for x in argv if x.endswith(('.c', '.S'))]
    state.update(recipe=fact(script), argv=argv, binding=binding, manifest=fact(manifest))
    headers('headers', argv, units, archive, builder, pin, aliases, run, state)
    for value in values:
        if value['path'].endswith(('.c', '.h', '.inc')):
            need(state['headers'].get(str((selected/value['path']).resolve()))
                 == {k: value[k] for k in ('bytes', 'sha256')}, 'every bound C leaf is in actual compiler-M closure')
    for name, value in binding['headers'].items():
        need(state['headers'].get(str(output/name)) == value, 'actual compiled config bytes')
    bridge = binary(Path(argv[-1])); state['elf'] = bridge_check(bridge)
    _, out, err = run('undefined', [builder.tools['nm'], '-u', bridge], profile='inspect', env=builder.environment)
    need(out == err == b'', 'no unresolved imports')
    _, out, err = run('symbols', [builder.tools['nm'], '-S', '--defined-only', bridge], profile='inspect', env=builder.environment)
    need(not err, 'complete actual compiled symbols')
    replacements={'li2_pgd_source_release':'li2_pgd_source_release_rx',
                  'li2_pgd_source_terminal':'li2_pgd_source_terminal_rx'}
    if cache8:replacements['li2_pgx_source_prepare']='li2_pgx_source_prepare_member'
    need(len(ACTIVE_PROVIDERS)==len(set(ACTIVE_PROVIDERS))==133 and
         all(ACTIVE_PROVIDERS.count(name)==1 for name in replacements) and
         not set(replacements.values()).intersection(ACTIVE_PROVIDERS),
         'two exact distinct physical-lifetime API replacements, all other providers retained')
    providers=tuple(replacements.get(name,name) for name in ACTIVE_PROVIDERS)+(
        'li2_lifecycle_sealed_code_query','li2_pg_storage_query',
        'li2_pgd_source_rx_progress','li2_pgd_source_rx_value','li2_tf_chain_trace_direct')
    if cache8:
        providers+=('li2_loop_cache8_progress',)
    for name in providers:
        found = [line.split() for line in out.splitlines() if line.split()[-1:] == [name.encode()]]
        need(len(found) == 1 and len(found[0]) == 4 and found[0][2] in (b't', b'T')
             and int(found[0][1], 16) > 0, 'one actual complete provider '+name)
    for name in ('pe', 'sg_owner', 'lhc'):
        found = [line.split() for line in out.splitlines() if line.split()[-1:] == [name.encode()]]
        need(len(found) == 1 and len(found[0]) == 4 and found[0][2] in (b'b', b'B')
             and int(found[0][0], 16) % 4096 == 0 and int(found[0][1], 16) % 4096 == 0,
             'actual isolated page-aligned certificate/owner storage '+name)
    if recurrence:state['recurrence_layout']=recurrence_layout(bridge,out)
    state.update(bridge=fact(bridge), status='compiled_diagnostic_only')
    return bridge


def recurrence_layout(bridge, symbols):
    """Exact compiler-emitted sizeof/offsetof values in the actual ELF; no inferior."""
    import struct
    expected=(12582912,12382208,12088,8760,1024,9784,11832,104,176,4376,
              8,16,24,168,172,0,8,24,48,0,8,280,
              0,8,16,24,32,40,44,48,52,56,64,72,80,88,96)
    found=[line.split() for line in symbols.splitlines() if line.split()[-1:]==[b'li2_lrc_layout']]
    need(len(found)==1 and len(found[0])==4 and found[0][2] in (b'r',b'R') and
         int(found[0][1],16)==8*len(expected),'one exact actual compiler layout object')
    address=int(found[0][0],16);size=int(found[0][1],16)
    data,_,segments=elf(bridge)
    matches=[p for p in segments if p[0]==1 and p[1]==4 and p[3]<=address and address+size<=p[3]+p[5]]
    need(len(matches)==1,'whole layout object in one actual readonly ELF LOAD')
    segment=matches[0];offset=segment[2]+address-segment[3]
    actual=struct.unpack_from('<'+str(len(expected))+'Q',data,offset)
    need(actual==expected,'all37 actual compiler sizes and offsets equal independent reader layout')
    return dict(symbol='li2_lrc_layout',address=address,bytes=size,values=list(actual),inferior_started=False)
