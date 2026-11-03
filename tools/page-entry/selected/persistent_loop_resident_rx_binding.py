#!/usr/bin/env python3
"""Distinct two-slot LOOP RX lifetime; no old NX receipt or capture cast."""
import hashlib
import json
from pathlib import Path
import sys
from persistent_group_binding import image_identity, need, fact
from persistent_loop_ro_certificate_binding import LEAVES as RO_LEAVES, certificate_header

RX_INPUTS = ('persistent_loop_resident_rx_binding.py',
    'build-persistent-loop-resident-rx.sh', 'selected_controller.inc',
    'loop_resident_rx_profile.h', 'loop_resident_rx.h',
    'loop_resident_rx_types.inc', 'loop_resident_rx_owner.inc',
    'tf_chain.h','tf_chain.inc')
LEAVES = RO_LEAVES + RX_INPUTS
MODES = ('release', 'differential')


RECURRENCE_INPUTS=('persistent_loop_rx_recurrence_binding.py','build-persistent-loop-rx-recurrence.sh',
    'loop_rx_recurrence.h','loop_rx_recurrence_attach.inc','loop_rx_recurrence_owner.inc',
    'counter_environment.inc')
RECURRENCE=dict(version=7,bytes=12382208,storage_bytes=12582912,capacity=1024,
    row_bytes=12088,source_bytes=8760,initial_seals=6,final_seals=23,
    denominator='actual-pe_build-after-coarse-and-negative-hint',stop_detail=8960,
    observation_authority=False,qualification_credit=False)


def write_binding(selected, archive, image, output, mode, *, recurrence=False):
    need(mode in MODES and type(recurrence)is bool and (not recurrence or mode=='release'),
         'literal original RX mode or distinct release-only recurrence profile')
    need(selected.is_dir() and archive.is_file() and image.is_file() and output.is_dir(),
         'actual active-domain binding inputs')
    leaves = LEAVES + (RECURRENCE_INPUTS if recurrence else ())
    need(len(leaves)==len(set(leaves)), 'whole distinct LOOP and RO-certificate source closure')
    values = []
    for name in leaves:
        path = selected / name
        need(not path.is_symlink() and path.is_file(), 'regular active-domain policy source')
        values.append(dict(path=name, **fact(path.read_bytes())))
    original = image_identity(image.read_bytes())
    policy = hashlib.sha256(json.dumps(dict(sources=values, original=original, mode=mode),
                          sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    actual_archive = fact(archive.read_bytes())
    literal = lambda value: '{' + ','.join('0x' + value[i:i+2] for i in range(0, 64, 2)) + '}'
    linked = ('#ifndef LI2_LINKED_EPOCH_CONFIG_H\n#define LI2_LINKED_EPOCH_CONFIG_H\n'
              '#define LI2_LINK_BINDING_VERSION 1\n'
              '#define LI2_LINK_ARCHIVE_SHA256 ' + literal(actual_archive['sha256']) + '\n'
              '#define LI2_LINK_POLICY_SHA256 ' + literal(policy) + '\n#endif\n')
    persistent = ('#ifndef LI2_PERSISTENT_GROUP_CONFIG_H\n#define LI2_PERSISTENT_GROUP_CONFIG_H\n'
                  '#define LI2_PG_BINDING_VERSION 1\n#define LI2_PG_GROUP_BINDING_VERSION 4\n'
                  '#define LI2_PG_LOOP_RO_BINDING_VERSION 1\n#define LI2_PG_LOOP_RESIDENT_RX_BINDING_VERSION 1\n' +
                  ('#define LI2_PG_LOOP_RX_RECURRENCE_BINDING_VERSION 1\n' if recurrence else '') +
                  '#define LI2_PG_LOOP_BINDING_VERSION 1\n#define LI2_PG_LOOP_POLICY_VERSION 12\n#define LI2_PG_LOOP_FALLBACK_VERSION 11\n#define LI2_PG_LOOP_ENCODING_VERSION 2\n'
                  '#define LI2_PG_LOOP_EFFECTS_BINDING_VERSION 1\n#define LI2_PG_LOOP_EFFECTS_POLICY_VERSION 13\n#define LI2_PG_LOOP_EFFECTS_SCALAR_VERSION 3\n#define LI2_PG_LOOP_EFFECTS_MOV_VERSION 2\n'
                  '#define LI2_PG_ARCHIVE_SHA256 ' + literal(actual_archive['sha256']) + '\n'
                  '#define LI2_PG_POLICY_SHA256 ' + literal(policy) + '\n#endif\n')
    headers = {'linked_epoch_config.h': linked, 'persistent_group_config.h': persistent,
               'loop_ro_certificate_config.h': certificate_header(mode)}
    record = dict(version=1, profile='persistent-loop-resident-rx-'+mode+'-v1', mode=mode, native_probe=True, parse_memo=True, unregistered=True, subentry=True, cross_pair=True, direct_frontier=True, bounded_fused=True, bounded_loop=True, policy_version=12, fallback_policy=11, encoding_domain=dict(version=2, policies=[11,12,13], near_record=1, far_record=2, miss='source-derived-rel32-or-rip-indirect-u64', literal_bytes=8, literal_boundaries=0, old_pf_api=False), header_version=2, chooser_version=12, decoder_read_version=2, effects=dict(binding_version=1, policy_version=13, scalar_version=3, mov_version=2, selection_order=[12,13,11]), capture_version=None, pf_refusals=dict(version=1,reason=256,shared_reasons=18,abi2=False),
                  archive=actual_archive, policy_sha256=policy, original=original, sources=values,
                  headers={name: fact(text.encode()) for name, text in headers.items()})
    record['byte_certificate']=dict(version=1, sealed_generation=True, source_lease=False,
        mirror='isolated-anonymous-RO', root='isolated-anonymous-RO', mirror_pages=89,
        slots=2, full_scan_fallback=True, every_hit_full_scan=mode=='differential',
        old_capture_compatible=False, qualification_credit=False)
    record['history_certificate']=dict(version=1, cells=3, saved_completion='isolated-anonymous-RO',
        witnesses='isolated-anonymous-RO', complete_live_predicates=True,
        every_hit_reconstruction=mode=='differential', qualification_credit=False)
    record['rx_lifetime']=dict(version=1, slots=2, source_release_version=1,
        continuation='at-most-two-authenticated-original-DIRECT-TF-steps',branch_limit=2,
        unsafe_handoff='revoke-all-before-original-route',
        original_domain_preserved=True, old_capture_compatible=False,
        code_permission_counts='actual-pe_permission-calls',
        metadata_permission_counts='actual-pe_permission-calls-only',
        qualification_credit=False)
    if recurrence:
        record['profile']='persistent-loop-rx-recurrence-release-v1'
        record['recurrence']=RECURRENCE
    name='persistent_loop_rx_recurrence_binding.json' if recurrence else 'persistent_loop_resident_rx_binding.json'
    paths = [output / name for name in headers] + [output / name]
    need(not any(path.exists() for path in paths), 'fresh exclusive active-domain outputs')
    for name, text in headers.items():
        with (output / name).open('x') as stream:
            stream.write(text)
    with paths[-1].open('x') as stream:
        stream.write(json.dumps(record, sort_keys=True) + '\n')


def main():
    need(len(sys.argv) == 6 and sys.argv[5] in MODES,
         'selected directory, actual archive, original image, output directory, mode')
    selected, archive, image, output = (Path(x).resolve(strict=True) for x in sys.argv[1:5])
    mode = sys.argv[5]
    write_binding(selected,archive,image,output,mode)


if __name__ == '__main__':
    main()
