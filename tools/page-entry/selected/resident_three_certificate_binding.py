#!/usr/bin/env python3
"""Bind a finite three-resident direct graph to its complete actual ELF and source policy."""
import hashlib
import json
from pathlib import Path
import sys
import struct

from persistent_direct_frontier_binding import LEAVES as DIRECT_LEAVES
from persistent_group_binding import image_identity, need, fact

LEAVES = tuple({'build-persistent-direct-frontier.sh':'build-resident-three-certificate.sh',
                'persistent_direct_frontier_binding.py':'resident_three_certificate_binding.py'}.get(n,n)
               for n in DIRECT_LEAVES) + (
    'sealed_generation.h','sealed_generation.inc','private_code_query.h','private_code_query.inc',
    'resident_source_lease.h','resident_source_lease.inc','resident_source_owner.inc','resident_source_resident.inc',
    'resident_three_owner.h','resident_three_owner.inc','resident_three_storage.inc',
    'resident_three_controller.inc','resident_three_rseq.inc','readonly_query.h','native_policy.c',
    'resident_three_observe.h','resident_three_observe.inc','resident_three_memory.h','resident_three_memory.inc',
    'maps_view.inc','tf_chain.inc') + ('flag_stack.h', 'flag_stack.c', 'flag_stack_storage.h', 'flag_stack_query.inc', 'flag_stack_owner.inc', 'helper_tf.h', 'helper_tf.c', 'tf_owner.inc', 'tf_entry_route.inc', 'rseq_guard.h', 'entry.S', 'tf_chain.h', 'tf_nx_page_boundary.h')


from resident_three_flags_binding import configuration


PROFILES = {'differential': (True, 0), 'release': (False, 0), 'stale': (True, 1), 'mirror': (True, 2), 'fd': (True, 3)}
EXTRA = ('sealed_byte_certificate.h','sealed_byte_certificate.inc','sealed_byte_certificate_observe.h',
         'sealed_byte_certificate_observe.inc','resident_three_flags_binding.py')


def header_text(profile):
    need(profile in PROFILES, 'one exact fixed certificate header')
    differential,control=PROFILES[profile]
    return ('#ifndef LI2_SBC_EXPERIMENT_PROFILE_H\n#define LI2_SBC_EXPERIMENT_PROFILE_H\n'
            '#define LI2_SEALED_BYTE_CERTIFICATE 1\n#define LI2_SEALED_BYTE_CERTIFICATE_OBSERVE 1\n'+
            ('#define LI2_SEALED_BYTE_CERTIFICATE_DIFFERENTIAL 1\n' if differential else '')+
            '#define LI2_SEALED_BYTE_CERTIFICATE_CONTROL '+str(control)+'\n#endif\n')


def main():
    need(len(sys.argv) == 6,
         'selected directory, actual archive, original image, output directory, exact certificate profile')
    selected, archive, image, output = (Path(x).resolve(strict=True) for x in sys.argv[1:5])
    mode = 'release'
    need(selected.is_dir() and archive.is_file() and image.is_file() and output.is_dir(),
         'actual active-domain binding inputs')
    profile=sys.argv[5]; need(profile in PROFILES, 'one fixed certificate profile')
    differential,control=PROFILES[profile]
    profile_header='certificate_profiles/'+profile+'.h'
    need((selected/profile_header).read_text()==header_text(profile), 'whole exact selected feature header')
    leaves = LEAVES + EXTRA + (profile_header,)
    need(len(leaves)==len(set(leaves)), 'distinct complete three-resident source policy')
    values = []
    for name in leaves:
        path = selected / name
        need(not path.is_symlink() and path.is_file(), 'regular active-domain policy source')
        values.append(dict(path=name, **fact(path.read_bytes())))
    data = image.read_bytes()
    original = image_identity(data)
    resident, geometry = configuration(data)
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
                  '#define LI2_PG_ARCHIVE_SHA256 ' + literal(actual_archive['sha256']) + '\n'
                  '#define LI2_PG_POLICY_SHA256 ' + literal(policy) + '\n#endif\n')
    headers = {'linked_epoch_config.h': linked, 'persistent_group_config.h': persistent,
               'resident_three_config.h': resident}
    record = dict(version=1, profile='resident-three-direct-flags-capture-v1', mode=mode, native_probe=True, parse_memo=True, unregistered=True, subentry=True, cross_pair=True, direct_frontier=True,
                  archive=actual_archive, policy_sha256=policy, original=original, sources=values,
                  resident_three=True, sealed_storage=True, source_lease=True, flag_stack=True, helper_tf=True, tf_nx_page_boundary=True, geometry=geometry,
                  sealed_byte_certificate=True, certificate_observer=True,
                  certificate_profile=profile, certificate_differential=differential,
                  certificate_control=control, certificate_header=profile_header,
                  headers={name: fact(text.encode()) for name, text in headers.items()})
    paths = [output / name for name in headers] + [output / 'resident_three_binding.json']
    need(not any(path.exists() for path in paths), 'fresh exclusive active-domain outputs')
    for name, text in headers.items():
        with (output / name).open('x') as stream:
            stream.write(text)
    with paths[-1].open('x') as stream:
        stream.write(json.dumps(record, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
