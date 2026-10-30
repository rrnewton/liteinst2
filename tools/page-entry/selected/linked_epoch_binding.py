#!/usr/bin/env python3
"""Exact production archive/policy bytes for the separate linked-epoch recipe.

This writes build input only. It grants no component/owner/allocator or emitted
code qualification. The future collector must retain actual compiler-M closure,
resolved Cargo features/exports and rehash every fact after compilation.
"""
import hashlib
import json
from pathlib import Path
import sys

LEAVES = (
    'decoder/Cargo.toml', 'decoder/src/region.rs', 'decoder/src/tf.rs',
    'decoder/src/write_footprint.rs', 'region_decode.h', 'linked_plan.h', 'linked_plan.c',
    'linked_source.h', 'linked_source.inc', 'linked_rseq.h', 'linked_rseq.inc',
    'linked_proof.h', 'linked_proof.inc', 'linked_controller.inc', 'linked_reuse.inc',
    'lifecycle_loader.c', 'span_source.inc', 'rseq_guard.c', 'rseq_region.inc',
    'runtime_loader.c', 'selected_globals.inc', 'selected_chain.inc',
    'native_lifecycle.inc', 'native_pair_lifecycle.inc', 'tf_span_transfer.inc',
    'span_fetch.inc', 'span_fast_bytes.h', 'build-linked-epoch.sh',
    'linked_epoch_binding.py',
)


def main():
    if len(sys.argv) != 4:
        raise ValueError('selected directory, actual archive, existing output directory')
    selected, archive, output = (Path(x).resolve(strict=True) for x in sys.argv[1:])
    if not selected.is_dir() or not archive.is_file() or not output.is_dir():
        raise ValueError('binding inputs')
    facts = []
    for name in LEAVES:
        source = selected / name
        if source.is_symlink() or not source.is_file():
            raise ValueError('exact regular source')
        data = source.read_bytes()
        facts.append({'path': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
    policy = hashlib.sha256(json.dumps(facts, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    data = archive.read_bytes()
    archive_hash = hashlib.sha256(data).hexdigest()
    def literal(digest):
        return '{' + ','.join('0x' + digest[i:i + 2] for i in range(0, 64, 2)) + '}'
    header = ('#ifndef LI2_LINKED_EPOCH_CONFIG_H\n#define LI2_LINKED_EPOCH_CONFIG_H\n'
              '#define LI2_LINK_BINDING_VERSION 1\n'
              '#define LI2_LINK_ARCHIVE_SHA256 ' + literal(archive_hash) + '\n'
              '#define LI2_LINK_POLICY_SHA256 ' + literal(policy) + '\n#endif\n')
    (output / 'linked_epoch_config.h').write_text(header)
    record = {'version': 1, 'archive': {'bytes': len(data), 'sha256': archive_hash},
              'policy_sha256': policy, 'sources': facts,
              'header_sha256': hashlib.sha256(header.encode()).hexdigest()}
    (output / 'linked_epoch_binding.json').write_text(json.dumps(record, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
