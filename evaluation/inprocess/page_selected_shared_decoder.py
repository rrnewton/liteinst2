"""Exact local package/source closure for the shared no_std x86 decoder.

This describes compiler inputs only. It supplies no execution or qualification
authority and never transports an old archive to a new source identity.
"""
from pathlib import Path
from page_selected import need

DECODER = 'tools/page-entry/selected/decoder'
SHARED = 'crates/liteinst-x86'
MANIFESTS = (DECODER+'/Cargo.toml', SHARED+'/Cargo.toml')
SHARED_SOURCE = SHARED+'/src/lib.rs'


def local_packages(metadata, root):
    """Select the actual decoder root; authenticate its one local dependency."""
    local = [p for p in metadata['packages'] if p['source'] is None]
    expected = {('li2-page-selected-decoder', '0.0.0'): root/MANIFESTS[0],
                ('liteinst-x86', '0.1.0'): root/MANIFESTS[1]}
    need(len(local) == 2 and {(p['name'], p['version']) for p in local} == set(expected)
         and all(Path(p['manifest_path']) == expected[(p['name'], p['version'])] for p in local),
         'exact decoder and shared-x86 local package identities/manifests')
    decoder = next(p for p in local if p['name'] == 'li2-page-selected-decoder')
    shared = next(p for p in local if p['name'] == 'liteinst-x86')
    need(metadata['resolve']['root'] == decoder['id'] and
         metadata['workspace_members'] == [decoder['id']], 'isolated decoder root, not root workspace')
    iced = [p for p in metadata['packages'] if p['name'] == 'iced-x86' and p['version'] == '1.21.0']
    need(len(iced) == 1 and iced[0]['source'] is not None, 'one locked iced-x86 dependency')
    nodes = metadata['resolve']['nodes']
    for package, dependencies, aliases in (
        (decoder, (iced[0]['id'], shared['id']), ('iced_x86', 'liteinst_x86')),
        (shared, (iced[0]['id'],), ('iced_x86',))):
        found = [n for n in nodes if n['id'] == package['id']]
        need(len(found) == 1, 'one resolved node for each local package')
        node = found[0]
        need(len(node['dependencies']) == len(dependencies) and set(node['dependencies']) == set(dependencies)
             and sorted(node['deps'], key=lambda d:d['name']) ==
             [dict(name=name, pkg=identity, dep_kinds=[dict(kind=None, target=None)])
              for name, identity in zip(aliases, dependencies, strict=True)],
             'exact normal local dependency edges without target/dev/build alternatives')
        targets = package['targets']
        need(len(targets) == 1 and targets[0]['src_path'] ==
             str(root/(DECODER if package is decoder else SHARED)/'src/lib.rs') and
             targets[0]['kind'] == (['staticlib'] if package is decoder else ['lib']) and
             targets[0]['crate_types'] == (['staticlib'] if package is decoder else ['lib']),
             'only actual production library targets')
        if package is shared:
            need(node['features'] == [], 'shared no_std helper has no default/std feature')
    iced_nodes = [n for n in nodes if n['id'] == iced[0]['id']]
    need(len(iced_nodes) == 1 and 'no_std' in iced_nodes[0]['features'] and
         'decoder' in iced_nodes[0]['features'] and
         not {'std', 'default'} & set(iced_nodes[0]['features']), 'actual iced no_std decoder feature domain')
    return decoder


def source_paths(root, decoder_names):
    need(type(decoder_names) is tuple and len(decoder_names) == len(set(decoder_names))
         and all(type(n) is str and '/' not in n and n.endswith('.rs') for n in decoder_names),
         'exact unique decoder production source names')
    return {str(root/DECODER/'src'/name) for name in decoder_names} | {str(root/SHARED_SOURCE)}


def source_key(root, selected, name):
    """Normalize only the declared shared Rust leaf; arbitrary parent escapes fail."""
    if name == '../../../'+SHARED_SOURCE:
        return SHARED_SOURCE
    need(not Path(name).is_absolute() and '..' not in Path(name).parts and name.startswith('decoder/src/')
         and name.endswith('.rs'), 'declared decoder source or exact shared lib.rs')
    return str((selected/name).relative_to(root))
