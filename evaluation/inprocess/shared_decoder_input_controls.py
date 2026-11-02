#!/usr/bin/env python3
"""Pure source/package/provenance controls; no compiler, subject or credit."""
import ast
import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


def extract(path, names, namespace):
    tree = ast.parse(path.read_bytes())
    chosen = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.Assign))
              and (getattr(n, 'name', None) in names or isinstance(n, ast.Assign)
                   and any(isinstance(t, ast.Name) and t.id in names for t in n.targets))]
    found = {n.name for n in chosen if isinstance(n, ast.FunctionDef)}
    found |= {t.id for n in chosen if isinstance(n, ast.Assign) for t in n.targets if isinstance(t, ast.Name)}
    assert found == set(names)
    exec(compile(ast.Module(body=chosen, type_ignores=[]), str(path), 'exec'), namespace)


def main():
    env = dict(Path=Path, hashlib=hashlib, io=io, tarfile=tarfile)
    extract(HERE/'page_selected.py', ('need',), env)
    extract(HERE/'page_selected_shared_decoder.py',
            ('DECODER','SHARED','MANIFESTS','SHARED_SOURCE','local_packages','source_paths','source_key'), env)
    extract(HERE/'loop_ro_native_positive.py', ('H','historical_sources'), env)
    root = Path('/source'); selected = root/'tools/page-entry/selected'
    packages = [
        dict(name='li2-page-selected-decoder', version='0.0.0', id='root', source=None,
             manifest_path=str(selected/'decoder/Cargo.toml'), targets=[dict(src_path=str(selected/'decoder/src/lib.rs'),
                kind=['staticlib'], crate_types=['staticlib'])]),
        dict(name='liteinst-x86', version='0.1.0', id='shared', source=None,
             manifest_path='/source/crates/liteinst-x86/Cargo.toml', targets=[dict(
                src_path='/source/crates/liteinst-x86/src/lib.rs', kind=['lib'], crate_types=['lib'])]),
        dict(name='iced-x86', version='1.21.0', id='iced', source='registry')]
    def edge(name, pkg): return dict(name=name, pkg=pkg, dep_kinds=[dict(kind=None,target=None)])
    metadata = dict(packages=packages, workspace_members=['root'], resolve=dict(root='root', nodes=[
        dict(id='root', features=['default','linked-epoch','loop-effects','mov-guard','scalar-read','scalar-region','scalar-span'],
             dependencies=['iced','shared'], deps=[edge('iced_x86','iced'),edge('liteinst_x86','shared')]),
        dict(id='shared', features=[], dependencies=['iced'], deps=[edge('iced_x86','iced')]),
        dict(id='iced', features=['decoder','instr_info','lazy_static','no_std'])]))
    assert env['local_packages'](metadata, root) == packages[0]
    reversed_packages = copy.deepcopy(metadata); reversed_packages['packages'].reverse()
    assert env['local_packages'](reversed_packages, root)['id'] == 'root'
    names = ('lib.rs','decode.rs')
    assert env['source_paths'](root, names) == {
        '/source/tools/page-entry/selected/decoder/src/lib.rs',
        '/source/tools/page-entry/selected/decoder/src/decode.rs', '/source/crates/liteinst-x86/src/lib.rs'}
    assert env['source_key'](root, selected, 'decoder/src/decode.rs') == 'tools/page-entry/selected/decoder/src/decode.rs'
    assert env['source_key'](root, selected, '../../../crates/liteinst-x86/src/lib.rs') == 'crates/liteinst-x86/src/lib.rs'
    mutations = (
        lambda m:m['packages'].pop(1),
        lambda m:m['packages'].append(copy.deepcopy(m['packages'][1])),
        lambda m:m['packages'][1].update(manifest_path='/other/Cargo.toml'),
        lambda m:m['packages'][1].update(version='0.2.0'),
        lambda m:m['packages'][1].update(source='registry'),
        lambda m:m['resolve'].update(root='shared'),
        lambda m:m.update(workspace_members=['root','shared']),
        lambda m:m['resolve']['nodes'][1].update(features=['default']),
        lambda m:m['resolve']['nodes'][1].update(features=['std']),
        lambda m:m['resolve']['nodes'][2]['features'].append('std'),
        lambda m:m['resolve']['nodes'][2]['features'].append('default'),
        lambda m:m['resolve']['nodes'][2]['features'].remove('no_std'),
        lambda m:m['resolve']['nodes'][2]['features'].remove('decoder'),
        lambda m:m['resolve']['nodes'][0]['dependencies'].remove('shared'),
        lambda m:m['resolve']['nodes'][1]['dependencies'].append('root'),
        lambda m:m['resolve']['nodes'][0]['deps'][1].update(name='other'),
        lambda m:m['resolve']['nodes'][1]['deps'][0].update(pkg='root'),
        lambda m:m['resolve']['nodes'][1]['deps'][0].update(dep_kinds=[dict(kind='dev',target=None)]),
        lambda m:m['resolve']['nodes'][1]['deps'][0].update(dep_kinds=[dict(kind=None,target='cfg(unix)')]),
        lambda m:m['packages'][1]['targets'][0].update(src_path='/source/crates/liteinst-x86/src/tests.rs'),
        lambda m:m['packages'][1]['targets'][0].update(kind=['test']),
        lambda m:m['packages'][1]['targets'][0].update(crate_types=['cdylib']),
        lambda m:m['packages'][0]['targets'].append(copy.deepcopy(m['packages'][0]['targets'][0])),
        lambda m:m['resolve']['nodes'].append(copy.deepcopy(m['resolve']['nodes'][1])),
        lambda m:m['packages'][2].update(version='1.20.0'),
    )
    refused = []
    def reject(name, call):
        try: call()
        except ValueError: refused.append(name)
        else: raise AssertionError('accepted '+name)
    for i, mutate in enumerate(mutations):
        value = copy.deepcopy(metadata); mutate(value)
        reject('metadata-'+str(i), lambda:env['local_packages'](value,root))
    for name in ('../../../crates/liteinst-x86/src/tests.rs','../../../other/lib.rs',
                 '/source/lib.rs','decoder/src/../lib.rs'):
        reject('source-key-'+name, lambda:env['source_key'](root,selected,name))
    for names in (('lib.rs','lib.rs'), ('../lib.rs',), ['lib.rs']):
        reject('source-names-'+repr(names), lambda:env['source_paths'](root,names))
    files = {'tools/page-entry/selected/decoder/src/file'+str(i)+'.rs': bytes([i])*7 for i in range(13)}
    files.update({'tools/page-entry/selected/'+name:b'old-'+name.encode() for name in
        ('decoder/Cargo.toml','decoder/Cargo.lock','build-loop-effects-decoder.sh')})
    expected = {name:dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest()) for name,data in files.items()}
    def archive(rows):
        out=io.BytesIO()
        with tarfile.open(fileobj=out,mode='w') as bundle:
            for name,data,kind in rows:
                info=tarfile.TarInfo(name);info.type=kind;info.size=len(data)
                bundle.addfile(info,io.BytesIO(data))
        return out.getvalue()
    rows=[(name,data,tarfile.REGTYPE) for name,data in files.items()]
    raw=archive(rows);assert env['historical_sources'](raw,expected)==expected
    bad_rows=(rows[:-1],rows+[rows[0]],rows+[("extra",b'x',tarfile.REGTYPE)],
        [(rows[0][0],b'changed',tarfile.REGTYPE),*rows[1:]],
        [(rows[0][0],rows[0][1],tarfile.SYMTYPE),*rows[1:]],
        [('../escape',rows[0][1],tarfile.REGTYPE),*rows[1:]])
    for i, changed in enumerate(bad_rows):
        reject('historical-'+str(i), lambda:env['historical_sources'](archive(changed),expected))
    bad=copy.deepcopy(expected);bad[rows[0][0]]['sha256']='0'*64
    reject('historical-wrong-hash',lambda:env['historical_sources'](raw,bad))
    assert len(refused)==39 and len(set(refused))==39
    print(json.dumps(dict(status='passed', positives=6, refusals=39,
        compiler_commands=0, subjects=0, qualification_credit=False), sort_keys=True))


if __name__ == '__main__': main()
