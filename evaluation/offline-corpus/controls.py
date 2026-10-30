#!/usr/bin/env python3
"""Pure saved-copy witness controls. Never executes an ELF, compiler or producer."""
import argparse
import subprocess
import linecache
import re
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import traceback
import types

if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
OLD_REV = '2cf9a6eed125b509cf59083c335cc17c434c5716'
OLD_SHA = '9dc7a95f01f47a73e88fcdf8604eed05c9e49bdaa76948163bccbc1a99421b4c'
CORPUS_SHA = '007e529b3716061d8b7f11f3e33541ee80292027165703663db2f72a81e35b07'
NEW_SHA = 'db7d33395fa0af59eaffaa648039e28bc0e42f68461f2902f1fec1dc582dbb30'
REPRODUCE_SHA = '7b0843690e459eb1c488d33508b586766434c42ac44c46c247ad4b69723074d8'
HELPER_SHA = 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
sha = lambda b: hashlib.sha256(b).hexdigest()

def read(path):
    path = Path(path)
    assert path.is_file() and not path.is_symlink()
    assert path.parent.resolve(strict=True) == path.parent
    data = path.read_bytes()
    assert len(data) <= 16 * 1024 * 1024
    return data

def save(path, value):
    data = value if isinstance(value, bytes) else (json.dumps(value, sort_keys=True, indent=2)+'\n').encode()
    with path.open('xb') as f:
        f.write(data)

def module(name, path, digest, data=None):
    data = read(path) if data is None else data
    assert sha(data) == digest
    linecache.cache[str(path)] = (len(data), None, data.decode().splitlines(True), str(path))
    result = types.ModuleType(name); result.__file__ = str(path)
    sys.modules[name] = result
    exec(compile(data, str(path), 'exec'), result.__dict__)
    return result

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('--raw', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    assert a.repo.is_absolute() and a.repo.resolve(strict=True) == a.repo
    assert a.raw.is_absolute() and a.raw.resolve(strict=True) == a.raw and a.raw.is_relative_to(a.repo/'ignored')
    assert a.out.is_absolute() and not a.out.exists() and a.out.parent.resolve(strict=True) == a.out.parent
    assert a.out.is_relative_to(a.repo/'ignored') and not a.out.is_relative_to(a.raw)
    assert Path(__file__).resolve() == a.repo/'evaluation/offline-corpus/controls.py'
    metadata = {}
    def take(path):
        path = Path(path); assert path.is_relative_to(a.raw)
        data = read(path); key = str(path)
        assert key not in metadata or metadata[key] == sha(data)
        metadata[key] = sha(data)
        return data
    def parsed(path): return json.loads(take(path))
    summary = parsed(a.raw/'summary.json'); comparison = parsed(a.raw/'comparison/summary.json')
    revision = summary['revision']; assert re.fullmatch('[0-9a-f]{40}', revision)
    assert summary['status'] == 'PASS' and summary['error'] is None and summary['comparison_cases'] == 80
    assert summary['common_core_null_pairs'] == 704 and summary['common_recording_pairs'] == 2112
    assert summary['common_obligations_satisfied'] is summary['full_a3'] is summary['native_full_state'] is False
    assert comparison['revision'] == revision and comparison['cases'] == 80 and comparison['fatal'] is None
    assert comparison['counts'] == dict(PASS=80,FAILED=0,UNSUPPORTED=0,UNRUN=0)
    assert all(comparison[k] is False for k in ('architectural_full_state','normal_loader_generalization','full_a3','qualification_complete'))
    sources = parsed(a.raw/'sources-before.json')
    assert sources == parsed(a.raw/'sources-after-build.json') == parsed(a.raw/'sources-after.json')
    assert parsed(a.raw/'tools-before.json') == parsed(a.raw/'tools-after.json')
    assert parsed(a.raw/'configurations-before.json') == parsed(a.raw/'configurations-after.json')
    inputs = parsed(a.raw/'inputs.json')
    assert inputs == parsed(a.raw/'comparison/inputs.json') and inputs['revision'] == revision
    for name, digest in (('corpus.py',CORPUS_SHA),('adapter.py',NEW_SHA),('reproduce.py',REPRODUCE_SHA)):
        path = a.repo/'evaluation/offline-corpus'/name
        assert sha(read(path)) == digest
        assert sources[str(path.relative_to(a.repo))]['sha256'] == digest
        assert inputs['files'][str(path)]['sha256'] == digest

    def closed(directory, parent, limits, inner):
        request = parsed(directory/'request.json'); receipt = parsed(directory/'receipt.json')
        assert (request['cpu_seconds'],request['wall_seconds'],request['file_bytes']) == limits
        assert receipt['request_sha256'] == sha(take(directory/'request.json')) and receipt['helper_sha256'] == HELPER_SHA
        assert receipt['exit'] == 0 and receipt['absence_proof'] == 'ECHILD' and receipt['inputs_unchanged'] is True
        assert receipt['cleanup_events'] == receipt['unexpected_descendants'] == []
        assert receipt['aborted'] is receipt['cleanup_error'] is None and receipt['wall_timeout'] is False
        ended = parsed(parent/'closed.json'); begun = parsed(parent/'started.json')
        assert ended['exit'] == 0 and ended['wait_returned'] is True and ended['pid'] == begun['pid']
        assert ended.get('error',ended.get('parent_error')) is None and not ended.get('timeout',False)
        for stream in ('stdout','stderr'):
            assert sha(take(directory/(stream+'.txt'))) == receipt[stream+'_sha256']
        stem = 'helper.' if inner else ''
        assert take(parent/(stem+'stderr'+('' if inner else '.txt'))) == b''
        terminal = parsed(parent/(stem+'stdout'+('' if inner else '.txt')))
        assert terminal == dict(exit=0,wall_timeout=False,absence_proof='ECHILD',descendants=0,success=True)
        return request

    assert [r['id'] for r in summary['phases']] == ['build-core','build-target','target','compare']
    for phase,limits in zip(summary['phases'],((120,180,128<<20),(120,180,128<<20),(20,30,16<<20),(120,180,256<<20))):
        assert phase['status'] == phase['command_status'] == 'PASS' and phase['exit'] == 0
        closed(a.raw/phase['id'],a.raw/phase['id']/'parent',limits,False)
    commands = parsed(a.raw/'comparison/commands.json')
    assert len(commands) == 99 and len({r['name'] for r in commands}) == 99
    for row in commands:
        assert row['status'] == 'PASS' and row['attempted'] is True and row['exit'] == row['parent_exit'] == 0
        assert Path(row['name']).name == row['name']
        d = a.raw/'comparison'/row['name']
        limits = (60,90,128<<20) if row['name'].endswith(('-assemble','-link')) else (20,30,16<<20)
        assert closed(d,d,limits,True) == row['request']
        for field, filename in (('receipt','receipt.json'),('parent','closed.json')):
            desc = row[field]; data = take(d/filename)
            assert desc == dict(path=str(d/filename),bytes=len(data),sha256=sha(data))

    historical = subprocess.run(['/usr/bin/git','--no-pager','-C',str(a.repo),'show',
        OLD_REV+':evaluation/offline-corpus/adapter.py'], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,check=False,
        env={'PATH':'/usr/bin:/bin','LC_ALL':'C','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null'})
    assert historical.returncode == 0 and historical.stderr == b'' and len(historical.stdout) <= 65536
    corpus = module('corpus',a.repo/'evaluation/offline-corpus/corpus.py',CORPUS_SHA)
    old = module('old_witness',Path('historical-adapter-2cf9a6e.py'),OLD_SHA,historical.stdout)
    new = module('new_witness',a.repo/'evaluation/offline-corpus/adapter.py',NEW_SHA)
    cases = parsed(a.raw/'comparison/cases.json')
    assert [(r['program'],r['dataset'],r['lane']) for r in cases] == [
        (name,key,lane) for name in corpus.PROGRAMS for key in corpus.datasets()
        for lane in ('native','liteinst','stock-algorithm','bootstrap-patched-reference')]
    assert all(r['status']=='PASS' and r['attempted'] is True and r['exit']==0 for r in cases)
    original_reads = {}
    def artifact(path):
        data = take(path); original_reads[str(path)] = data; return data
    for program in ('checksum','rle-roundtrip'):
        root = a.raw/'comparison'/program
        artifact(root/'original'); artifact(root/'selection.txt')
        artifact(root/'core/COMPLETE'); index = artifact(root/'core/bundle-index.tsv')
        names = []
        for line in index.decode().splitlines()[4:]:
            tag,name,count,digest = line.split('\t')
            assert tag == 'file' and Path(name).name == name and name not in names
            names.append(name); data = artifact(root/'core'/name)
            assert len(data) == int(count) and sha(data) == digest
        assert {p.name for p in (root/'core').iterdir()} == set(names)|{'COMPLETE','bundle-index.tsv'}
        for lane in ('stock-algorithm','bootstrap-patched-reference'):
            candidate = artifact(root/lane/'candidate.elf')
            binding = json.loads(artifact(root/lane/'inventory/producer-binding.json'))
            envelope = parsed(root/lane/'envelope.json')
            assert binding['envelope_sha256'] == sha(take(root/lane/'envelope.json'))
            assert binding['input_files'] == envelope['files'] and binding['lane'] == lane
            assert binding['candidate_sha256'] == sha(candidate)
            assert binding['site_inventory_sha256'] == sha(take(root/lane/'inventory/sites.tsv'))
            for role in ('original','selection','candidate'):
                desc = binding['input_files'][role]
                path = root/lane/'candidate.elf' if role == 'candidate' else root/('selection.txt' if role == 'selection' else 'original')
                data = original_reads[str(path)]
                assert desc == dict(path=str(path),bytes=len(data),sha256=sha(data))
    x = dict(revision=revision,raw=str(a.raw))
    a.out.mkdir(mode=0o700)
    rows = []

    def observe(label, fn, should_accept, subject):
        try:
            value = fn()
        except AssertionError as error:
            frames = traceback.extract_tb(error.__traceback__)
            leaf = frames[-1]
            assert leaf.filename == subject.__file__, 'a different exception origin is not a guard refusal'
            row = dict(label=label, accepted=False, assertion=dict(file=Path(leaf.filename).name,
                function=leaf.name, line=leaf.lineno, source=leaf.line, message=str(error)))
        else:
            row = dict(label=label, accepted=True, value=value)
        row['expected_acceptance'] = should_accept
        rows.append(row)
        assert row['accepted'] is should_accept, label

    def reindex(d, files):
        old_index = files['bundle-index.tsv'].decode().splitlines()
        index = '\n'.join(old_index[:4]) + '\n'
        for line in old_index[4:]:
            tag, name, _, _ = line.split('\t'); assert tag == 'file'
            index += 'file\t%s\t%d\t%s\n' % (name, len(files[name]), sha(files[name]))
        files['bundle-index.tsv'] = index.encode()
        marker = files['COMPLETE'].decode().splitlines()
        assert marker[1].startswith('index_sha256 ')
        marker[1] = 'index_sha256 ' + sha(index.encode())
        files['COMPLETE'] = ('\n'.join(marker)+'\n').encode()
        d.mkdir()
        for name, data in files.items(): save(d/name, data)

    for program in ('checksum', 'rle-roundtrip'):
        root = Path(x['raw'])/'comparison'/program
        original = original_reads[str(root/'original')]
        selection = original_reads[str(root/'selection.txt')]
        selected = [h for h in corpus.instructions(program) if h['target'] is not None]
        target = next(line+'\n' for line in selection.decode().splitlines() if line.startswith('target '))
        prepared, _, got_selected = old.prepare(program, original, target, corpus.sha(corpus.assembly(program)))
        assert prepared == selection and got_selected == selected
        files = {Path(name).name: data for name, data in original_reads.items()
                 if Path(name).parent == root/'core'}
        d = a.out/(program+'-positive'); reindex(d, dict(files))
        observe(program+'/old-positive', lambda: old.core_witness(original, selection, d, selected), True, old)
        observe(program+'/new-positive', lambda: new.core_witness(original, selection, d, selected), True, new)
        ledger = [r.split('\t') for r in files['plan-ledger.tsv'].decode().splitlines()]
        image = next(r for r in ledger if r[0] == 'image' and r[2] == '1')
        _, image_id, _, entry, _, _, filename = image
        entry = int(entry); head = selected[0]
        boundary = next(r for r in ledger if r[:3] == ['restored-boundary', image_id, str(head['pc'])])
        body = int(boundary[3]); prefix_length = body-entry
        hook_field = next(r for r in ledger if r[:2] == ['field', image_id] and r[8] == b'HookCall'.hex())
        call_operand = int(hook_field[2])
        candidate_offset = old.owned(files['candidate.elf'], old.elf(files['candidate.elf'])[1], entry, len(files[filename]))[0]

        for mutation, old_accepts in (
            ('original-byte', False), ('source-detour', False), ('branch-condition', False),
            ('branch-target', False), ('fallthrough-target', False), ('restored-extent', False),
            ('prefix-bypass', True), ('logical-pc', True), ('hook-target', True),
            ('save-instruction', True), ('restore-instruction', True), ('xsave-mask', True),
            ('route', True), ('target-allocation', True), ('duplicate-hook-field', True)):
            changed = dict(files); ls = copy.deepcopy(ledger)
            code = bytearray(files[filename]); candidate = bytearray(files['candidate.elf'])
            if mutation in ('original-byte', 'source-detour'):
                at = 0x1000 if mutation == 'original-byte' else old.owned(original, old.elf(original)[1], head['pc'], 5)[0]
                candidate[at] ^= 1
            elif mutation == 'restored-extent':
                next(r for r in ls if r[:3] == ['restored-boundary', image_id, str(head['pc'])])[3] = str(entry+len(code))
            elif mutation == 'route':
                next(r for r in ls if r[:2] == ['route', image_id])[3] = str(entry+1)
            elif mutation == 'duplicate-hook-field':
                ls.append(hook_field[:])
            elif mutation == 'target-allocation':
                lines = changed['target.tsv'].decode().splitlines()
                lines = [('allocation_bytes\t'+str(int(r.split('\t')[1])+64)) if r.startswith('allocation_bytes\t') else r for r in lines]
                changed['target.tsv'] = ('\n'.join(lines)+'\n').encode()
            else:
                if mutation == 'prefix-bypass':
                    code[:5] = old.relative(b'\xe9', entry, body)
                else:
                    positions = {'branch-condition':prefix_length+1, 'branch-target':prefix_length+2,
                        'fallthrough-target':prefix_length+len(head['code'])+1,
                        'logical-pc':52, 'hook-target':call_operand, 'save-instruction':0,
                        'restore-instruction':prefix_length-1}
                    if mutation == 'xsave-mask':
                        mask = int(target.split()[2])
                        sequence = b'\xb8'+struct.pack('<I',mask)+b'\xba'+bytes(4)+bytes.fromhex('480fae2424')
                        assert code.count(sequence) == 1
                        positions[mutation] = code.index(sequence)+1
                    code[positions[mutation]] ^= 1
                changed[filename] = bytes(code)
                candidate[candidate_offset:candidate_offset+len(code)] = code
                next(r for r in ls if r[:2] == ['image', image_id])[5] = sha(code)
            changed['candidate.elf'] = bytes(candidate)
            changed['plan-ledger.tsv'] = ('\n'.join('\t'.join(r) for r in ls)+'\n').encode()
            d = a.out/(program+'-'+mutation); reindex(d, changed)
            observe(program+'/'+mutation+'/legacy', lambda: old.core_witness(original, selection, d, selected), old_accepts, old)
            observe(program+'/'+mutation+'/strengthened', lambda: new.core_witness(original, selection, d, selected), False, new)

        if program == 'rle-roundtrip':
            # Both actual unconditional JMP images carry the fixed terminal
            # return stub too, although normal control flow never reaches it.
            for sid in (5, 11):
                h = selected[sid-1]; assert h['code'][0] == 0xe9
                changed = dict(files); ls = copy.deepcopy(ledger)
                im = next(r for r in ls if r[0] == 'image' and r[2] == str(sid))
                _, iid, _, address, _, _, filename_jmp = im
                address = int(address)
                restored = int(next(r for r in ls if r[:3] == ['restored-boundary', iid, str(h['pc'])])[3])
                code_jmp = bytearray(files[filename_jmp]); tail = restored-address+len(h['code'])
                assert tail+5 == len(code_jmp) and code_jmp[tail] == 0xe9
                code_jmp[tail+1] ^= 1
                image_offset = old.owned(files['candidate.elf'], old.elf(files['candidate.elf'])[1], address, len(code_jmp))[0]
                candidate_jmp = bytearray(files['candidate.elf'])
                candidate_jmp[image_offset:image_offset+len(code_jmp)] = code_jmp
                im[5] = sha(code_jmp)
                changed[filename_jmp] = bytes(code_jmp); changed['candidate.elf'] = bytes(candidate_jmp)
                changed['plan-ledger.tsv'] = ('\n'.join('\t'.join(r) for r in ls)+'\n').encode()
                d = a.out/(program+'-unconditional-tail-'+str(sid)); reindex(d, changed)
                observe(program+'/unconditional-tail-'+str(sid)+'/legacy', lambda: old.core_witness(original, selection, d, selected), True, old)
                observe(program+'/unconditional-tail-'+str(sid)+'/strengthened', lambda: new.core_witness(original, selection, d, selected), False, new)

        for lane in ('stock-algorithm', 'bootstrap-patched-reference'):
            candidate = original_reads[str(root/lane/'candidate.elf')]
            binding = json.loads(original_reads[str(root/lane/'inventory/producer-binding.json')])
            observe(program+'/'+lane+'/positive', lambda: old.e9_witness(original, candidate, binding, selected), True, old)
            for mutation in ('missing-site', 'extent', 'source-detour', 'branch-condition', 'branch-target', 'fallthrough-target'):
                altered = bytearray(candidate); b = copy.deepcopy(binding)
                row = next(r for r in b['outcomes'] if r['pc'] == selected[0]['pc'])
                if mutation == 'missing-site': b['outcomes'].remove(row)
                elif mutation == 'extent': row['high'] += 1
                else:
                    address = {'source-detour':selected[0]['pc'], 'branch-condition':row['low']+1,
                        'branch-target':row['low']+2, 'fallthrough-target':row['low']+len(selected[0]['code'])+1}[mutation]
                    mappings = [m for m in b['ownership']['mappings'] if m['va'] <= address < m['va']+m['length']]
                    assert len(mappings) <= 1
                    offset = mappings[0]['offset']+address-mappings[0]['va'] if mappings else old.owned(original, old.elf(original)[1], address, 1)[0]
                    altered[offset] ^= 1
                b['candidate_sha256'] = sha(altered)
                observe(program+'/'+lane+'/'+mutation, lambda: old.e9_witness(original, bytes(altered), b, selected), False, old)

    assert all(read(name) == data for name, data in original_reads.items()), 'immutable raw bytes unchanged'
    assert all(sha(read(name)) == digest for name, digest in metadata.items()), 'saved metadata unchanged'
    result = dict(schema=1, revision=x['revision'], completed=True, native_execution=False,
        historical_adapter_revision=OLD_REV, historical_adapter_sha256=OLD_SHA,
        corpus_sha256=CORPUS_SHA, strengthened_adapter_sha256=NEW_SHA,
        controls_source_sha256=sha(read(Path(__file__).resolve())),
        saved_metadata_files=len(metadata), saved_metadata_digest=sha(json.dumps(metadata,sort_keys=True).encode()),
        positive_checks=sum(r['expected_acceptance'] and r['label'].endswith('positive') for r in rows),
        legacy_gap_acceptances=sum(r['expected_acceptance'] and r['label'].endswith('/legacy') for r in rows),
        expected_refusals=sum(not r['expected_acceptance'] for r in rows), observations=rows,
        meaning='saved-copy witness controls only; original 80 output outcomes are not changed')
    assert len(rows) == 96 and result['positive_checks'] == 8 and result['legacy_gap_acceptances'] == 20 and result['expected_refusals'] == 68
    save(a.out/'results.json', result)
    print(json.dumps({k:v for k,v in result.items() if k!='observations'},sort_keys=True))

if __name__ == '__main__': main()
