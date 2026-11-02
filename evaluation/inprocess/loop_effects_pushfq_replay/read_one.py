"""Read one closed effects owner record with one explicit private model overlay; no subjects, builds, controls or qualification.

Run with Python 3.12 -B on a separately reserved singleton, under external
30 CPU seconds / 60 wall seconds / 512 MiB AS / 16 MiB output limits.
Example: read_one.py --case 3 --placement 0. All paths are relative to cwd.
The original failed owner receipt remains failed regardless of this result.
"""
import argparse, ctypes, hashlib, importlib.util, importlib.machinery, json, os, signal, struct, sys, traceback
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
SELECTED = ROOT/'tools/page-entry/selected'
NATIVE = ROOT/'target/evaluation/inprocess/tunables-effects-full19-r2-loop-native'
OWNER = ROOT/'target/evaluation/inprocess/tunables-effects-full19-r2-loop-owner'
REVISION = '1b2028e795bac3b308114d73681311b67cf2da1a'
NATIVE_SHA = '63ffcec24921e93d9ef9682e04feb411a1684f21c1ed93939701a5a0e4f4fbf1'
OWNER_SHA = '02ed8e3106cb8add3f761dd4f7e9f80f745a5b8008694fc183a353635b3b849a'


def fact(path):
    b = Path(path).read_bytes()
    return dict(bytes=len(b), sha256=hashlib.sha256(b).hexdigest())


def context(case, placement, lane, candidate, candidate_sha):
    """Return unchanged reader arguments from authenticated closed actual files."""
    assert fact(NATIVE/'receipt.json')['sha256'] == NATIVE_SHA
    assert fact(OWNER/'receipt.json')['sha256'] == OWNER_SHA
    n = json.loads((NATIVE/'receipt.json').read_bytes())
    r = json.loads((OWNER/'receipt.json').read_bytes())
    assert n['revision'] == r['revision'] == REVISION
    assert n['source'] == r['source'] and n['hardware'] == r['hardware'] and n['cpu'] == r['cpu'] == 192
    assert n['status'] == 'observed_native_references' and r['status'] == 'failed'
    assert all(v[k] is True for v in (n, r) for k in ('source_unchanged', 'inputs_unchanged', 'cleanup_complete'))
    pins = {}
    inputs = dict(n['inputs'])
    for p, value in r['inputs'].items():
        assert p not in inputs or inputs[p] == value
        inputs[p] = value

    artifacts = dict(n['artifacts'])
    for p, value in r['artifacts'].items():
        assert p not in artifacts or artifacts[p] == value
        artifacts[p] = value
    for p in set(inputs) & set(artifacts):
        assert inputs[p] == {k:artifacts[p][k] for k in ('bytes', 'sha256')}

    def pin(path):
        p = Path(path).resolve(strict=True)
        value = fact(p)
        assert str(p) not in pins or pins[str(p)] == value
        pins[str(p)] = value
        assert str(p) in inputs or str(p) in artifacts
        if str(p) in artifacts:
            assert value == {k:artifacts[str(p)][k] for k in ('bytes', 'sha256')}
            assert p.stat().st_mode & 0o7777 == artifacts[str(p)]['mode']
        if str(p) in inputs:
            assert inputs[str(p)] == value
        if p.is_relative_to(ROOT) and not p.is_relative_to(ROOT/'target'):
            assert inputs[str(p)] == value
        return p

    # Only this explicit model leaf is overlaid; every original module still
    # resolves sibling imports from its real repository path. Record both facts.
    original_model=SELECTED/'tests/persistent_loop_effects_owner/source_decode.py'
    candidate=Path(candidate).resolve(strict=True)
    candidate_fact=fact(candidate);assert candidate_fact['sha256']==candidate_sha
    script_fact=fact(__file__)
    real_spec=importlib.util.spec_from_file_location
    class OverlayLoader(importlib.machinery.SourceFileLoader):
        def get_code(self, fullname):
            assert fact(candidate)==candidate_fact
            return compile(candidate.read_bytes(),str(original_model),'exec',dont_inherit=True)
    def model_spec(name, path, *args, **kwargs):
        p=Path(path).resolve()
        if p.is_relative_to(ROOT) and not p.is_relative_to(ROOT/'target'):pin(p)
        if p==original_model:
            assert not args and not kwargs
            return real_spec(name,p,loader=OverlayLoader(name,str(p)))
        return real_spec(name,path,*args,**kwargs)
    importlib.util.spec_from_file_location=model_spec

    def load(name, path):
        spec = importlib.util.spec_from_file_location(name, pin(path))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def capture(directory, value):
        p = pin(directory/value['file'])
        assert fact(p) == {k:value[k] for k in ('bytes', 'sha256')}
        return p.read_bytes()

    sys.path[:0] = [str(ROOT/'evaluation/inprocess'), str(SELECTED.parent)]
    source_model=load('effects_model_overlay',original_model)
    prefix_controls=[]
    for decoder in (source_model.decode12,source_model.decode):
        for prefix in (b'\x66',b'\x67',b'\xf0',b'\xf2',b'\xf3',b'\x40',b'\x48',b'\x64'):
            try:decoder(0x200021031,prefix+b'\x9c')
            except source_model.CoverageError:prefix_controls.append(prefix.hex());continue
            raise ValueError('prefixed PUSHFQ incorrectly acquired independent coverage')
    assert len(prefix_controls)==16
    try:source_model.old.decode(0x200021031,b'\x9c')
    except source_model.CoverageError:pass
    else:raise ValueError('old source model changed')
    ar = load('r4_single_app', SELECTED/'tests/tunables_loop_paired_app/read.py')
    reader = load('r4_single_owner', SELECTED/'tests/persistent_loop_effects_owner/read.py')
    sr = load('r4_single_seed', SELECTED/'tests/provider_app/seed_probe/read.py')
    xs = load('r4_single_xstate', SELECTED/'tests/b2_reference/xstate.py')
    raw = capture(NATIVE, next(x for x in n['commands'] if x['name'] == 'seed-prerequisite')['captures']['stdout'])
    h = struct.unpack_from('<16Q', raw, 128)
    cp = [struct.unpack_from('<6I', raw, 256+24*i) for i in range(67)]
    facts = xs.profile(cp, h[8], h[10], h[12], h[5], h[6])
    profile = sr.read(raw, pin(NATIVE/'seed-probe').read_bytes(), facts, xs,
                      cpu=192, pid=n['seed_prerequisite']['pid'])
    assert sr.require(profile, facts, cpu=192) == bytes(16)
    seed = (sr, xs, profile, facts, raw)
    policy = pin(NATIVE/'native-policy.so')
    assert fact(policy) == {k:n['reader_support']['native_policy'][k] for k in ('bytes', 'sha256')}
    lib = ctypes.CDLL(str(policy))
    lib.li2_native_policy.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
    lib.li2_native_policy.restype = ctypes.c_uint
    original = pin(NATIVE/'application/tunables-loop-paired')
    assert fact(original) == n['application_build']['artifact']
    image = ar.elf(original.read_bytes(), lambda b:lib.li2_native_policy(b, len(b)),
                   json.loads(pin(NATIVE/'native-dwarf-layout.json').read_bytes()), n['application_build']['headers'])
    label = 'subject-'+lane+'-'+str(case)+'-'+str(placement)
    row = next(x for x in r['commands'] if x['name'] == label)
    current = next(x for x in r['cases'] if x['label'] == label)
    assert json.loads(pin(OWNER/(label+'.json')).read_bytes()) == row
    status = 125 if case >= 5 else 0
    assert row['exit'] == row['expected_exit'] == current['exit'] == status
    assert row['reaped'] and not row['timed_out'] and row['cleanup_errors'] == []
    assert row['bounds'] == [30, 536870912, 16777216, 60] and all(v['closed'] for v in row['descriptors'])
    stdout = capture(OWNER, row['captures']['stdout'])
    record = capture(OWNER, row['captures']['record'])
    app = (ar.prefix(stdout, 1, case, placement, image, row['pid'], 192, seed) if case >= 5 else
           ar.read(stdout, 1, case, placement, status, image, row['pid'], 192, seed))
    nr = next(x for x in n['commands'] if x['name'] == 'subject-native-'+str(case)+'-'+str(placement))
    native = ar.read(capture(NATIVE, nr['captures']['stdout']), 0, case, placement, 0, image, nr['pid'], 192, seed)
    import namespace
    from persistent_loop_native_build import preparation
    from unrolled_hash_owner import image_inventory
    build = OWNER/(lane+'-build')
    mode = 'differential' if lane == 'differential' else 'capture'
    products = build/('persistent-loop-effects-'+mode)
    bridge = pin(products/('bridge-persistent-loop-effects-'+mode+'.so'))
    carrier = pin(build/'carrier')
    interp = pin(n['application_build']['interpreter']['path'])
    observed = r['lanes'][lane]
    assert fact(bridge) == observed['subject_artifacts']['bridge']
    assert fact(carrier) == observed['subject_artifacts']['carrier']
    objects, description = namespace.plan(original, [original.parent],
        bytes.fromhex(fact(original)['sha256']), bytes.fromhex(fact(interp)['sha256']))
    assert objects == []
    manifest = preparation(current, row, OWNER/label, original, [original.parent], objects,
        description, carrier, OWNER, pin, dict(cpu=192, namespace_aliases={}))
    inventory = image_inventory(original, interp, carrier, objects, manifest)
    binding = json.loads(pin(products/'persistent_loop_effects_binding.json').read_bytes())
    observed_binding = observed['release_build']['persistent_binding']
    assert binding == {k:v for k,v in observed_binding.items() if k not in ('manifest', 'header_paths')}
    manifest_fact = observed_binding['manifest']
    assert pin(manifest_fact['path']) == products/'persistent_loop_effects_binding.json'
    assert fact(manifest_fact['path']) == {k:manifest_fact[k] for k in ('bytes', 'sha256')}
    assert set(observed_binding['header_paths']) == set(binding['headers'])
    for name, value in observed_binding['header_paths'].items():
        assert pin(value['path']) == products/name
        assert fact(value['path']) == binding['headers'][name] == {k:value[k] for k in ('bytes', 'sha256')}
    for p, value in observed['release_build']['headers'].items():
        assert fact(pin(p)) == value
    inventory.update(bridge=bridge.read_bytes(), persistent_binding=binding,
        headers=observed['release_build']['headers'], app_symbols=image['symbols'])
    layout = json.loads(pin(build/'owner-dwarf-layout.json').read_bytes())
    assert layout == json.loads(pin(OWNER/(lane+'-owner-layout.stdout')).read_bytes())

    def closure():
        assert fact(candidate)==candidate_fact and fact(__file__)==script_fact
        assert all(fact(p) == v for p, v in pins.items())
        assert all(Path(p).stat().st_mode & 0o7777 == artifacts[p]['mode']
                   for p in pins if p in artifacts)
        for module in list(sys.modules.values()):
            path = getattr(module, '__file__', None)
            if path and not str(path).startswith('<'):
                p = Path(path).resolve()
                if p.is_relative_to(ROOT) and not p.is_relative_to(ROOT/'target'):
                    assert fact(p) == inputs[str(p)]
    return reader, (record, layout, inventory, app, row['pid'], 192, status), native, closure


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--case', type=int, choices=range(7), required=True)
    p.add_argument('--placement', type=int, choices=range(4), required=True)
    p.add_argument('--lane', choices=('maintained', 'differential'), default='maintained')
    p.add_argument('--candidate',type=Path,required=True)
    p.add_argument('--candidate-sha256',required=True)
    args = p.parse_args()
    assert not sys.flags.optimize and len(os.sched_getaffinity(0)) == 1
    signal.alarm(60)
    reader, values, native, closure = context(args.case, args.placement, args.lane, args.candidate, args.candidate_sha256)
    phase = 'owner_reader'
    try:
        owner = reader.read(*values)
        phase = 'pair'
        pair = reader.pair(native, values[3], owner)
        print(json.dumps(dict(status='diagnostic_single_pair_passed', pair=pair, original_receipt_remains_failed=True, candidate=fact(args.candidate), prefix_controls=16, qualification_credit=False)), flush=True)
        return 0
    except Exception as error:
        print(json.dumps(dict(status='single_reader_failed', phase=phase,candidate=fact(args.candidate),prefix_controls=16,
            error_type=type(error).__name__, error=str(error), original_receipt_remains_failed=True,
            qualification_credit=False)), flush=True)
        traceback.print_exc()
        return 1
    finally:
        closure()
        signal.alarm(0)


if __name__ == '__main__':
    raise SystemExit(main())
