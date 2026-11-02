"""Old proofs keep their archive; new native/owner/lifecycle gates are mandatory.

The distinct effects native/owner/lifecycle authenticators and the40-case
component provider must validate actual same-source receipts. No diagnostic
owner, placeholder or historical source bridge accepts a receipt.
"""
import importlib
from pathlib import Path
import re

from page_selected import fact, need
from persistent_dynamic import digest, imported_sources
from direct_frontier_program import decode, direct_prerequisite
from bounded_block_prerequisite import block_prerequisite
from bounded_fused_prerequisite import fused_prerequisite
from persistent_loop_component_prerequisite import prerequisite as component_prerequisite
from loop_effects13_component import prerequisite as effects_component_prerequisite

ROOT = Path(__file__).resolve().parents[2]
PROVIDERS = {
    'native': ('persistent_loop_effects_native_prerequisite', (
        'native_v2_all_cases_and_placements', 'native_full_state', 'native_controls')),
    'owner': ('persistent_loop_effects_owner_prerequisite', (
        'policy12_focal_full_state', 'native_pair_full_state',
        'read_faults_before_effect', 'owner_and_pair_controls')),
    'lifecycle': ('persistent_loop_effects_lifecycle_prerequisite', (
        'cold_policy12', 'cold_policy11_complete_no_envelope',
        'warm_mixed_transfer_and_completion', 'reversed_primary_order',
        'replacement_generation_and_old_permit_revocation',
        'held_cancellation_and_one_ordinary_replay', 'full_state_pairs_and_controls')),
}


def future_proof(kind, path, expected_sha256, r, pin, binary, archive):
    module_name, coverage = PROVIDERS[kind]
    module_path = pin(ROOT/'evaluation/inprocess'/(module_name+'.py'))
    module = importlib.import_module(module_name)
    need(Path(module.__file__).resolve(strict=True) == module_path,
         'actual source-owned prerequisite module, with no fallback or injected provider')
    path = pin(path)
    need(path.name == 'receipt.json' and path.parent.parent == ROOT/'target/evaluation/inprocess' and
         re.fullmatch('[0-9a-f]{64}', expected_sha256) is not None and fact(path)['sha256'] == expected_sha256,
         'explicit complete private '+kind+' prerequisite identity')
    value = module.prerequisite(path, expected_sha256, r, pin, binary, archive)
    expected = dict(schema=1, kind=kind, status='verified_prerequisite',
        file=str(path.relative_to(ROOT)), **fact(path), revision=r['revision'], cpu=r['cpu'],
        source_sha256=digest(r['source']), hardware_sha256=digest(r['hardware']), archive=fact(archive),
        coverage={name: True for name in coverage}, qualification_credit=False, performance_credit=False)
    need(type(value) is dict and value == expected and digest(value) == digest(expected) and
         all(value['coverage'][name] is True for name in coverage) and
         value['qualification_credit'] is False and value['performance_credit'] is False,
         'whole verified '+kind+' prerequisite and every separate mandatory coverage gate')
    imported_sources(pin)
    return value


def prerequisites(args, r, pin, binary, archive):
    # The unchanged old validators require the old archive, not the new archive
    # with additive scalar/effects exports. Recover that exact retained identity
    # from the public/private native41 join; the full old validator follows.
    public_path = pin(args.direct_receipt)
    need(public_path.parent == ROOT/'evaluation/inprocess/results' and public_path.suffix == '.json',
         'canonical public native41 prerequisite')
    public = decode(public_path.read_bytes())
    directory = ROOT/'target/evaluation/inprocess'/public_path.stem
    receipt = pin(directory/'receipt.json')
    need(fact(receipt) == public['receipt'], 'whole native41 public/private receipt identity')
    actual = decode(receipt.read_bytes()); built = actual['build']['artifacts']['decoder.a']
    old_archive = binary(built['path'])
    need(old_archive == directory/'artifacts/decoder.a' and
         fact(old_archive) == {k: built[k] for k in ('bytes', 'sha256')} and
         actual['build']['decoder_features'] == ['scalar-region', 'scalar-span', 'linked-epoch', 'mov-guard'],
         'retained original ten-source archive remains distinct from the new feature profile')
    r['prerequisite_archive'] = fact(old_archive)
    r['prerequisite_stage'] = 'native41'
    r['direct_prerequisite'] = direct_prerequisite(public_path, r, pin, binary, old_archive)
    r['prerequisite_stage'] = 'bounded_block'
    r['block_prerequisite'] = block_prerequisite(args.block_receipt, args.block_receipt_sha256,
                                               r, pin, binary, old_archive)
    r['prerequisite_stage'] = 'bounded_fused'
    r['fused_prerequisite'] = fused_prerequisite(args.fused_receipt, args.fused_receipt_sha256,
                                               r, pin, binary, old_archive)
    r['prerequisite_stage'] = 'loop_component'
    r['loop_component_prerequisite'] = component_prerequisite(args.loop_component_receipt,
        args.loop_component_receipt_sha256, r, pin, binary, archive)
    r['prerequisite_stage'] = 'effects_component'
    r['effects_component_prerequisite'] = effects_component_prerequisite(args.effects_component_receipt,
        args.effects_component_receipt_sha256, r, pin, binary, archive)
    for kind in PROVIDERS:
        r['prerequisite_stage'] = 'loop_'+kind
        r['loop_'+kind+'_prerequisite'] = future_proof(kind, getattr(args, 'loop_'+kind+'_receipt'),
            getattr(args, 'loop_'+kind+'_receipt_sha256'), r, pin, binary, archive)
    r['prerequisite_stage'] = None
