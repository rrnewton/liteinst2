"""Synthetic controls for the real pure analysis API; no native evidence."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest

_spec = importlib.util.spec_from_file_location('reference_study_analysis_under_test',
    Path(__file__).with_name('reference_study_analysis.py'))
a = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(a)

OI = [1, 2, 6, 7, 8, 11, 14, 16, 17, 18, 19, 20, 21, 23, 27, 29, 30, 31, 32,
    33, 36, 40, 44, 45, 48, 49, 51, 52, 56, 58, 59, 64, 68, 70, 71, 73, 74, 76,
    80, 81, 84, 87, 88, 89, 91, 92, 95, 96, 98, 100]


def raw(key, duration=100, entry=10, returned=20, base=1000):
    """Full synthetic 45-field parser objects, with independent fixed input algebra."""
    rows, cursor = [], base
    installed = key['leg'] == 'installed'
    for index in range(24):
        case = (index % 8)//2
        seed_index, length = case//2, (1, 64)[case % 2]
        data = [(37*j+11+seed_index) % 256 for j in range(64)]
        integrity = 14695981039346656037
        for byte in data:
            integrity = ((integrity ^ byte)*1099511628211) & ((1 << 64)-1)
        span = duration if type(duration) is int else duration[length]
        start, end = cursor, cursor+span
        cursor = end
        row = dict(phase=key['phase'], trial=key['trial'], leg=key['leg'], id=index+1,
            repeat=index//8+1, seed_index=seed_index,
            seed=(1311768467139281696, 18364758542526924135)[seed_index], length=length,
            input_fnv1a64=integrity,
            value=sum(byte ^ 0x5a for byte in data[:length]) ^ 0x9e3779b97f4a7c15,
            instructions=6*length+5, conditional_branches=length,
            taken_branches=length-1, input_bytes=length, ret_bytes=8,
            reference_sequence=index+1, reference_start_ticks=start, reference_end_ticks=end,
            reference_start_aux=0, reference_end_aux=0, reference_rsp=0x10010,
            reference_ticks=span, pid=7, tid=7)
        row.update(dict.fromkeys(('registration', 'install', 'function', 'generation', 'ordinal',
            'owner', 'invocation', 'history_prefix', 'entry_pc', 'return_pc', 'entry_rsp',
            'return_word', 'start_ticks', 'end_ticks', 'start_aux', 'end_aux', 'raw_ticks',
            'entry_gap_ticks', 'return_gap_ticks', 'ack', 'ack_ordinal')))
        if installed:
            row.update(registration=1, install=1852990822, function=1, generation=5,
                ordinal=index+1, owner='sampled', invocation=index, history_prefix=1,
                entry_pc=0x20000, return_pc=0x20024, entry_rsp=0x10008,
                return_word=0x30000+(80 if index % 2 == 0 else 216),
                start_ticks=start+entry, end_ticks=end-returned, start_aux=0, end_aux=0,
                raw_ticks=span-entry-returned, entry_gap_ticks=entry, return_gap_ticks=returned,
                ack='next-entry' if index < 23 else 'caller-checkpoint',
                ack_ordinal=index+2 if index < 23 else None)
        rows.append(row)
    return rows


def study():
    keys = a.catalog(a.MASTER_HEX)
    return keys, [a.project(key, raw(key)) for key in keys]


def wide(key, component):
    rows = raw(key, duration=0, entry=0, returned=0, base=a.U64)
    first = rows[0]
    first.update(reference_start_ticks=0, reference_ticks=a.U64)
    if key['leg'] == 'installed':
        stamp = a.U64 if component == 'entry' else 0
        first.update(start_ticks=stamp, end_ticks=stamp, raw_ticks=0,
            entry_gap_ticks=stamp, return_gap_ticks=a.U64-stamp)
    return a.project(key, rows)


class StudyAnalysis(unittest.TestCase):
    def test_canonical_integer_json_is_exact_and_rejects_noncanonical_values(self):
        self.assertEqual(a.canonical({'z': '\u03bb', 'a': [None, True, -2, 0]}),
            b'{"a":[null,true,-2,0],"z":"\\u03bb"}\n')
        self.assertEqual(a.canonical({'n': -(1 << 200)}),
            ('{"n":'+str(-(1 << 200))+'}\n').encode('ascii'))
        for value in [1.0, float('inf'), float('nan'), (1, 2), b'x', {1: 'x'}, {'x': [1.0]}]:
            with self.subTest(value=repr(value)), self.assertRaises(ValueError):
                a.canonical(value)

    def test_catalog_is_fixed_domain_separated_and_balanced(self):
        keys = a.catalog(a.MASTER_HEX)
        self.assertEqual(hashlib.sha256(a.canonical(keys)).hexdigest(),
            '89d08506fb5819745ac4e422c610f115fd0cc8ae668866f2b59a922612428145')
        self.assertEqual([key['process'] for key in keys], list(range(1, 401)))
        self.assertEqual([sum(key['phase'] == phase for key in keys)
            for phase in ('calibration', 'holdout', 'comparison')], [100, 100, 200])
        self.assertEqual(len({key['seed'] for key in keys}), 300)
        self.assertEqual(keys[0]['seed'], '3fa9c61af702f167a6bea4f0b4e0a0a4b5a0c0d1f64dd3184784f6cb28981411')
        self.assertEqual([key['trial'] for key in keys[200:]
            if key['leg'] == 'original' and key['position'] == 1], OI)
        for trial in range(1, 101):
            pair = keys[200+2*(trial-1):202+2*(trial-1)]
            self.assertEqual([key['trial'] for key in pair], [trial, trial])
            self.assertEqual([key['position'] for key in pair], [1, 2])
            self.assertEqual(pair[0]['seed'], pair[1]['seed'])
            self.assertEqual({key['leg'] for key in pair}, {'original', 'installed'})

    def test_catalog_master_and_key_mutations_refuse(self):
        for master in [None, a.MASTER_HEX.upper(), '0'*64, a.MASTER_HEX[:-1], bytes.fromhex(a.MASTER_HEX)]:
            with self.subTest(master=master), self.assertRaises(ValueError):
                a.catalog(master)
        key = a.catalog(a.MASTER_HEX)[0]
        for field, value in [('process', True), ('phase', 'qualification'), ('trial', 2),
                ('leg', 'original'), ('seed', '0'*64), ('position', 2), ('extra', 0)]:
            changed = dict(key); changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                a.project(changed, raw(key))
        key['phase'] = 'corrupted'
        self.assertEqual(a.catalog(a.MASTER_HEX)[0]['phase'], 'calibration')

    def test_projection_roundtrips_zero_max_and_all_endpoint_words(self):
        keys = a.catalog(a.MASTER_HEX)
        for key in [keys[0], keys[200]]:
            for base in [0, 1000, a.U64]:
                rows = raw(key, duration=0, entry=0, returned=0, base=base)
                for row in rows:
                    row['reference_start_aux'] = row['reference_end_aux'] = a.U32
                    if key['leg'] == 'installed':
                        row['start_aux'] = row['end_aux'] = a.U32
                observed = a.project(key, rows)
                self.assertEqual((observed['base'], observed['aux']), (base, a.U32))
                self.assertEqual(len(observed['rows']), 24)
                for row, endpoint in zip(rows, observed['rows']):
                    for word, offset in [('reference_start_ticks', 'reference_start_offset'),
                            ('reference_end_ticks', 'reference_end_offset'),
                            ('start_ticks', 'start_offset'), ('end_ticks', 'end_offset')]:
                        self.assertEqual(None if endpoint[offset] is None else base+endpoint[offset], row[word])
            self.assertEqual(wide(key, 'return')['rows'][0]['reference_end_offset'], a.U64)
        self.assertEqual(wide(keys[0], 'entry')['rows'][0]['start_offset'], a.U64)

    def test_projection_rejects_missing_duplicate_reordered_and_changed_identity(self):
        key = a.catalog(a.MASTER_HEX)[0]
        for mutation in range(12):
            rows = raw(key)
            if mutation == 0: rows.pop()
            elif mutation == 1: rows.append(rows[0])
            elif mutation == 2: rows[1] = copy.deepcopy(rows[0])
            elif mutation == 3: rows[0], rows[1] = rows[1], rows[0]
            elif mutation == 4: rows[0]['phase'] = 'holdout'
            elif mutation == 5: rows[0]['trial'] = True
            elif mutation == 6: rows[0]['leg'] = 'original'
            elif mutation == 7: rows[0]['length'] = 64
            elif mutation == 8: rows[0]['reference_sequence'] = 25
            elif mutation == 9: del rows[0]['reference_end_ticks']
            elif mutation == 10: rows[0]['extra'] = 0
            else: rows[0]['id'] = 1.0
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                a.project(key, rows)

    def test_projection_rejects_endpoint_aux_generation_and_absence_corruption(self):
        keys = a.catalog(a.MASTER_HEX)
        changes = [('reference_start_ticks', -1), ('reference_end_ticks', a.U64+1),
            ('reference_end_ticks', 999), ('reference_ticks', 99), ('start_ticks', 999),
            ('end_ticks', 1101), ('raw_ticks', 69), ('entry_gap_ticks', 11),
            ('return_gap_ticks', 21), ('reference_start_aux', 1), ('reference_end_aux', 1),
            ('start_aux', 1), ('end_aux', a.U32+1), ('pid', 8), ('tid', True),
            ('generation', 6), ('generation', None)]
        for field, value in changes:
            rows = raw(keys[0]); rows[0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                a.project(keys[0], rows)
        for field in ['generation', 'start_ticks', 'end_ticks', 'start_aux', 'end_aux',
                'raw_ticks', 'entry_gap_ticks', 'return_gap_ticks']:
            rows = raw(keys[200]); rows[0][field] = 0
            with self.subTest(original_field=field), self.assertRaises(ValueError):
                a.project(keys[200], rows)

    def test_calibration_requires_exact_complete_prefix_and_hash(self):
        keys, observations = study()
        budget = a.calibrate(observations[:100])
        self.assertEqual({name: budget[name] for name in ('Ue', 'Ur', 'B', 'status')},
            dict(Ue=10, Ur=20, B=30, status='EMPIRICAL_BUDGET'))
        self.assertEqual(budget['calibration_sha256'], hashlib.sha256(a.canonical(observations[:100])).hexdigest())
        for changed in [observations[:99], observations[:101], observations[100:200],
                [observations[1], observations[0]]+observations[2:100], observations[:99]+[observations[0]]]:
            with self.assertRaises(ValueError):
                a.calibrate(changed)

    def test_calibration_keeps_overflow_unresolved_and_comparison_continues(self):
        keys, observations = study()
        observations[0] = wide(keys[0], 'entry')
        observations[99] = wide(keys[99], 'return')
        budget = a.calibrate(observations[:100])
        self.assertEqual((budget['Ue'], budget['Ur'], budget['B'], budget['status']),
            (a.U64, a.U64, None, 'UNRESOLVED_OVERFLOW'))
        result = a.summarize(keys, observations, budget)
        holdout = result['holdout']
        self.assertIsNone(holdout['coverage']['covered'])
        self.assertIsNone(holdout['exceedance_counts']['total'])
        self.assertTrue(all(row['covered'] is None for row in holdout['processes']))
        self.assertEqual(len(result['comparison']['blocks']), 100)
        self.assertEqual(result['status'], 'DESCRIPTIVE_COMPLETE')
        # Overflow does not suppress a separately identifiable component breach.
        observations[99] = a.project(keys[99], raw(keys[99]))
        changed = raw(keys[100]); changed[0].update(end_ticks=1079, raw_ticks=69, return_gap_ticks=21)
        observations[100] = a.project(keys[100], changed)
        result = a.summarize(keys, observations, a.calibrate(observations[:100]))
        self.assertIsNone(result['budget']['B'])
        self.assertEqual(result['holdout']['processes'][0]['exceedances'],
            [dict(call=1, length=1, component='return', magnitude=1)])
        self.assertEqual(result['holdout']['exceedance_counts']['return'], 1)

    def test_holdout_retains_every_positive_exceedance_and_length(self):
        keys, observations = study()
        rows = raw(keys[100])
        for index, entry, returned in [(0, 11, 20), (1, 11, 19), (2, 10, 22)]:
            row = rows[index]
            row.update(start_ticks=row['reference_start_ticks']+entry,
                end_ticks=row['reference_end_ticks']-returned,
                raw_ticks=100-entry-returned, entry_gap_ticks=entry, return_gap_ticks=returned)
        observations[100] = a.project(keys[100], rows)
        result = a.summarize(keys, observations, a.calibrate(observations[:100]))
        holdout = result['holdout']
        self.assertEqual(holdout['coverage']['covered'], 99)
        self.assertEqual(holdout['processes'][0]['max_gap'], 32)
        self.assertEqual(holdout['processes'][0]['exceedances'], [
            dict(call=1, length=1, component='entry', magnitude=1),
            dict(call=1, length=1, component='total', magnitude=1),
            dict(call=2, length=1, component='entry', magnitude=1),
            dict(call=3, length=64, component='return', magnitude=2),
            dict(call=3, length=64, component='total', magnitude=2)])
        self.assertEqual(holdout['exceedance_counts'],
            {'entry': 2, 'return': 1, 'total': 2, 'any_known_component_rows': 3})
        self.assertEqual(holdout['by_length']['1'],
            {'entry': 2, 'return': 0, 'total': 1, 'any_known_component_rows': 2})
        self.assertEqual(holdout['by_length']['64'],
            {'entry': 0, 'return': 1, 'total': 1, 'any_known_component_rows': 1})
        self.assertEqual((len(holdout['processes']), len(result['comparison']['blocks'])), (100, 100))

    def test_comparison_preserves_signed_strata_ties_and_order_means(self):
        keys, observations = study()
        for index in range(200, 400):
            key = keys[index]; delta = key['trial']-51 if key['leg'] == 'installed' else 0
            observations[index] = a.project(key, raw(key, duration={1: 100+delta, 64: 100+2*delta},
                entry=0, returned=0))
        result = a.summarize(keys, observations, a.calibrate(observations[:100]))['comparison']
        self.assertEqual([block['contrast']['numerator'] for block in result['blocks']],
            [36*(trial-51) for trial in range(1, 101)])
        self.assertTrue(all(block['contrast']['denominator'] == 24 for block in result['blocks']))
        dist = result['all_calls']
        self.assertEqual(dist['mean'], dict(numerator=-1800, denominator=2400))
        self.assertEqual(dist['minimum'], dict(numerator=-1800, denominator=24))
        self.assertEqual(dist['maximum'], dict(numerator=1764, denominator=24))
        self.assertEqual(dist['nearest_rank'], {str(p): dict(numerator=n, denominator=24)
            for p, n in [(5, -1656), (50, -36), (95, 1584)]})
        self.assertEqual(result['by_length']['1']['mean'], dict(numerator=-600, denominator=1200))
        self.assertEqual(result['by_length']['64']['mean'], dict(numerator=-1200, denominator=1200))
        for order, trials in [('original-first', OI), ('installed-first', sorted(set(range(1, 101))-set(OI)))]:
            self.assertEqual(result['by_order'][order]['count'], 50)
            self.assertEqual(result['by_order'][order]['mean'],
                dict(numerator=sum(36*(trial-51) for trial in trials), denominator=1200))

    def test_summary_refuses_incomplete_reordered_and_wrong_catalog(self):
        keys, observations = study(); budget = a.calibrate(observations[:100])
        for changed in [observations[:-1], observations+[observations[-1]],
                observations[:200]+[observations[201], observations[200]]+observations[202:],
                observations[:399]+[observations[398]]]:
            with self.assertRaises(ValueError):
                a.summarize(keys, changed, budget)
        for field, value in [('phase', 'holdout'), ('trial', True), ('seed', '0'*64),
                ('position', 2), ('process', 0)]:
            changed = copy.deepcopy(keys); changed[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                a.summarize(changed, observations, budget)

    def test_summary_refuses_budget_and_calibration_substitution(self):
        keys, observations = study(); budget = a.calibrate(observations[:100])
        for field, value in [('Ue', 11), ('Ur', 19), ('B', 31), ('status', 'PASS'),
                ('calibration_sha256', '0'*64), ('extra', 0), ('B', 30.0)]:
            changed = dict(budget); changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                a.summarize(keys, observations, changed)
        changed = copy.deepcopy(observations); changed[0]['base'] += 1
        self.assertEqual(a.calibrate(changed[:100])['B'], budget['B'])
        with self.assertRaises(ValueError):
            a.summarize(keys, changed, budget)

    def test_projected_observations_enforce_checked_domains_and_chronology(self):
        keys, observations = study()
        for mutation in range(15):
            changed = copy.deepcopy(observations[:100]); first = changed[0]
            if mutation == 0: first['base'] = a.U64
            elif mutation == 1: first['aux'] = a.U32+1
            elif mutation == 2: first['pid'] = True
            elif mutation == 3: first['tid'] = 8
            elif mutation == 4: first['generation'] = None
            elif mutation == 5: first['rows'].pop()
            elif mutation == 6: first['rows'][0]['process'] = 2
            elif mutation == 7: first['rows'][0]['call'] = True
            elif mutation == 8: first['rows'][0]['reference_start_offset'] = 1
            elif mutation == 9: first['rows'][0]['reference_end_offset'] = -1
            elif mutation == 10: first['rows'][1]['reference_start_offset'] = 0
            elif mutation == 11: first['rows'][0]['end_offset'] = 1
            elif mutation == 12: first['rows'][0]['start_offset'] = None
            elif mutation == 13: first['rows'][0]['extra'] = 0
            else: first['rows'][0]['reference_start_offset'] = 0.0
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                a.calibrate(changed)

    def test_arbitrary_precision_reductions_never_wrap(self):
        keys, observations = study()
        for index in range(200, 400):
            key = keys[index]
            observations[index] = wide(key, 'return') if key['leg'] == 'installed' else a.project(
                key, raw(key, duration=0, entry=0, returned=0, base=0))
        result = a.summarize(keys, observations, a.calibrate(observations[:100]))['comparison']
        self.assertEqual(result['all_calls']['mean'], dict(numerator=100*a.U64, denominator=2400))
        self.assertEqual(result['by_length']['1']['mean'], dict(numerator=100*a.U64, denominator=1200))
        self.assertEqual(result['by_length']['64']['mean'], dict(numerator=0, denominator=1200))
        self.assertIn(str(100*a.U64).encode('ascii'), a.canonical(result))

    def test_full_population_zero_durations_and_pid_reuse_are_retained(self):
        keys = a.catalog(a.MASTER_HEX)
        observations = [a.project(key, raw(key, duration=0, entry=0, returned=0,
            base=0 if key['process'] % 2 else a.U64)) for key in keys]
        result = a.summarize(keys, observations, a.calibrate(observations[:100]))
        self.assertEqual(result['population'], dict(processes=400, installed=300, original=100, calls=9600, endpoints=33600))
        self.assertEqual(sum(len(item['rows']) for item in observations), 9600)
        self.assertEqual(sum(sum(row[name] is not None for name in
            ('reference_start_offset', 'reference_end_offset', 'start_offset', 'end_offset'))
            for item in observations for row in item['rows']), 33600)
        self.assertEqual(result['holdout']['coverage']['covered'], 100)
        self.assertEqual(result['budget']['B'], 0)
        self.assertEqual(result['comparison']['all_calls']['mean'], dict(numerator=0, denominator=2400))
        self.assertTrue(all(value == dict(numerator=0, denominator=24)
            for value in result['comparison']['all_calls']['nearest_rank'].values()))
        self.assertEqual({item['pid'] for item in observations}, {7})


if __name__ == '__main__':
    unittest.main()
