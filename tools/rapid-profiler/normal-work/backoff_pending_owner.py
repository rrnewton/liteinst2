#!/usr/bin/env python3
"""Strict command-driven ownership-control wire; no native/timing authority."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import importlib.util
from pathlib import Path

_path = Path(__file__).resolve().with_name('backoff_work.py')
_spec = importlib.util.spec_from_file_location('_pending_owner_population', _path)
if _spec is None or _spec.loader is None:
    raise RuntimeError('missing local back-off population checker')
common = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(common)
COMMENT = '# normal backoff pending owner; deterministic native functional control; schedule not run; no timing or performance claim'
KEYS = tuple(('k hold_ordinal generation_a generation_b arms repetitions calls helper_calls '
    'instructions conditional taken input_bytes ret_bytes pid tid controller_tid app_cpu controller_cpu '
    'entry caller install function batches events rows sampled unsampled reports records actions journal_words '
    'next_entry_acknowledgements checkpoint_acknowledgements banks observed_generations rearmed '
    'sampled_after_closed input_unchanged detached joined old_report_copies shared_owner_refusals '
    'reclaim_before_checkpoint phase_rows deadline_scope schedule timing').split())
PHASE_FIELDS = tuple(('number kind hold_ordinal generation_a generation_b entered ret_observed '
    'confirmed completed unsampled a_present copied_index reports records banks current '
    'history_actions reclaim_attempts completed_batches').split())
FIXED = dict(arms=2, repetitions=128, calls=3072, helper_calls=1536, instructions=614400,
    conditional=99840, taken=96768, input_bytes=99840, ret_bytes=24576, install=1851943729,
    function=1, batches=128, events=6144, rows=3072, reports=2, actions=3, journal_words=65536,
    next_entry_acknowledgements=2944, checkpoint_acknowledgements=128, banks=3,
    observed_generations=2, joined=1, old_report_copies=1, shared_owner_refusals=2, phase_rows=3)
BOOLEANS = ('rearmed', 'sampled_after_closed', 'input_unchanged', 'detached', 'reclaim_before_checkpoint')
LITERALS = dict(deadline_scope='original-15s-functional', schedule='not-run', timing='none')
SCOPE = ('Complete command-driven functional wire only. No Schedule, timed policy, '
    'Requested shutdown, 520-arm, performance, accuracy or full-A5 qualification.')
SOURCE_ATTESTED = (common.SOURCE_ATTESTED+' The three phase summaries do not export the '
    'complete copied payload/slot/history snapshots. Actual two SharedOwner attempts and '
    'next-entry release before the same block checkpoint require authenticated producer execution.')


def _terminal(line, k, app_cpu, controller_cpu):
    words = line.split(' ')
    assert words[:2] == ['normal-observer-backoff-pending-owner', 'FUNCTIONAL_PASS']
    assert len(words) == len(KEYS)+2
    result = {}
    for key, word in zip(KEYS, words[2:]):
        assert word.startswith(key+'=')
        value = word[len(key)+1:]
        if key in LITERALS:
            assert value == LITERALS[key]
            result[key] = value
        elif key in BOOLEANS:
            assert value == 'true'
            result[key] = True
        else:
            result[key] = common._uint(value)
    assert all(result[key] == value for key, value in FIXED.items())
    assert (result['k'], result['app_cpu'], result['controller_cpu']) == (k, app_cpu, controller_cpu)
    assert result['hold_ordinal'] == (22 if k == 10 else 1006)
    assert 0 < result['generation_a'] < result['generation_b'] <= common.U64
    assert 0 < result['pid'] <= common.I32 and result['tid'] == result['pid']
    assert 0 < result['controller_tid'] <= common.I32 and result['controller_tid'] != result['tid']
    assert 0 < result['entry'] <= common.U64-37 and 0 < result['caller'] <= common.U64-67
    assert result['sampled'] == result['records'] == 2*k
    assert result['unsampled'] == 3072-2*k
    return result


def _phases(lines, terminal, k):
    assert len(lines) == 3
    t, a, b = (terminal[key] for key in ('hold_ordinal', 'generation_a', 'generation_b'))
    result = []
    for i, line in enumerate(lines, 1):
        assert len(line)+1 <= 272
        cells = line.split(',')
        assert cells[0] == 'PHASE' and len(cells) == len(PHASE_FIELDS)+1
        row = {}
        for field, value in zip(PHASE_FIELDS, cells[1:]):
            if field == 'kind':
                assert value == ('shared-owner' if i < 3 else 'reclaimed')
                row[field] = value
            elif field == 'a_present':
                assert value == ('true' if i < 3 else 'false')
                row[field] = value == 'true'
            else:
                row[field] = common._uint(value)
        expected = (t, t, t-1, k, t-1-k) if i < 3 else (t+2, t+2, t+1, k+1, t-k)
        assert tuple(row[field] for field in ('entered','ret_observed','confirmed','completed','unsampled')) == expected
        assert tuple(row[field] for field in ('number','hold_ordinal','generation_a','generation_b',
            'copied_index','reports','records','banks','current','history_actions','reclaim_attempts',
            'completed_batches')) == (i,t,a,b,0,1,k,1 if i < 3 else 2,b,2,i,(t-22)//24)
        result.append(row)
    return result


def check(stdout, stderr, k, app_cpu, controller_cpu):
    assert type(k) is int and k in (10,1000)
    assert all(type(cpu) is int and 0 <= cpu <= 1023 for cpu in (app_cpu,controller_cpu))
    assert app_cpu != controller_cpu
    assert type(stdout) is bytes and 0 < len(stdout) <= common.MAX_OUTPUT
    assert type(stderr) is bytes and stderr == b''
    assert stdout.endswith(b'\n') and common.ASCII.fullmatch(stdout)
    lines = stdout[:-1].decode('ascii').split('\n')
    assert len(lines) == 3083 and lines[:2] == [COMMENT,common.HEADER]
    assert sum(len(line)+1 for line in (lines[0],lines[1],lines[-1])) <= 4096
    terminal = _terminal(lines[-1],k,app_cpu,controller_cpu)
    # Real shared population grammar, never a rewritten timed transcript.
    result = common._population(lines[2:3074],lines[3074:3077],lines[3077:3079],terminal,k)
    a,b,t = (terminal[key] for key in ('generation_a','generation_b','hold_ordinal'))
    assert [row['generation'] for row in result['history']] == [a,b,b]
    for g,row in enumerate(result['rows']):
        generation,prefix,local = (a,1,g) if g < t else (b,2,g-t)
        assert (row['generation'],row['history_prefix']) == (generation,prefix)
        assert row['owner'] == ('sampled' if local < k else 'closed')
    assert result['rows'][t-1]['owner'] == 'closed'
    assert (result['rows'][t-1]['ack'],result['rows'][t-1]['ack_ordinal']) == ('N',t+1)
    assert (result['rows'][t]['invocation'],result['rows'][t+1]['invocation']) == (0,1)
    assert (result['rows'][t+1]['ack'],result['rows'][t+1]['ack_ordinal']) == ('C',None)
    phases = _phases(lines[3079:3082],terminal,k)
    result.update(phases=phases,phase_table=('\n'.join(lines[3079:3082])+'\n').encode('ascii'),
        scope=SCOPE,source_attested=SOURCE_ATTESTED)
    return result
