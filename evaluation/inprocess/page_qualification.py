#!/usr/bin/env python3
"""Project pinned, closed qualification receipts; never run subjects or architectural readers."""
import argparse, collections, hashlib, json, re, subprocess
from pathlib import Path


def need(ok, why):
    if not ok: raise ValueError(why)


def encode(x): return json.dumps(x, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
def digest(x): return hashlib.sha256(encode(x)).hexdigest()
def fact(b): return dict(bytes=len(b), sha256=hashlib.sha256(b).hexdigest())
def pick(x, keys): return {k: x[k] for k in keys.split()}


def at(x, path, optional=False):
    for k in path.split('.'):
        if not isinstance(x, dict) or k not in x:
            need(optional, 'missing field: '+path)
            return None
        x = x[k]
    return x


FIELDS = {
 'mask': 'name accepted actual_exit operation_completed header.completed header.pairs header.refusals footprint.actual_before_queries vtm256_promotions.typed_promotions vtm256_promotions.supplied_none_queries',
 'vector': 'name actual_exit outcome.operation outcome.pairs outcome.new_pairs outcome.refusals outcome.actual_before_queries',
 'flat_vector': 'name status exit operation pairs new_pairs verified_memory_failures actual_before_queries refusals',
 'repeat': 'accepted actual_exit operation_completed actual_failed_operation',
 'rseq': 'name accepted operation_exit guard_kind new_rx_calls target_raw_calls',
 'negative': 'mode exit expected.owner_error expected.report_error',
 'zero': 'name accepted actual_exit result',
}
SCALARS = {
 'rseq': 'required_cases accepted_cases completed_cases required_refusals finite_command_count',
 'negative': 'required_cases attempted_cases qualified_failed_operations qualified_refused_sites full_cohort_qualified B2_completion_credit',
 'zero': 'required_native_processes actual_native_processes',
 'effect': 'accepted_pairs oneshot',
 'application': 'namespace_controls full_b2_qualification full_b3_qualification',
}


def table(rows, fields, incomplete=False):
    return dict(columns=fields.split(), rows=[[at(c, k, incomplete) for k in fields.split()] for c in rows])


def numeric_table(columns, rows):
    need(all(len(c) == len(columns) for c in rows), 'complete table rows')
    # Retain all numeric/semantic columns; one record hash is represented by the whole-table digest.
    keep = [i for i, k in enumerate(columns) if k not in ('record_sha256', 'captures_sha256', 'sha256')]
    return dict(columns=[columns[i] for i in keep], rows=[[c[i] for i in keep] for c in rows], original_rows_sha256=digest(rows))


def summary(kind, p, r):
    out = pick(p, SCALARS.get(kind, ''))
    if 'totals' in p:
        need(p['totals'] == r['totals'], 'public/private totals')
        out['totals'] = p['totals']
    if kind in FIELDS:
        src = r if kind == 'negative' else p
        out.update(table(src['cases'], FIELDS[kind], p['status'] == 'failed'))
    elif kind == 'numeric': out.update(numeric_table(p['case_columns'], p['cases']))
    elif kind == 'effect':
        out.update(table(p['cases'], 'name status exit', p['status'] == 'failed'))
    elif kind == 'pair':
        n = p['native_pair']
        out.update(pair={k:v for k,v in n.items() if not isinstance(v, (dict, list))},
            old_registered=p['rseq_native'], old_boundary=p['rseq_native_boundary'], companions=p['companions'],
            controls=dict(columns=n['reader_control_columns'], rows=n['reader_control_rows']))
        out.update(numeric_table(n['columns'], n['rows']))
    elif kind == 'application':
        fields = 'lane status exit whole_process_ns captures.stdout.bytes captures.stderr.bytes captures.record.bytes application.effects application.cycles application.live_state_snapshots reader_controls.rejected'
        out.update(table(p['cases'], fields, True))
        out['pair'] = None if p['pair'] is None else {k:v for k,v in p['pair'].items() if not isinstance(v, (dict, list))}
        out['terminal'] = [c.get('terminal') for c in p['cases']]
        out['terminal_controls'] = [dict(refusals=len(c['terminal_controls']['refusals']), native_qualification_credit=c['terminal_controls']['native_qualification_credit']) if 'terminal_controls' in c else None for c in p['cases']]
    elif kind == 'checks':
        need(p == r and len(p['commands']) == 6, 'exact six-check receipt')
        need([c['id'] for c in p['commands']] == ['recorder_tests','fmt','clippy','workspace_tests','workspace_check','serial_launch'], 'six required check identities')
        cols = 'id argv status exit_code seconds timeout_seconds tests_passed harness_totals evidence_status parse_error private_log_sha256 cleanup_complete termination'
        out.update(table(p['commands'], cols, True))
        out['required_counts'] = [{k:v for k,v in c.items() if k.endswith('_count')} for c in p['commands']]
    else: need(False, 'unknown receipt schema')
    return out


def hardware(h):
    h = dict(h)
    if 'isa_flags' in h:
        flags = h.pop('isa_flags'); h.update(isa_flags_count=len(flags), isa_flags_sha256=digest(flags))
    return h


def closure(v):
    count = 0
    if isinstance(v, dict):
        for k in ('inputs', 'binaries', 'artifacts', 'aliases', 'registry'):
            if k+'_before' in v:
                need(k+'_after' in v and v[k+'_before'] == v[k+'_after'], 'retained '+k+' closure')
                count += 1
        count += sum(closure(x) for x in v.values())
    elif isinstance(v, list): count += sum(closure(x) for x in v)
    return count


def expand(packed):
    """Restore the ordinary schema-1 JSON, including complete table rows."""
    need(packed['schema'] == 2 and packed['text_encoding'] == 'tilde-fixed-base36-v1', 'representation schema')
    tokens, width = packed['text_tokens'], packed['text_index_width']
    need(isinstance(tokens, list) and all(isinstance(x, str) for x in tokens) and len(set(tokens)) == len(tokens), 'unique text tokens')
    expected = 1
    while 36**expected < len(tokens): expected += 1
    need(type(width) is int and width == expected, 'text reference width')
    pattern = re.compile(r'~~|~([0-9a-z]{'+str(width)+'})')
    def text(v):
        if isinstance(v, dict): return {text(k):text(x) for k,x in v.items()}
        if isinstance(v, list): return [text(x) for x in v]
        def replace(match):
            if match.group(1) is None: return '~'
            index = int(match.group(1), 36); need(index < len(tokens), 'text reference index')
            return tokens[index]
        return pattern.sub(replace, v) if isinstance(v, str) else v
    def tables(v):
        if isinstance(v, list): return [tables(x) for x in v]
        if not isinstance(v, dict): return v
        v = {k:tables(x) for k,x in v.items()}
        if 'row_tails' in v:
            tails = v.pop('row_tails'); v['rows'] = [[head, *tails[index]] for head,index in v['rows']]
        return v
    return tables(text(packed['data']))


def compact(out):
    """Pool repeated table suffixes and text; retain numerical JSON values."""
    original = encode(out)
    need(not re.search(rb'/home/|/usr/local/|devbig[0-9]+|internalfb\.com', original), 'no decoded private host paths/names')
    def tables(v):
        if isinstance(v, list): return [tables(x) for x in v]
        if not isinstance(v, dict): return v
        need('row_tails' not in v, 'unambiguous row-tail representation')
        v = {k:tables(x) for k,x in v.items()}
        if not (isinstance(v.get('columns'), list) and isinstance(v.get('rows'), list) and len(v['rows']) > 1 and len(v['columns']) > 1): return v
        if not all(isinstance(row, list) and len(row) == len(v['columns']) for row in v['rows']): return v
        tails, indices, rows = [], {}, []
        for row in v['rows']:
            key = encode(row[1:])  # False/0, True/1 and int/float remain distinct.
            if key not in indices: indices[key] = len(tails); tails.append(row[1:])
            rows.append([row[0], indices[key]])
        candidate = dict(v, rows=rows, row_tails=tails)
        return candidate if len(encode(candidate)) < len(encode(v)) else v
    tabular = tables(out)
    def strings(v):
        if isinstance(v, dict):
            for k,x in v.items(): yield k; yield from strings(x)
        elif isinstance(v, list):
            for x in v: yield from strings(x)
        elif isinstance(v, str): yield v
    counts = collections.Counter(strings(tabular))
    candidates = {part for value in counts for part in [value, *value.split('/')] if len(part) >= 6 and '~' not in part}
    scored = []
    for token in candidates:
        uses = sum(value.count(token)*n for value,n in counts.items())
        saved = uses*(len(token)-4)-len(encode(token))-1
        if uses > 1 and saved > 0: scored.append((saved, token))
    tokens = [token for _,token in sorted(scored, key=lambda x:(-x[0], x[1]))]
    def text(tokens):
        width = 1
        while 36**width < len(tokens): width += 1
        def reference(index):
            tag = ''
            for _ in range(width): tag = '0123456789abcdefghijklmnopqrstuvwxyz'[index%36]+tag; index //= 36
            return '~'+tag
        references = {token:reference(i) for i,token in enumerate(tokens)}; used = set()
        pattern = re.compile('|'.join(['~', *[re.escape(token) for token in sorted(tokens, key=lambda x:(-len(x), x))]]))
        def replace(match):
            token = match.group()
            if token == '~': return '~~'
            used.add(token); return references[token]
        def visit(v):
            if isinstance(v, dict): return {pattern.sub(replace,k):visit(x) for k,x in v.items()}
            if isinstance(v, list): return [visit(x) for x in v]
            return pattern.sub(replace,v) if isinstance(v, str) else v
        return visit(tabular), used, width
    data, used, width = text(tokens)
    tokens = [token for token in tokens if token in used]
    data, used, width = text(tokens)
    packed = dict(schema=2, text_encoding='tilde-fixed-base36-v1', text_index_width=width, text_tokens=tokens, data=data)
    need(encode(expand(packed)) == original, 'canonical whole-object representation inverse')
    return packed


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root', type=Path, default=Path.cwd()); ap.add_argument('--manifest', type=Path, required=True)
    ap.add_argument('--manifest-sha256', required=True); ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args(); root = a.root.resolve()
    raw = a.manifest.read_bytes(); need(fact(raw)['sha256'] == a.manifest_sha256, 'frozen manifest hash')
    m = json.loads(raw); need(m['schema'] == 1 and m['sealed'] is True, 'closed manifest required')
    need(len(m['receipts']) == m['required_receipts'] and len({e['label'] for e in m['receipts']}) == len(m['receipts']), 'complete unique receipt population')
    need([e['label'] for e in m['receipts']] == m['required_labels'], 'fixed ordered labels')
    sources, hosts, limits, audits_pool, rows = [], [], [], [], []
    def pool(xs, x):
        if x not in xs: xs.append(x)
        return xs.index(x)
    def read(pin):
        path = Path(pin['file']); need(not path.is_absolute() and '..' not in path.parts, 'relative evidence path')
        target = (root/path).resolve(); need(target.is_relative_to(root), 'evidence inside repository')
        need(0 <= pin['bytes'] <= 32 << 20 and target.stat().st_size == pin['bytes'], 'bounded pinned file')
        data = target.read_bytes(); need(fact(data) == pick(pin, 'bytes sha256'), 'exact evidence bytes: '+str(path))
        return data
    for e in m['receipts']:
        pb, rb = read(e['public']), read(e['private']); p, r = json.loads(pb), json.loads(rb)
        need(p['status'] == r['status'] == e['status'] and e['status'] in ('passed','passed_finite_inactive_profile','failed'), 'original closed status')
        need(p.get('profile') == e['profile'], 'exact profile')
        src = p['source']; need(src == r['source'] and src['revision'] == p['expected_revision'] == r['expected_revision'] == m['revision'], 'same exact revision')
        need(src['tracked_clean'] is True and src['head_sources_match'] is True and p['source_unchanged'] is True and r['source_unchanged'] is True, 'source closure')
        need(re.fullmatch('[0-9a-f]{40}', src['revision']) and re.fullmatch('[0-9a-f]{64}', src['source_manifest_sha256']), 'source identities')
        tree = subprocess.check_output(['git','-C',str(root),'rev-parse',src['revision']+'^{tree}']).decode().strip()
        need(tree == src['tree'] and ('source_after' not in r or r['source_after'] == src), 'historical Git tree')
        if e['kind'] == 'checks': need(p == r and p['configuration_unchanged'] is True, 'checks configuration closure')
        else: need(p['private_receipt'] == fact(rb) and p['final_error_count'] == len(r['final_errors']), 'private receipt/final errors')
        hw = hardware(p['hardware']); need(hw == hardware(r['hardware']), 'actual hardware projection')
        bd = p.get('bounds', {'log_limit_bytes_per_command':p.get('log_limit_bytes_per_command'), 'wall_seconds':[c['timeout_seconds'] for c in p['commands']]}) if e['kind']=='checks' else p['bounds']
        need(bd == m['bounds'][e['bounds']] and ('bounds' not in r or r['bounds'] == bd), 'exact original bounds')
        if 'configuration_unchanged' in p: need(p['configuration_unchanged'] is True, 'configuration unchanged')
        cl = closure(r); need(cl == e['closure_pairs'], 'complete before/after closure population')
        commands = r['commands']; need(len(commands) == e['command_count'], 'closed command count')
        for key in ('commands_sha256','command_rows_sha256'):
            if key in p: need(p[key] == digest(commands), 'public/private command digest')
        if e['kind'] != 'checks': need(all(c['bounds'] in bd.values() for c in commands), 'every command retains published bounds')
        if 'command_count' in p: need(p['command_count'] == len(commands), 'public command count')
        if isinstance(p.get('commands'), int): need(p['commands'] == len(commands), 'public command count')
        if e['kind'] == 'checks':
            clean = [c.get('cleanup_complete') for c in commands]
            faults = [c for c in commands if c['status'] != 'passed' or c.get('exit_code') != 0 or c.get('termination') is not None]
        else:
            clean = [c.get('reaped') is True and not c.get('cleanup_errors') for c in commands]
            faults = [dict(name=c['name'], exit=c.get('exit'), expected_exit=c.get('expected_exit'), reaped=c.get('reaped'), timed_out=c.get('timed_out'), error=c.get('error'), cleanup_errors=c.get('cleanup_errors')) for c in commands if c.get('error') or c.get('cleanup_errors') or c.get('reaped') is not True or c.get('timed_out') or (c.get('expected_exit') is not None and c.get('exit') != c['expected_exit'])]
        observation = dict(all_commands_clean=all(x is True for x in clean), cleanup_complete=p.get('cleanup_complete'), final_errors=r.get('final_errors'), failed_commands=len(faults))
        need(observation == e['closure'], 'exact observed cleanup, including failures')
        if e['status'] != 'failed': need(observation['all_commands_clean'] and not faults and not r.get('error') and not r.get('final_errors'), 'passed receipt closure')
        result = summary(e['kind'], p, r)
        need(len(result['rows']) == e['rows'], 'exact retained process/check rows')
        for path, value in e['expect'].items(): need(at(p, path) == value, 'pinned observation: '+path)
        if e['status'] != 'failed':
            for path, value in e['complete'].items(): need(at(p, path) == value, 'unchanged complete cohort: '+path)
        terminal = None
        if e['terminal'] is not None:
            t = e['terminal']; data = read(t['capture']); cs = [c for c in commands if c.get('name') == t['command']]
            need(len(cs) == 1 and pick(cs[0]['captures']['stderr'], 'bytes sha256') == pick(t['capture'], 'bytes sha256'), 'terminal capture command join')
            found = [json.loads(x[11:]) for x in data.splitlines() if x.startswith(b'LI2_LOADER ')]
            need(len(found) == 1, 'unique actual loader terminal')
            terminal = pick(found[0], 'status failure_code detail_abs detail_negative last_syscall selected_steps')
            need(terminal == t['expected'], 'actual terminal fields')
        audits = []
        for pin in e['audits']: read(pin); audits.append(pool(audits_pool,pick(pin, 'file bytes sha256')))
        need(audits, 'independent closed data review required')
        cpu, affinity = hw.pop('probe_cpu'), hw.pop('affinity_cpu_count')
        rows.append(dict(label=e['label'], public=e['public'], private=e['private'], status=p['status'], required=e['required'], source=pool(sources,src), hardware=pool(hosts,hw), cpu=cpu, affinity_cpu_count=affinity, bounds=pool(limits,bd), reproduce=p['reproduce'], commands=len(commands), commands_sha256=digest(commands), exit_counts=dict(collections.Counter(str(c.get('exit',c.get('exit_code'))) for c in commands)), closure=observation, result=result, failure=dict(error=r.get('error'), commands=faults, terminal=terminal) if p['status']=='failed' else None, audits=audits))
    out = dict(schema=1, status='closed_receipts_projected', statuses=dict(collections.Counter(e['status'] for e in m['receipts'])), manifest=fact(raw), revision=m['revision'], sources=sources, hardware=hosts, bounds=limits, audits=audits_pool, rows=rows,
        scope='Exact pinned receipt projection; original statuses and required failed operations retained. Independent audits validate source/artifacts/captures and full architectural readers. This program does not replay readers, launch subjects, or grant performance/full-B3 credit.',
        reproduce=['python3','-B','evaluation/inprocess/page_qualification.py','--root','${REPOSITORY}','--manifest','${FROZEN_MANIFEST}','--manifest-sha256',a.manifest_sha256,'--output','${NEW_OUTPUT}'])
    # Lossless representation only: retain an asserted inverse for each shared column set.
    total_columns = []
    for row in rows:
        result = row['result']
        if 'totals' in result:
            original = result['totals']; columns = list(original)
            packed = [pool(total_columns, columns), list(original.values())]
            need(dict(zip(total_columns[packed[0]], packed[1])) == original, 'totals inverse')
            result['totals'] = packed
        for key in ('public','private'):
            original = row[key]; packed = [original[k] for k in ('file','bytes','sha256')]
            need(dict(zip(('file','bytes','sha256'),packed)) == original, 'receipt fact inverse')
            row[key] = packed
    columns = list(rows[0]); packed = [[row[k] for k in columns] for row in rows]
    need([dict(zip(columns,row)) for row in packed] == rows, 'complete receipt row inverse')
    out.update(columns=columns, rows=packed, receipt_fact_columns=['file','bytes','sha256'], total_columns=total_columns)
    out = compact(out)
    data = encode(out)+b'\n'; need(len(data) <= 40*1024, 'unchanged 40KiB projection limit')
    need(not re.search(rb'/home/|/usr/local/|devbig[0-9]+|internalfb\.com',data), 'no private host paths/names')
    with a.output.open('xb') as f: f.write(data)
    print(json.dumps(dict(**fact(data), receipts=len(rows), native_subjects=0, reader_replays=0),sort_keys=True))

if __name__ == '__main__': main()
