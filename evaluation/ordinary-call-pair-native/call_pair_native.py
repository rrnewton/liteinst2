"""Strict numeric transcript joins. Actual state, ownership and closure are separate."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
import re

U64=(1 << 64)-1
PROFILE='normal-call-pair-original-rust-v1'
STATUS='CALL_PAIR_ORIGINAL_TRANSCRIPT_VALIDATED'
SEEDS=(1311768467139281696,18364758542526924135)
RECORDS=((b'',1),(b'a',1),(b'a,b,c',3),(b',',2),(b',,',3),(b'a,',2),(b',a',2),
         (b'""',1),(b'"a,b"',1),(b'"a","b"',2),(b'a,"b,c",d',3),(b'"a""b",c',2),
         (b'""""',1),(b'"",""',2),(b'plain,"say ""hi""",,tail',4),(b'"comma,, and ""quote""",last,',3))
HEADER='k,seed,case,scenario,input_len,fields,packed,caller_extent,caller_heads,caller_call,caller_continuation,caller_ret,caller_delta,stack_bytes,parent_extent,parent_heads,parent_edges,parent_returns,parent_visits,parent_ret_offset,child_delta,child_extent,child_heads,child_edges,child_declared_heads,child_declared_edges,child_declared_returns,child_visits,child_ret_offset,comparisons,original_steps,candidate_steps,parent_generation,child_generation,child_sampled,parent_actual_children,parent_sampled_children,child_end_sequence,parent_end_sequence,history_actions,journal_events,target_calls,target_returns,outer_returns,normal_reaps'
COVERAGE='k,scenario,seed,cases,parent_heads,parent_edges,parent_returns,child_heads,child_edges,child_returns,child_declared_heads,child_declared_edges,child_declared_returns'
AUTHORITY='Numeric joins only; full actual state/XSAVE/stack/source/input/journal/Report/history, original-address mapping, physical returns and normal reaps require the authenticated native adapter and final owned closure. No Schedule, K exhaustion, threaded application or performance credit.'


def uint(word):
    assert type(word) is str and re.fullmatch(r'0|[1-9][0-9]{0,19}',word)
    value=int(word); assert value <= U64
    return value


def number(value,lo=0,hi=U64):
    assert type(value) is int and lo <= value <= hi
    return value


def lines(data,cap):
    assert type(data) is bytes and 0 < len(data) <= cap and data.endswith(b'\n')
    assert re.fullmatch(rb'[\x20-\x7e\n]+',data)
    rows=data[:-1].decode('ascii').split('\n'); assert all(rows)
    return rows


def table(data,header,count,cap):
    rows=lines(data,cap); assert rows[0] == header and len(rows) == count+1
    fields=header.split(','); result=[]
    for line in rows[1:]:
        words=line.split(','); assert len(words) == len(fields)
        result.append(dict(zip(fields,map(uint,words))))
    return result


def catalog():
    return [(k,seed,case,scenario) for k in (10,1000) for seed in SEEDS
            for case in range(1,17) for scenario in (1,2,3)]


def body(value,lo,hi):
    assert type(value) is dict
    length=number(value['length'],lo,hi); va=number(value['elf_va'],1)
    assert va+length <= U64
    heads=value['heads']; returns=value['returns']
    assert type(heads) is list and heads and heads == sorted(set(heads)) and heads[0] == 0
    for head in heads: number(head,0,length-1)
    assert all(1 <= b-a <= 15 for a,b in zip(heads,heads[1:]+[length]))
    assert type(returns) is list and 1 <= len(returns) <= 4 and returns == sorted(set(returns))
    assert all(number(r,0,length-1) in heads for r in returns)
    number(value['edges'],len(heads)-len(returns),2*(len(heads)-len(returns)))
    return length,va


def geometry(parent,child,caller):
    pl,pv=body(parent,5,80); cl,cv=body(child,5,256)
    assert pv+pl <= cv or cv+cl <= pv
    assert len({v//4096 for v in (pv,pv+pl-1,cv,cv+cl-1)}) <= 2
    assert parent['returns'] == [pl-1] and parent['edges'] == len(parent['heads'])-1
    pc=number(parent['call_offset'],1,pl-2); continuation=number(parent['continuation_offset'],1,pl-1)
    assert pc in parent['heads'] and continuation == pc+5
    assert parent['heads'][parent['heads'].index(pc)+1] == continuation
    assert number(parent['child_delta'],16,64) % 16 == 0
    assert parent['callee_entry'] == cv
    raw=parent['body_hex']; assert type(raw) is str and re.fullmatch('[0-9a-f]{'+str(pl*2)+'}',raw)
    code=bytes.fromhex(raw); assert code[-1] == 0xc3 and code[pc] == 0xe8
    assert pv+continuation+int.from_bytes(code[pc+1:pc+5],'little',signed=True) == cv
    assert type(caller) is dict
    length=number(caller['length'],1,256); va=number(caller['elf_va'],1); assert va+length <= U64
    h=caller['heads']; assert type(h) is list and h and h == sorted(set(h)) and h[0] == 0
    for x in h: number(x,0,length-1)
    assert all(1 <= b-a <= 15 for a,b in zip(h,h[1:]+[length]))
    call=number(caller['call_offset'],0,length-1); cont=number(caller['continuation_offset'],1,length-1)
    assert call in h and h[h.index(call)+1] == cont and 2 <= cont-call <= 3
    assert caller['outer_ret_offset'] == h[-1] == length-1 and call < cont < length-1
    d=number(caller['subject_rsp_delta'],16,256); assert d % 16 == 0
    low=number(caller['lowest_stack'],d-8,256); assert low % 8 == 0
    raw=caller['body_hex']; assert type(raw) is str and re.fullmatch('[0-9a-f]{'+str(length*2)+'}',raw)
    code=bytes.fromhex(raw); assert code[-1] == 0xc3
    op=code[call:cont]; assert len(op) in (2,3)
    if len(op) == 3: assert 0x40 <= op[0] <= 0x4f; op=op[1:]
    assert op[0] == 0xff and 0xd0 <= op[1] <= 0xd7
    stack=max(low,d+parent['child_delta']+128)+8
    assert 0 < stack <= 456
    return stack


def terminal(comparisons):
    return (f'native-call-pair-state:profile={PROFILE}:required=192:pairs=192:children=384:'
        f'comparisons={comparisons}:coverage-groups=12:k-values=2:seeds=2:scenarios=3:'
        'target-calls=768:target-returns=768:real-outer-ret=384:normal-reaps=384:scope=original-caller-nested-body:complete')


def check(pairs,coverage,stdout,stderr,*,parent,child,caller):
    assert type(stderr) is bytes and stderr == b''
    stack=geometry(parent,child,caller)
    rows=table(pairs,HEADER,192,524288); covered=table(coverage,COVERAGE,12,16384)
    for r,key in zip(rows,catalog()):
        assert tuple(r[n] for n in ('k','seed','case','scenario')) == key
        k,seed,case,scenario=key; data,fields=RECORDS[case-1]
        assert (r['input_len'],r['fields'],r['packed']) == (len(data),fields,(len(data) << 32)|fields)
        assert (r['caller_extent'],r['caller_heads']) == (caller['length'],len(caller['heads']))
        for column,field in [('caller_call','call_offset'),('caller_continuation','continuation_offset'),('caller_ret','outer_ret_offset'),('caller_delta','subject_rsp_delta')]:
            assert r[column] == caller[field]
        assert r['stack_bytes'] == stack
        assert (r['parent_extent'],r['parent_heads'],r['parent_edges'],r['parent_returns'],r['parent_visits'],r['parent_ret_offset']) == (parent['length'],len(parent['heads']),parent['edges'],1,len(parent['heads']),parent['returns'][0])
        assert r['child_delta'] == parent['child_delta'] and r['child_extent'] == child['length']
        assert (r['child_declared_heads'],r['child_declared_edges'],r['child_declared_returns']) == (len(child['heads']),child['edges'],len(child['returns']))
        assert r['child_ret_offset'] in child['returns']
        assert 2 <= r['child_heads'] <= min(r['child_visits'],len(child['heads']))
        assert r['child_heads']-1 <= r['child_edges'] <= min(r['child_visits']-1,child['edges'])
        assert r['comparisons'] == len(caller['heads'])+r['parent_visits']+r['child_visits']+1
        assert r['comparisons'] <= r['original_steps'] <= 20000
        assert r['comparisons'] <= r['candidate_steps'] <= 20000
        assert r['parent_generation'] > 0
        sampled=int(scenario != 3)
        assert r['child_sampled'] == r['parent_sampled_children'] == sampled
        assert r['parent_actual_children'] == 1 and r['child_end_sequence'] == sampled and r['parent_end_sequence'] == 1+sampled
        if scenario == 1: assert r['child_generation'] == r['parent_generation']
        elif scenario == 2: assert r['child_generation'] > 0 and r['child_generation'] != r['parent_generation']
        else: assert r['child_generation'] == 0
        assert r['history_actions'] == (3 if scenario == 2 else 2) and r['journal_events'] == 4
        assert tuple(r[n] for n in ('target_calls','target_returns','outer_returns','normal_reaps')) == (4,4,2,2)
    keys=[(k,scenario,seed) for k in (10,1000) for scenario in (1,2,3) for seed in SEEDS]
    for c,key in zip(covered,keys):
        k,scenario,seed=key; group=[r for r in rows if (r['k'],r['scenario'],r['seed']) == key]
        assert len(group) == 16 and tuple(c[n] for n in ('k','scenario','seed','cases')) == (*key,16)
        assert tuple(c[n] for n in ('parent_heads','parent_edges','parent_returns')) == (len(parent['heads']),parent['edges'],1)
        assert {r['child_ret_offset'] for r in group} == set(child['returns'])
        assert c['child_returns'] == c['child_declared_returns'] == len(child['returns'])
        for suffix in ('heads','edges'):
            declared=len(child['heads']) if suffix == 'heads' else child['edges']
            counts=[r['child_'+suffix] for r in group]
            assert c['child_declared_'+suffix] == declared
            assert max(counts) <= c['child_'+suffix] <= min(sum(counts),declared)
    comparisons=sum(r['comparisons'] for r in rows); assert 0 < comparisons <= U64
    assert lines(stdout,1024) == [terminal(comparisons)]
    return dict(status=STATUS,profile=PROFILE,required=192,pairs=192,children=384,comparisons=comparisons,groups=12,
        rows=rows,coverage=covered,pairs_table=pairs,coverage_table=coverage,stdout=stdout,authority=AUTHORITY)
