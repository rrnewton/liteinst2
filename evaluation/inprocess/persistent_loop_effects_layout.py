"""Exact independent policy12 storage expectations, checked against actual DWARF.

No bridge execution. Header append +8; two completion members add16; three
completion cells add48. The 64-aligned ingress absorbs earlier +24 as +64.
The nine-cell chooser state is260544; final PF counters stay explicit.
"""
import re
import shutil
from maps_view import need, ENV

def domain_protected_extents(builder, bridge, symbols, pin, run, state):
    """Derive actual group storage from DWARF; never execute the bridge."""
    gdb = pin(shutil.which('gdb', path=ENV['PATH']))
    gdb_environment = dict(builder.environment, MALLOC_ARENA_MAX='1')
    _, out, err = run('persistent-group-gdb-version', [gdb, '--version'], profile='inspect', env=gdb_environment)
    need(out and not err, 'actual GDB tool identity')
    expression = ('printf "LI2_PG_EXTENTS %llu %llu %llu %llu %llu %llu %llu %llu\\n", '
                  '(unsigned long long)sizeof(struct pe_payload), (unsigned long long)sizeof(pe), '
                  '(unsigned long long)sizeof(struct li2_pg_compact), '
                  '(unsigned long long)sizeof(struct li2_pg_plan), '
                  '(unsigned long long)sizeof(((struct li2_pg_compact*)0)->image), '
                  '(unsigned long long)sizeof(((struct li2_pg_compact*)0)->stub_image), '
                  '(unsigned long long)sizeof(struct li2_mg_plan), '
                  '(unsigned long long)sizeof(struct li2_pg_layout)')
    _, out, err = run('persistent-group-protected-extents', [gdb, '-nx', '-nh', '-batch',
                     '-iex', 'set auto-load off', '-iex', 'set debuginfod enabled off',
                     '-iex', 'set index-cache enabled off', '-iex', 'maintenance set worker-threads 1',
                     '-ex', 'file '+str(bridge), '-ex', expression], profile='inspect', env=gdb_environment)
    match = re.fullmatch(rb'LI2_PG_EXTENTS ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+)\n', out)
    need(not err and match is not None, 'one actual group DWARF storage-size result')
    payload, owner, compact, full, images, stubs, recovery, layout = map(int, match.groups())
    rounded = (payload+4095) & ~4095
    need((compact, full, images, stubs, recovery, layout) == (353608, 981320, 65536, 4096, 6488, 48) and
         compact < payload <= rounded == 89*4096 and payload == 362664 and owner == 4498752,
         'actual typed group primary, full reconstruction, two images and stub storage')
    rows = [line.split() for line in symbols.splitlines() if line.split()[-1:] == [b'pe']]
    need(len(rows) == 1 and len(rows[0]) == 4 and rows[0][2] in (b'b', b'B') and
         int(rows[0][1], 16) == owner, 'actual ELF group owner equals DWARF extent')
    state['protected_extents'] = dict(payload=payload, proof_rounded=rounded, owner=owner,
        compact=compact, full=full, images=images, stubs=stubs, code=images+stubs,
        code_extents_per_member=3, code_pages_per_member=17, domain_code_extents_max=6, domain_code_pages_max=34, slots=4096, spill=4096, allocation=19*4096,
        recovery=recovery, layout=layout)

def retained_extents(builder, bridge, symbols, pin, run, state):
    """Actual two-slot authority/storage, with one independent ELF owner join."""
    gdb = pin(shutil.which('gdb', path=ENV['PATH']))
    expression = ('printf "LI2_PTR_EXTENTS %llu %llu %llu %llu %llu\\n", '
        '(unsigned long long)sizeof(struct li2_ptr_slot_ref), '
        '(unsigned long long)sizeof(struct li2_ptr_slot), '
        '(unsigned long long)sizeof(pe.retained), '
        '(unsigned long long)sizeof(pe.retained)/sizeof(pe.retained[0]), '
        '(unsigned long long)sizeof(pe.retained[0].publication)')
    _, out, err = run('persistent-retained-two-extents', [gdb, '-nx', '-nh', '-batch',
        '-iex', 'set auto-load off', '-iex', 'set debuginfod enabled off',
        '-iex', 'set index-cache enabled off', '-iex', 'maintenance set worker-threads 1',
        '-ex', 'file '+str(bridge), '-ex', expression], profile='inspect',
        env=dict(builder.environment, MALLOC_ARENA_MAX='1'))
    match = re.fullmatch(rb'LI2_PTR_EXTENTS ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+)\n', out)
    need(not err and match is not None, 'exact actual retained slot DWARF result')
    sizes = tuple(map(int, match.groups()))
    need(sizes == (24,398136,796272,2,362664) and
         state['protected_extents']['payload'] == sizes[-1] and
         state['protected_extents']['owner'] > sizes[2],
         'two complete actual active-domain retained authorities and immutable publication mirrors')
    state['retained_extents'] = dict(zip(('reference','slot','slots','count','publication'),sizes))

def subentry_extents(builder, bridge, pin, run, state):
    """Actual entry custody and historical domain storage from emitted DWARF."""
    gdb = pin(shutil.which('gdb', path=ENV['PATH']))
    expressions = (
        'sizeof(struct li2_pgs_target)', 'sizeof(struct li2_pgs_entry)',
        'sizeof(pe.entry)', 'sizeof(pe.domain.work.view.entry)',
        'sizeof(pe.domain.completion[0].domain_source.entry)',
        'sizeof(pe.domain)', 'sizeof(pe.domain.work)',
        'sizeof(pe.domain.completion[0])',
        'sizeof(pe.domain.completion)/sizeof(pe.domain.completion[0])',
        '(char*)&pe.next_serial-(char*)&pe.entry')
    expression = ('printf "LI2_PGS_EXTENTS '+' '.join(['%llu']*len(expressions))+'\\n", '+
                  ', '.join('(unsigned long long)('+value+')' for value in expressions))
    _, out, err = run('persistent-subentry-extents', [gdb, '-nx', '-nh', '-batch',
        '-iex', 'set auto-load off', '-iex', 'set debuginfod enabled off',
        '-iex', 'set index-cache enabled off', '-iex', 'maintenance set worker-threads 1',
        '-ex', 'file '+str(bridge), '-ex', expression], profile='inspect',
        env=dict(builder.environment, MALLOC_ARENA_MAX='1'))
    match = re.fullmatch(b'LI2_PGS_EXTENTS '+b' '.join([rb'([0-9]+)']*len(expressions))+b'\n', out)
    need(not err and match is not None, 'exact actual entry and domain DWARF extents')
    sizes = tuple(map(int, match.groups()))
    need(sizes == (64,504,504,504,504,225880,11312,71384,3,544) and
         state['protected_extents']['owner'] == ((4272808+225880+16+63)&~63),
         'entry and additional peer custody retained by value in all three completion cells')
    state['subentry_extents'] = dict(zip(('target','entry','owner_entry','live_entry',
        'completed_entry','domain','work','completion','receipts','owner_entry_and_counts'),sizes))

def cross_pair_extents(builder, bridge, symbols, pin, run, state):
    """Require the complete new peer lease and its actual protected storage."""
    gdb = pin(shutil.which('gdb', path=ENV['PATH']))
    expressions = (
        'sizeof(struct li2_pgx_check)', 'sizeof(struct li2_pgx_source)',
        'sizeof(struct li2_pgd_source_progress)', 'sizeof(pg_source)',
        'sizeof(pg_source.domain)', 'sizeof(pg_source.domain_previous)',
        'sizeof(pg_source.peer_candidate)', 'sizeof(pg_source.peer_original)',
        'sizeof(pe.domain.completion[0].domain_source.peer)',
        '(char*)&pe.domain-(char*)&pe',
        '(char*)&pg_source.domain.peer-(char*)&pg_source.domain',
        '(char*)&pg_source.domain.entry-(char*)&pg_source.domain')
    expression = ('printf "LI2_PGX_EXTENTS '+' '.join(['%llu']*len(expressions))+'\\n", '+
                  ', '.join('(unsigned long long)('+value+')' for value in expressions))
    _, out, err = run('persistent-cross-pair-extents', [gdb, '-nx', '-nh', '-batch',
        '-iex', 'set auto-load off', '-iex', 'set debuginfod enabled off',
        '-iex', 'set index-cache enabled off', '-iex', 'maintenance set worker-threads 1',
        '-ex', 'file '+str(bridge), '-ex', expression], profile='inspect',
        env=dict(builder.environment, MALLOC_ARENA_MAX='1'))
    match = re.fullmatch(b'LI2_PGX_EXTENTS '+b' '.join([rb'([0-9]+)']*len(expressions))+b'\n', out)
    need(not err and match is not None, 'exact actual cross-pair source and storage DWARF result')
    sizes = tuple(map(int, match.groups()))
    need(sizes == (672,20056,22688,89736,22688,22688,20056,128,20056,4272808,2128,22184),
         'complete cross-pair source, four checkpoints and saved peer storage')
    # The two separate PF refusal counters follow the domain; preserve all16
    # bytes before independently rounding the complete owner to64.
    need(state['subentry_extents']['domain'] == 225880 and
         state['subentry_extents']['completion'] == 71384 and
         state['subentry_extents']['receipts'] == 3 and
         state['protected_extents']['owner'] == ((sizes[9]+225880+16+63)&~63),
         'all three complete peer receipts and exact final owner alignment')
    rows = [line.split() for line in symbols.splitlines() if line.split()[-1:] == [b'pg_source']]
    need(len(rows) == 1 and len(rows[0]) == 4 and rows[0][2] in (b'b',b'B') and
         int(rows[0][0],16) > 0 and int(rows[0][1],16) == sizes[3],
         'actual protected source-owner ELF storage equals its full DWARF extent')
    state['cross_pair_extents'] = dict(zip(('checkpoint','peer','domain_source','source_owner',
        'current_domain','previous_domain','candidate_peer','original_pages','completed_peer',
        'owner_domain_offset','peer_offset','entry_offset'),sizes))

def direct_frontier_extents(builder,bridge,pin,run,state):
    """Exact new typed direct rows and by-value completion append."""
    gdb=pin(shutil.which('gdb',path=ENV['PATH']))
    expressions=('sizeof(struct li2_dd_descriptor)','sizeof(struct li2_dd_record)',
        'sizeof(struct li2_dd_plan)','sizeof(struct li2_dd_recovered)',
        'sizeof(struct pda_direct_exit)','sizeof(pe.domain.completion[0].direct_exit)',
        '(char*)&pe.domain.completion[0].direct_exit-(char*)&pe.domain.completion[0]')
    expression=('printf "LI2_DD_EXTENTS '+' '.join(['%llu']*len(expressions))+'\\n", '+
        ', '.join('(unsigned long long)('+v+')'for v in expressions))
    _,out,err=run('persistent-direct-frontier-extents',[gdb,'-nx','-nh','-batch',
        '-iex','set auto-load off','-iex','set debuginfod enabled off',
        '-iex','set index-cache enabled off','-iex','maintenance set worker-threads 1',
        '-ex','file '+str(bridge),'-ex',expression],profile='inspect',
        env=dict(builder.environment,MALLOC_ARENA_MAX='1'))
    match=re.fullmatch(b'LI2_DD_EXTENTS '+b' '.join([rb'([0-9]+)']*len(expressions))+b'\n',out)
    need(not err and match is not None,'one complete actual direct-frontier DWARF result')
    sizes=tuple(map(int,match.groups()))
    need(sizes==(120,1584,2288,152,528,528,70856) and
         state['subentry_extents']['completion']==sizes[-1]+sizes[-2],
         'exact complete typed descriptors, recovery and appended historical direct-exit custody')
    state['direct_frontier_extents']=dict(zip(('descriptor','record','plan','recovered',
        'exit','saved_exit','exit_offset'),sizes))

def loop_extents(builder, bridge, symbols, pin, run, state):
    """Derive every appended header/scratch field, without executing an inferior."""
    gdb = pin(shutil.which('gdb', path=ENV['PATH']))
    sizes = (
        ('header', 'sizeof(struct pe_header)', 296),
        ('policy_offset', '(char*)&((struct pe_header*)0)->plan_policy-(char*)0', 288),
        ('reserved', 'sizeof(((struct pe_header*)0)->reserved)', 32),
        ('span', 'sizeof(struct li2_span_decoded)', 336),
        ('store', 'sizeof(struct li2_mg_store)', 144),
        ('chooser_node', 'sizeof(struct li2_le_decoded)', 488),
        ('chooser_head', 'sizeof(struct li2_le_head)', 40),
        ('chooser_arm', 'sizeof(struct li2_le_arm)', 16),
        ('chooser_link', 'sizeof(struct li2_le_link)', 16),
        ('chooser_candidate', 'sizeof(struct li2_le_candidate)', 56),
        ('chooser_shape', 'sizeof(struct li2_le_shape)', 5432),
        ('witness', 'sizeof(struct li2_le_witness)', 83320),
        ('counts', 'sizeof(struct plr_counts)', 72),
        ('scratch', 'sizeof(struct plr_state)', 260544),
        ('member_completion', 'sizeof(struct pda_member_completion)', 16904),
    )
    scratch_fields = (('scope',0), ('route',4), ('choice_complete',8), ('counts',16),
        ('choice',88), ('check',83408), ('historical',166728), ('pages',250048),
        ('source',250064), ('direct',258256))
    owner_fields = (('retained',1128), ('candidate',802424), ('ref',1167560),
        ('ingress',1167616), ('cold',1439488), ('compact_rebuild',3402128),
        ('loop',3755736), ('effects',4016280), ('recovery_scratch',4266320), ('domain',4272808),
        ('pf_backward_refused',4498688), ('pf_backward_cancelled',4498696))
    counts = ('chooser_attempts', 'chooser_selected', 'chooser_no_envelope',
        'publications12', 'hits12', 'entries_with12', 'completed_with12',
        'historical_reconstructions', 'actual_entries12')
    rows = list(sizes)+[('effects_counts','sizeof(struct ple_counts)',72),('effects_state','sizeof(struct ple_state)',250040)]
    rows += [('scratch_'+name, '(char*)&pe.loop.'+name+'-(char*)&pe.loop', offset)
             for name,offset in scratch_fields]
    rows += [('owner_'+name, '(char*)&pe.'+name+'-(char*)&pe', offset)
             for name,offset in owner_fields]
    rows += [('counter_'+name, '(char*)&pe.loop.counts.'+name+'-(char*)&pe.loop.counts', i*8)
             for i,name in enumerate(counts)]
    rows += [('effects_'+name,'(char*)&pe.effects.'+name+'-(char*)&pe.effects',offset)for name,offset in (('choice_complete',0),('counts',8),('choice',80),('check',83400),('historical',166720))]
    rows += [('effects_counter_'+name.replace('12','13'),'(char*)&pe.effects.counts.'+name.replace('12','13')+'-(char*)&pe.effects.counts',i*8)for i,name in enumerate(counts)]
    expression = ('printf "LI2_LOOP_EXTENTS '+' '.join(['%llu']*len(rows))+'\\n", '+
        ', '.join('(unsigned long long)('+expr+')' for _,expr,_ in rows))
    _, out, err = run('persistent-loop-extents', [gdb, '-nx', '-nh', '-batch',
        '-iex', 'set auto-load off', '-iex', 'set debuginfod enabled off',
        '-iex', 'set index-cache enabled off', '-iex', 'maintenance set worker-threads 1',
        '-ex', 'file '+str(bridge), '-ex', expression,
        '-ex', "python import gdb; print('LI2_LOOP_ALIGN '+str(gdb.lookup_type('struct li2_pg_epoch').alignof))"], profile='inspect',
        env=dict(builder.environment, MALLOC_ARENA_MAX='1'))
    match = re.fullmatch(b'LI2_LOOP_EXTENTS '+b' '.join([rb'([0-9]+)']*len(rows))+b'\nLI2_LOOP_ALIGN 64\n', out)
    need(not err and match is not None, 'one complete actual loop header/scratch/owner DWARF result')
    observed = tuple(map(int, match.groups()))
    need(observed == tuple(v for _,_,v in rows),
         'whole independent loop witness, nine counters, actual header and complete owner layout')
    # Independent source algebra, not an inference from arbitrary observed sizes.
    need(83320 == 64+8192+128*488+128*56+5432 and
         260544 == 16+9*8+3*83320+16+8192+2288 and
         250040 == 8+72+3*83320 and
         4498752 == ((4272808+225880+16+63)&~63) and
         state['protected_extents']['owner'] == 4498752 and
         state['protected_extents']['proof_rounded'] == 89*4096,
         'unchanged two images/eight boundaries/89 proof pages with explicit new scratch only')
    state['loop_extents'] = dict(zip((name for name,_,_ in rows), observed))
    state['loop_extents']['owner_alignment'] = 64


def protected_extents(builder, bridge, symbols, pin, run, state):
    domain_protected_extents(builder, bridge, symbols, pin, run, state)
    retained_extents(builder, bridge, symbols, pin, run, state)
    subentry_extents(builder, bridge, pin, run, state)
    cross_pair_extents(builder, bridge, symbols, pin, run, state)
    direct_frontier_extents(builder, bridge, pin, run, state)
    loop_extents(builder, bridge, symbols, pin, run, state)
