"""Fixed offer-prefix observations; no completed-program or owner authority."""
import struct

from page_selected import need

PROFILE = 'persistent-loop-translation-arena-prefix-capacity128-release-v1'
WIRE = 8952
MAGIC = 0x315846504132494C
IDENTITY = dict(version=1, offers=1024, wire_bytes=WIRE, header_bytes=128,
    counter_words=160, maps_view_bytes=88, maps_bytes=64, phase_words=24,
    binding_bytes=16, node_bytes=56, nodes=128, slots=8,
    checkpoint='actual-offers-before-ingress-or-close', output='stderr',
    expected_exit=125, write_failure_exit=126, ordinary_report=False,
    observation_authority=False, qualification_credit=False)
CORE = ('next_serial next_generation offers publications hits cold_attempts cancelled '
        'retirements permit_claims entries completed unexpected subentry_selections '
        'subentry_hits subentry_entries subentry_completed').split()
REASONS = ('NONE ROOT_UNSUPPORTED SOURCE_INVALID SOURCE_TRUNCATED SOURCE_OVERLAP '
           'OUTSIDE_PAIR HEAD_LIMIT EXIT_LIMIT QUEUE_LIMIT NO_EXIT RIP_REACH BRANCH_REACH '
           'FALLTHROUGH_REACH GUARD_RIP_REACH GUARD_FOLLOW_REACH ROOT_SELECTED '
           'SINGLE_MEMBER LINK_LIMIT').split()
LOOP = ('chooser_attempts chooser_selected chooser_no_envelope publications12 hits12 '
        'entries_with12 completed_with12 historical_reconstructions actual_entries12').split()
EFFECTS = [n.replace('12', '13') for n in LOOP]
CACHE = ('cold_calls compact_build_calls compact_validate_calls attach_attempts accepted source_declines').split()
RX = ('entries retained_entries quiet_releases direct_offers direct_steps code_opens code_revokes '
      'code_writes code_syncs metadata_permissions metadata_syncs terminal_attempts terminal_closed '
      'transit_offers transit_steps transit_declined transit_limit').split()
ARENA = ('initialized poisoned topology_epoch next_binding detached rebound rebound_peers cold_nodes '
         'evicted epoch_invalidations stale_refusals physical_checks').split()
HISTORY = ('decisions hits misses full_calls differential_checks disagreements issues invalidations '
           'abort_invalidations errors restored_bytes').split()
COMMON = ('issues hits topology_hits topology_full topology_differential common_hits common_full '
          'common_differential history_fallbacks directory_writes directory_queries disagreements '
          'common_lhc_hits common_revalidated_hits').split()
BYTE = ('decisions hits misses full_scans full_scan_errors disagreements full_scan_bytes issues '
        'invalidations abort_invalidations live_queries live_query_errors postseal_bytes').split()
INGRESS = ('events segv trap sigill bus other').split()
VIEW = ('queries hits refreshes updates invalidations comparisons mismatches unexplained stack_probes '
        'enabled differential poisoned reserved').split()
MAPS = ('fresh_calls acquisitions reuses invalidations handler_id mutation_epoch active valid poisoned reserved').split()
PHASE = ('initialized registered active busy closing decoding failing resuming redirected warm consumed '
         'phase first_error bound completion aborting selected_slot selected_bank pending_route step_pending '
         'handling arena_initialized rebind_mask reserved').split()
NODE = ('generation root node_epoch issued_epoch reusable installed index claim reserved').split()
PHASE_OFFSET, BINDING_OFFSET, NODE_OFFSET = 1560, 1656, 1784
CONTROL_COUNT = 60


def preparation_identity(holder):
    """Only additional prefix identity; shared preparation keeps all base checks."""
    binding = holder['binding']
    need(binding['profile'] == PROFILE and binding['arena_prefix'] == IDENTITY and
         'arena_observer' not in binding and 'group_descriptor_observer' not in binding and
         'cache8_observer' not in binding,
         'exact terminating prefix identity, distinct from ordinary release and finite observers')
    return PROFILE


def read(data, status):
    need(type(data) is bytes and len(data) == WIRE and type(status) is int and status == 125,
         'one complete prefix binary and exact diagnostic termination')
    h = struct.unpack_from('<16Q', data)
    need(h[:8] == (MAGIC, 1, WIRE, 1024, 128, 8, 160, 24) and
         h[8:10] == (5, 2) and 4096 <= h[10] < 1 << 47 and
         h[11] & 0x10100 == 0x100 and h[12] == 1024 and h[14:] == (1, 0),
         'literal offer1024 hook and actual pre-close TRACE framing')
    offset = 128
    value = {}
    def words(name, fields):
        nonlocal offset
        raw = struct.unpack_from('<'+str(len(fields))+'Q', data, offset)
        offset += 8*len(fields)
        value[name] = dict(zip(fields, raw, strict=True))
    words('core', CORE)
    words('misses', REASONS)
    words('pf', ('backward_refused', 'backward_cancelled'))
    words('loop', LOOP); words('effects', EFFECTS); words('cache', CACHE)
    for name in ('bound', 'entered', 'completed'):
        words(name+'_by_count', [str(i) for i in range(9)])
    for name, fields in (('rx', RX), ('arena', ARENA), ('history', HISTORY),
                         ('common', COMMON), ('byte', BYTE), ('ingress', INGRESS)):
        words(name, fields)
    need(offset == 1408 and value['core']['offers'] == h[12] and
         value['ingress']['events'] == h[13], 'whole160-word counter roster and duplicated actual trigger')
    value['maps_view'] = dict(zip(VIEW, struct.unpack_from('<9Q4I', data, offset), strict=True)); offset += 88
    value['maps'] = dict(zip(MAPS, struct.unpack_from('<6Q4I', data, offset), strict=True)); offset += 64
    need(offset == PHASE_OFFSET, 'exact scalar maps layouts')
    phase = struct.unpack_from('<24I', data, offset); offset += 96
    need(phase[:16] == (1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) and
         phase[16] < 8 and phase[17] < 2 and phase[18:22] == (2, 1, 1, 1) and
         phase[22] < 256 and phase[23] == 0,
         'actual reset/offer checkpoint, before ingress capture, close, claim or build')
    value['phase'] = dict(zip(PHASE, phase, strict=True))
    need(offset == BINDING_OFFSET, 'exact binding start')
    bindings = []
    for i in range(8):
        row = struct.unpack_from('<Q2I', data, offset); offset += 16
        need(row[0] > 0 and row[1] < 128 and row[2] == 0, 'raw binding scalar representation')
        bindings.append(dict(zip(('generation', 'node', 'reserved'), row, strict=True)))
    need(offset == NODE_OFFSET, 'exact node start')
    nodes = []
    for i in range(128):
        row = struct.unpack_from('<5Q4I', data, offset); offset += 56
        need(row[4] in (0, 1) and row[5] in (0, 1) and row[6] < 128 and
             row[7] in (0, 1) and row[8] == 0, 'raw node scalar representation')
        nodes.append(dict(zip(NODE, row, strict=True)))
    need(offset == len(data), 'whole binary consumed without trailing bytes')
    value.update(header=list(h), bindings=bindings, nodes=nodes,
        scope='Raw values at one actual offer before close. No node validity, instruction count, '
              'terminal conservation, program completion, matched timing or performance credit.')
    return value


def controls(data, status):
    read(data, status)
    cases = [('short', data[:-1]), ('trailing', data+b'\0')]
    def changed(name, at, fmt, value):
        b = bytearray(data); struct.pack_into('<'+fmt, b, at, value); cases.append((name, bytes(b)))
    for i in range(16):
        old = struct.unpack_from('<Q', data, 8*i)[0]
        changed('header.'+str(i), 8*i, 'Q', 0 if i == 10 else old ^ (0x100 if i == 11 else 1))
    changed('offer', 128+2*8, 'Q', 1023)
    changed('ingress', 1408-6*8, 'Q', struct.unpack_from('<Q', data, 1408-6*8)[0] ^ 1)
    for i in range(24):
        old = struct.unpack_from('<I', data, PHASE_OFFSET+4*i)[0]
        changed('phase.'+PHASE[i], PHASE_OFFSET+4*i, 'I', {16:8, 17:2, 22:256}.get(i, old ^ 1))
    for i in (0, 7):
        at = BINDING_OFFSET+16*i
        for name, delta, fmt, v in (('generation', 0, 'Q', 0), ('node', 8, 'I', 128), ('reserved', 12, 'I', 1)):
            changed('binding.'+str(i)+'.'+name, at+delta, fmt, v)
    for i in (0, 127):
        at = NODE_OFFSET+56*i
        for name, delta, fmt, v in (('reusable',32,'Q',2), ('installed',40,'I',2),
                                    ('index',44,'I',128), ('claim',48,'I',2), ('reserved',52,'I',1)):
            changed('node.'+str(i)+'.'+name, at+delta, fmt, v)
    refused = []
    for name, b in cases:
        try: read(b, status)
        except (AssertionError, ValueError): refused.append(name)
        else: raise AssertionError('prefix reader accepted '+name)
    need(len(refused) == len(set(refused)) == CONTROL_COUNT,
         'all60 distinct new framing/checkpoint/representation mutations; no old population substituted')
    return refused
