"""One parent-only stopped prefix snapshot; no target calls or ptrace owner.

The bytes are stable while the single target task is stopped, but may describe
the middle of a multi-store owner transition. They are not a terminal receipt,
admission authority, scan-iteration count, or matched timing measurement.
"""
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import time

from persistent_dynamic_sample import ENV, Sampler, bounded, one_symbol

CHECKPOINT_SECONDS = 5
MAX_SCALAR_BYTES = 32768
MAX_JSON_BYTES = 512 << 10
SCOPE = ('One actual single-task SIGSTOP/read/SIGCONT prefix observation. '
         'May stop inside an owner transition; no terminal conservation, '
         'completion, authority, matched timing, or inferred scan iterations.')


def need(ok, why):
    if not ok:
        raise ValueError(why)


def save(path, value):
    data = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()+b'\n'
    need(len(data) <= MAX_JSON_BYTES, 'bounded complete snapshot metadata')
    with Path(path).open('xb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    return dict(file=Path(path).name, bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def fields(node_count):
    """Explicit scalar roster; no whole pe, plan, capsule or proof copies."""
    need(type(node_count) is int and node_count in (12, 128), 'literal arena node count')
    out = {}
    def add(prefix, names, size=8):
        for name in names.split():
            key = prefix+'.'+name if prefix else name
            need(key not in out, 'distinct snapshot scalar')
            out[key] = size
    add('pe', 'next_serial next_generation offers publications hits cold_attempts cancelled retirements '
        'permit_claims entries completed unexpected subentry_selections subentry_hits subentry_entries subentry_completed')
    add('pe', 'initialized registered selected_slot selected_bank resuming warm consumed redirected '
        'close_started close_complete prepare_started prepare_complete build_started build_returned '
        'exit_seen recovery_started recovery_complete cleanup_started cleanup_complete', 4)
    add('pe.p', 'serial generation publication')
    add('pe.p', 'phase first_error completion_permit', 4)
    add('pe.domain.work', 'bound completion aborting', 4)
    add('pe.domain.work.view', 'count', 4)
    add('pe.cache8', 'cold_calls compact_build_calls compact_validate_calls attach_attempts accepted source_declines')
    for name in ('bound_by_count', 'entered_by_count', 'completed_by_count'):
        for index in range(9):
            add('pe.cache8', name+'['+str(index)+']')
    add('pe.rx', 'entries retained_entries quiet_releases direct_offers direct_steps code_opens code_revokes '
        'code_writes code_syncs metadata_permissions metadata_syncs terminal_attempts terminal_closed '
        'transit_offers transit_steps transit_declined transit_limit')
    add('lta_writer.value', 'initialized poisoned topology_epoch next_binding detached rebound rebound_peers '
        'cold_nodes evicted epoch_invalidations stale_refusals physical_checks')
    add('pe.arena', 'next_binding')
    add('pe.arena', 'initialized rebind_mask', 4)
    for index in range(8):
        prefix = 'pe.arena.binding['+str(index)+']'
        add(prefix, 'generation'); add(prefix, 'node reserved', 4)
    for index in range(node_count):
        suffix = '['+str(index)+']'
        prefix = 'pe.arena.node'+suffix
        add(prefix, 'identity.generation generation.build_serial publication.source.entry last_completed')
        add(prefix, 'identity.index generation.installed claim.valid', 4)
        add('lta_writer.value', 'node'+suffix)
        add('lta_writer.value.dormant'+suffix,
            'issued closed reusable node_epoch prepared_serial prepared_binding')
    add('lgd_counts', 'issues hits topology_hits topology_full topology_differential common_hits common_full '
        'common_differential history_fallbacks directory_writes directory_queries disagreements '
        'common_lhc_hits common_revalidated_hits')
    add('lhc.counts', 'decisions hits misses full_calls differential_checks disagreements issues invalidations '
        'abort_invalidations errors restored_bytes')
    add('sbc_observed', 'decisions hits misses full_scans full_scan_errors disagreements full_scan_bytes '
        'issues invalidations abort_invalidations live_queries live_query_errors postseal_bytes')
    add('mv', 'queries hits refreshes updates invalidations comparisons mismatches unexplained stack_probes')
    add('mv', 'enabled differential poisoned reserved', 4)
    add('maps_stats', 'fresh_calls acquisitions reuses invalidations handler_id mutation_epoch')
    add('maps_stats', 'active valid poisoned reserved', 4)
    add('selected_linked_epoch', 'events')
    for index in range(5):
        add('selected_linked_epoch', 'signals['+str(index)+']')
    add('', 'pe_busy pe_active pe_failing pe_closing pe_decoding pe_terminal_ingress handling '
        'selected_pending_route selected_step_pending', 4)
    need(len(out) < 4096 and sum(out.values()) < MAX_SCALAR_BYTES, 'small fixed scalar snapshot')
    return out


def layout_script(node_count):
    roster = fields(node_count)
    # Address/sizeof/type expressions only: GDB loads the file, never an inferior.
    return ("import gdb,json\nroster="+repr(roster)+"\nnode_count="+str(node_count)+r'''
if gdb.selected_inferior().pid != 0:
    raise ValueError('file-only layout has no inferior')
roots={}
rows={}
for name,width in roster.items():
    root=name.split('.',1)[0]
    if root not in roots:
        symbol=gdb.lookup_static_symbol(root)
        if symbol is None or not symbol.is_variable or symbol.symtab is None:
            raise ValueError('one actual static object '+root)
        roots[root]={'address':int(symbol.value().address),'bytes':int(symbol.type.sizeof)}
    value=gdb.parse_and_eval('&'+name)
    kind=value.type.target().strip_typedefs()
    if kind.code not in (gdb.TYPE_CODE_INT,gdb.TYPE_CODE_ENUM,gdb.TYPE_CODE_BOOL) or int(kind.sizeof)!=width:
        raise ValueError('exact whole scalar type '+name)
    rows[name]={'address':int(value),'bytes':int(kind.sizeof),'root':root}
print(json.dumps({'version':1,'node_count':node_count,'inferior_started':False,
    'pointer_bytes':int(gdb.lookup_type('void').pointer().sizeof),
    'roots':roots,'fields':rows},sort_keys=True,separators=(',',':')))
''')


class Observer(Sampler):
    def __init__(self, bridge, layout, directory, cpu, node_count):
        self.node_count = node_count
        self.called = False
        super().__init__(Path(bridge), layout, {}, Path(directory), cpu)

    def field_table(self):
        value = self.layout; roster = fields(self.node_count)
        need(type(value) is dict and set(value) == {'version', 'node_count', 'inferior_started',
             'pointer_bytes', 'roots', 'fields'} and value['version'] == 1 and
             value['node_count'] == self.node_count and value['inferior_started'] is False and
             value['pointer_bytes'] == 8 and type(value['roots']) is dict and
             type(value['fields']) is dict and set(value['fields']) == set(roster), 'complete file-only layout')
        roots = {name.split('.', 1)[0] for name in roster}
        need(set(value['roots']) == roots, 'exact emitted owner population')
        for name, item in value['roots'].items():
            emitted = one_symbol(self.symbols, name, 1)
            need(set(item) == {'address', 'bytes'} and
                 all(type(x) is int and x > 0 for x in item.values()) and
                 (item['address'], item['bytes']) == (emitted['address'], emitted['bytes']) and
                 sum(p['flags'] == 6 and p['vaddr'] <= item['address'] < item['address']+item['bytes'] <=
                     p['vaddr']+p['memsz'] for p in self.loads) == 1,
                 'whole DWARF owner agrees with unique ELF object and writable LOAD '+name)
        result = []
        for name, width in roster.items():
            item = value['fields'][name]; root = name.split('.', 1)[0]; owner = value['roots'][root]
            need(type(item) is dict and set(item) == {'address', 'bytes', 'root'} and
                 type(item['address']) is int and type(item['bytes']) is int and
                 item['root'] == root and item['bytes'] == width and
                 owner['address'] <= item['address'] < item['address']+width <= owner['address']+owner['bytes'] and
                 item['address'] % width == 0, 'aligned complete scalar in actual owner '+name)
            result.append((name, item['address'], width))
        need(len({(a, n) for _, a, n in result}) == len(result), 'distinct physical snapshot scalars')
        return result

    @staticmethod
    def live(pidfd):
        need(not select.select([pidfd], [], [], 0)[0], 'original pidfd is still live and unreaped')

    def stopped(self, pid, pidfd, starttime):
        self.live(pidfd)
        tasks = list(Path('/proc/'+str(pid)+'/task').iterdir())
        need([p.name for p in tasks] == [str(pid)], 'one actual target task')
        raw = bounded('/proc/'+str(pid)+'/status', 16384)
        status = dict(line.split(':', 1) for line in raw.decode('ascii').splitlines() if ':' in line)
        need(status['State'].split()[0] == 'T' and int(status['Pid']) == pid and
             int(status['Tgid']) == pid and int(status['Threads']) == 1 and int(status['TracerPid']) == 0,
             'actual group-stopped single task without a ptrace owner')
        current = self.proc_stat(pid)
        need(current['state'] == 'T' and current['starttime'] == starttime and
             os.sched_getaffinity(pid) == {self.cpu}, 'same stopped child identity and CPU')
        return current

    def __call__(self, *, pid, pidfd, row, deadline, release_ns):
        need(not self.called and row['pid'] == pid and time.monotonic_ns() >=
             release_ns+CHECKPOINT_SECONDS*1_000_000_000, 'one fixed post-release snapshot')
        self.called = True
        observation = dict(version=1, status='failed', scope=SCOPE, node_count=self.node_count,
            checkpoint_seconds=CHECKPOINT_SECONDS, stopped=False, resumed=False, single_task=False,
            pid=pid, release_ns=release_ns, begin_ns=time.monotonic_ns(), error=None)
        stop_sent = False
        try:
            self.live(pidfd)
            before = self.proc_stat(pid)
            need(before['state'] not in ('T', 't', 'Z', 'X') and
                 os.sched_getaffinity(pid) == {self.cpu}, 'live unstopped original target before signal')
            stop_deadline = min(deadline, time.monotonic()+2)
            signal.pidfd_send_signal(pidfd, signal.SIGSTOP); stop_sent = True
            while True:
                state = os.waitid(os.P_PIDFD, pidfd, os.WSTOPPED | os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if state is not None:
                    need(state.si_pid == pid and state.si_code == os.CLD_STOPPED and
                         state.si_status == signal.SIGSTOP, 'actual SIGSTOP notification for retained child')
                    break
                left = stop_deadline-time.monotonic()
                need(left > 0 and not select.select([pidfd], [], [], min(.01, left))[0],
                     'bounded actual target stop, not exit')
            stopped = self.stopped(pid, pidfd, before['starttime'])
            observation.update(stopped=True, single_task=True, stop_ns=time.monotonic_ns(),
                wait_status=dict(pid=state.si_pid, code=state.si_code, status=state.si_status), proc_before=before)
            raw, maps = self.maps(pid)
            with (self.out/'target.maps').open('xb') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            base, own = self.locate(maps)
            fd = os.open('/proc/'+str(pid)+'/mem', os.O_RDONLY | os.O_CLOEXEC)
            try:
                need(self.read(fd, base, 64) == self.image[:64] and
                     self.read(fd, base+self.header[0], self.header[1]-self.header[0]) ==
                     self.image[self.header[0]:self.header[1]], 'live ELF header and complete program headers')
                rx = []
                for load in self.loads:
                    if not load['flags'] & 1:
                        continue
                    h = hashlib.sha256()
                    for offset in range(0, load['filesz'], 1 << 20):
                        count = min(1 << 20, load['filesz']-offset)
                        value = self.read(fd, base+load['vaddr']+offset, count)
                        need(value == self.image[load['offset']+offset:load['offset']+offset+count],
                             'whole actual RX load equals exact authenticated bridge')
                        h.update(value)
                    rx.append(dict(vaddr=load['vaddr'], bytes=load['filesz'], sha256=h.hexdigest()))
                need(rx, 'at least one complete RX identity')
                first = self.values(fd, base, maps); second = self.values(fd, base, maps)
                need(first == second, 'two whole scalar reads agree while stopped')
            finally:
                os.close(fd)
            after = self.stopped(pid, pidfd, before['starttime'])
            need(stopped['utime'] == after['utime'] and stopped['stime'] == after['stime'] and
                 time.monotonic() < deadline, 'no target execution during bounded scalar capture')
            observation.update(values=second, proc_stopped=stopped, proc_after=after, base=base,
                maps_sha256=hashlib.sha256(raw).hexdigest(), bridge_mappings=own, rx=rx,
                projection=self.projection, scalar_bytes=sum(n for _, _, n in self.fields),
                field_count=len(self.fields), end_read_ns=time.monotonic_ns())
        except BaseException as exc:
            observation['error'] = type(exc).__name__+': '+str(exc)
            raise
        finally:
            try:
                if stop_sent:
                    self.live(pidfd)
                    signal.pidfd_send_signal(pidfd, signal.SIGCONT)
                    observation['continue_ns'] = time.monotonic_ns()
                    continue_deadline = min(deadline, time.monotonic()+2)
                    while True:
                        continued = os.waitid(os.P_PIDFD, pidfd,
                            os.WCONTINUED | os.WEXITED | os.WNOHANG | os.WNOWAIT)
                        if continued is not None:
                            need(continued.si_pid == pid and continued.si_code == os.CLD_CONTINUED and
                                 continued.si_status == signal.SIGCONT,
                                 'actual continued notification for the original target')
                            break
                        left = continue_deadline-time.monotonic()
                        need(left > 0 and not select.select([pidfd], [], [], min(.01, left))[0],
                             'bounded actual continuation, not an omitted or exited observation')
                    observation['resumed'] = True
                    observation['continue_wait_status'] = dict(pid=continued.si_pid,
                        code=continued.si_code, status=continued.si_status)
            except BaseException as exc:
                observation['resume_error'] = type(exc).__name__+': '+str(exc)
                raise
            finally:
                if observation['error'] is None and observation['resumed']:
                    observation['status'] = 'observed'
                observation['end_ns'] = time.monotonic_ns()
                artifact = save(self.out/'snapshot.json', observation)
        need(observation['status'] == 'observed' and observation['stopped'] and observation['single_task'],
             'complete mandatory stopped observation')
        return {key: observation[key] for key in ('version', 'status', 'node_count', 'checkpoint_seconds',
            'stopped', 'resumed', 'single_task', 'field_count', 'scalar_bytes')} | dict(artifact=artifact)


def prepare(bridge, directory, cpu, node_count, run, pin):
    """Bind file-only layout with the caller's original bounded observer runner."""
    from page_selected import interpreter
    from persistent_dynamic_profile import observer_libraries
    import persistent_dynamic_sample
    need(type(cpu) is int and os.sched_getaffinity(0) == {cpu}, 'same reserved observer CPU')
    fields(node_count)
    directory = Path(directory); directory.mkdir(mode=0o700)
    pin(__file__); pin(persistent_dynamic_sample.__file__)
    bridge = pin(bridge); gdb = pin('/usr/bin/gdb'); loader = pin(interpreter(gdb))
    listed, errors = run('snapshot-gdb-libraries', [loader, '--list', gdb], ENV)
    need(not errors, 'complete snapshot observer library listing')
    observer_libraries(listed, loader, pin)
    script = directory/'layout.py'
    with script.open('x') as stream:
        stream.write(layout_script(node_count)); stream.flush(); os.fsync(stream.fileno())
    pin(script)
    cache = directory/'gdb-cache'; cache.mkdir(mode=0o700)
    observer_env = dict(ENV, XDG_CACHE_HOME=str(cache.resolve()))
    argv = [gdb, '-q', '-nx', '-batch', '-iex', 'set auto-load off',
        '-iex', 'set debuginfod enabled off', '-iex', 'set index-cache enabled off',
        '-iex', 'maint set worker-threads 1', '--readnow', '--se='+str(bridge), '-x', script]
    data, errors = run('snapshot-layout', argv, observer_env)
    need(not errors and len(data) <= MAX_JSON_BYTES, 'complete bounded file-only DWARF layout')
    layout = json.loads(data)
    save(directory/'layout.json', layout); pin(directory/'layout.json')
    result = Observer(bridge, layout, directory, cpu, node_count)
    pin(directory/'projection.maps')
    return result
