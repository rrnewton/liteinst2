"""Closed RSEQ report parsing and actual inactive-registration completion."""
import json
from page_selected import need
import page_selected_chain_compare as chain

def unique(pairs):
    out={}
    for k,v in pairs:
        need(k not in out,'duplicate key');out[k]=v
    return out


def decode(b):
    return json.loads(b,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite')))


def reports(stderr,schema):
    lines=stderr.splitlines();rseq=[x for x in lines if x.startswith(b'LI2_RSEQ ')]
    need(len(rseq)==1 and all(len(x)+1<=4096 for x in lines),'one bounded actual RSEQ report')
    at=lines.index(rseq[0]);need(at in (1,2),'original report order')
    loader,repeat,run,c=chain.reports(b'\n'.join(lines[:at]+lines[at+1:])+b'\n')
    r=decode(rseq[0][len(b'LI2_RSEQ '):]);keys=set(schema['scalar_keys'])|{'scope'}|set(schema['arrays'])
    need(type(r)is dict and set(r)==keys and r['version']==1 and r['scope']==schema['scope'] and r['maps_profile']==1,'exact RSEQ schema/profile')
    for k in schema['scalar_keys']:
        need(type(r[k])is int and 0<=r[k]<1<<64,'unsigned scalar')
    for k,names in schema['arrays'].items():
        need(type(r[k])is list and len(r[k])==len(names) and all(type(x)is int and 0<=x<1<<64 for x in r[k]),'exact unsigned array '+k)
    need(all(r[k]==loader[k]==c[k]==run[k] for k in ('status','failure_code','detail_abs','detail_negative')),'same actual outcome in all reports')
    return loader,repeat,run,c,r


def observed_data(v, owner, pid):
    address,page,allocation,generation,offset,got_pid,tid = v[:7]
    need(address == owner[9] and page == owner[10] and address & 31 == 0 and
         page == address & ~4095 and address <= (1 << 64)-32 and allocation > 0 and generation > 0 and
         got_pid == tid == pid and v[7:12] == [1,1,0,0,0],
         'actual complete owned rseq page and singleton identity')
    need(v[12] < 1 << 31 and v[13:18] == [0,0,0,0,0] and v[18] > 0 and v[19] > 0 and
         v[20:23] == [1,1,1] and v[23] > 0 and v[24] == 0 and v[25] > 0 and
         v[26:28] == [0,1],
         'complete actual maps acquisition/read/close prefix')
    return [1,allocation,generation,offset]


def completed(loader, repeat, run, c, r, pid):
    # Preserve all existing cache, chain, source, release and frame predicates.
    chain.completed(loader, repeat, run, c)
    owner, counts, t, args = r['owner'], r['counts'], r['transaction'], r['args']
    initialized, registered, held, phase = owner[:4]
    need(initialized == 1 and registered in (0,1) and held == registered and
         phase == (3 if registered else 0) and owner[4:7] == [0,0,0] and
         owner[7] == owner[8] == pid > 0,
         'real terminal IDLE or ACTIVE registration, no synthetic unregister')
    calls, registrations, unregistrations, errors = counts[:4]
    need(registrations == unregistrations+registered and owner[13] == registrations and
         calls == registrations+unregistrations+errors == loader['rseq'],
         'every actual rseq return accounted, including retained active registration')
    if registrations:
        need(r['identity'][0] == 1 and r['identity'][1] > 0 and r['identity'][2] > 0 and
             owner[9] > 0 and owner[9] & 31 == 0 and owner[10] == owner[9] & ~4095 and
             owner[9] <= (1 << 64)-32 and owner[11] == 32 and owner[12] < 1 << 32 and
             r['tls'][:6] == [1,1,0,0,0,0],
             'successful registration has actual mapping identity and successful TLS observations')
    else:
        need(r['identity'] == [0]*4 and r['tls'] == [0]*8,
             'no registration means no invented mapping or TLS success')
    if not calls:
        need(owner[9:14] == [0]*5 and t == [0]*8 and args == [0]*6 and
             r['before'] == r['after'] == [0]*28 and counts == [0]*9 and
             r['last'] == [0]*5 and r['footprint'] == [0]*8,
             'zero calls retain only initialized singleton identity')
        return
    need(t[:3] == [1,1,1] and t[3] in (0,1) and t[5] in (0,1) and
         t[6] in (0,1) and t[7] == 0 and (args[2] & 0xffffffff) in (0,1),
         'last actual transaction issued and returned with scoped flags')
    prior, flags = t[3], args[2] & 0xffffffff
    if t[4]:
        need(t[5] == 1 and 1 <= t[4] <= 4095 and errors > 0 and registered == prior,
             'actual kernel error preserves prior registration')
    else:
        need(t[5] == 0 and registered == int(not flags) and prior == flags and
             args[0] == owner[9] and args[1] & 0xffffffff == owner[11] and
             args[3] & 0xffffffff == owner[12], 'actual successful register/unregister tuple')
    if not prior and not flags:
        need(t[6:] == [1,0] and args[0] == owner[9] and args[1] & 0xffffffff == 32 and
             args[3] & 0xffffffff == owner[12], 'fresh registration observed actual zero input before issue')
        identity = observed_data(r['before'], owner, pid)
        if not t[4]:
            need(observed_data(r['after'], owner, pid) == identity == r['identity'] and
                 r['before'][:7] == r['after'][:7], 'same actual registration mapping before and after kernel')
            need(r['after'][26:] == [0,1] and r['after'][23] > r['before'][23] and
                 r['after'][25] > r['before'][25] and r['after'][24] == r['before'][24],
                 'actual raw registration invalidated maps before the fresh post-kernel query')
        else:
            need(r['after'] == [0]*28, 'failed raw registration has no invented post-registration query')
    else:
        need(t[6:] == [0,0] and r['before'] == r['after'] == [0]*28,
             'existing-registration or unregister transaction has no fabricated fresh mapping observation')


