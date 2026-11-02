"""Exact separate effects13 terminal rows; no ABI3 counter-bank claim."""
import json
from page_selected import need
from persistent_loop_counter import LOOP_NAMES
PREFIX=b'LI2_LOOP_RUNTIME '
KEYS=('version','status','failure_code','route','scope','choice_complete')+LOOP_NAMES
EFFECTS_PREFIX=b'LI2_LOOP_EFFECTS '
EFFECTS_NAMES=tuple(k.replace('12','13')for k in LOOP_NAMES)
EFFECTS_KEYS=('version','policy_version','scalar_version','mov_version','status','failure_code',
              'route','scope','choice_complete')+EFFECTS_NAMES

def decode(line):
    def pairs(items):
        need(len(items) == len(dict(items)), 'no duplicate LOOP terminal fields')
        return dict(items)
    need(type(line) is bytes and line.startswith(PREFIX) and len(line) <= 4096 and b'\r' not in line,
         'bounded actual LOOP terminal row')
    value = json.loads(line[len(PREFIX):], object_pairs_hook=pairs)
    need(type(value) is dict and tuple(value) == KEYS and
         all(type(v) is int and 0 <= v < 1 << 64 for v in value.values()) and
         value['version'] == 1 and value['route'] in (0, 11, 12, 13) and
         value['scope'] in (0, 1, 2, 3) and value['choice_complete'] in (0, 1) and
         PREFIX + json.dumps(value, separators=(',', ':'), allow_nan=False).encode() == line,
         'whole canonical LOOP schema1 and exact policy/scope domains')
    return value



def effects_decode(line):
    def pairs(items):
        need(len(items)==len(dict(items)),'no duplicate effects terminal fields')
        return dict(items)
    need(type(line)is bytes and line.startswith(EFFECTS_PREFIX)and len(line)<=4096 and b'\r'not in line,
         'bounded actual effects terminal row')
    value=json.loads(line[len(EFFECTS_PREFIX):],object_pairs_hook=pairs)
    need(type(value)is dict and tuple(value)==EFFECTS_KEYS and
         all(type(v)is int and 0<=v<1<<64 for v in value.values())and
         tuple(value[k]for k in('version','policy_version','scalar_version','mov_version'))==(1,13,3,2)and
         value['route']in(0,11,12,13)and value['scope']in(0,1,2,3)and value['choice_complete']in(0,1)and
         EFFECTS_PREFIX+json.dumps(value,separators=(',',':'),allow_nan=False).encode()==line,
         'whole canonical effects schema1 and separately bound policy13/scalar3/MOV2 domains')
    return value


def split(stderr):
    need(type(stderr)is bytes and stderr.endswith(b'\n'),'complete effects terminal stream')
    lines=stderr[:-1].split(b'\n')
    need(len(lines)>6 and lines[-1].startswith(b'LI2_PERSISTENT_UNREGISTERED ')and
         lines[-2].startswith(b'LI2_PERSISTENT_SUBENTRY ')and lines[-3].startswith(b'LI2_PF_REFUSALS ')and
         lines[-4].startswith(PREFIX)and lines[-5].startswith(EFFECTS_PREFIX)and
         lines[-6].startswith(b'LI2_LINKED_NATIVE_PROBE ')and
         sum(line.startswith(PREFIX)for line in lines)==1 and
         sum(line.startswith(EFFECTS_PREFIX)for line in lines)==1,
         'one actual probe/effects/LOOP/PF/subentry/unregistered terminal order')
    loop,effects=decode(lines[-4]),effects_decode(lines[-5])
    need(all(loop[k]==effects[k]for k in('status','failure_code','route','scope')),
         'both actual rows share the same outcome and current routing scope')
    # Both rows are fully typed before removing their exact original bytes.
    original=b'\n'.join(lines[:-5]+lines[-3:])+b'\n'
    return loop,effects,original
