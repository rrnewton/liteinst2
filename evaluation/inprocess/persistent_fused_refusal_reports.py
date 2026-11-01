"""Separate PF refusal row; no ABI2 cell or old miss bucket is synthesized."""
import hashlib,json
from page_selected import need
PREFIX=b'LI2_PF_REFUSALS '
KEYS=('version','policy_version','reason','status','failure_code','refused','cancelled')
CONTROL_COUNT=22

def decode(line):
    def pairs(items):
        need(len(items)==len(dict(items)),'no duplicate PF refusal fields')
        return dict(items)
    need(type(line)is bytes and line.startswith(PREFIX)and len(line)<=4096 and b'\r'not in line,
         'bounded actual PF refusal row')
    value=json.loads(line[len(PREFIX):],object_pairs_hook=pairs)
    need(type(value)is dict and tuple(value)==KEYS and
         all(type(v)is int and 0<=v<1<<64 for v in value.values())and
         (value['version'],value['policy_version'],value['reason'])==(1,11,256)and
         PREFIX+json.dumps(value,separators=(',',':'),allow_nan=False).encode()==line,
         'canonical complete PF refusal schema1 policy11 reason256')
    need(value['cancelled']<=value['refused'],'PF cancellation cannot precede classified refusal')
    return value

def split(stderr):
    need(type(stderr)is bytes and stderr.endswith(b'\n'),'complete PF terminal stream')
    lines=stderr[:-1].split(b'\n')
    need(len(lines)>4 and lines[-1].startswith(b'LI2_PERSISTENT_UNREGISTERED ')and
         lines[-2].startswith(b'LI2_PERSISTENT_SUBENTRY ')and lines[-3].startswith(PREFIX)and
         lines[-4].startswith(b'LI2_LINKED_NATIVE_PROBE ')and
         sum(line.startswith(PREFIX)for line in lines)==1,
         'one PF row in actual probe/PF/subentry/unregistered order')
    return decode(lines[-3]),b'\n'.join(lines[:-3]+lines[-2:])+b'\n'

def controls(stderr,owner,owner_reader):
    value,_=split(stderr);owner_reader.pf_terminal(value,owner);refused=[]
    def reject(name,mutant):
        need(mutant!=stderr,'causal PF terminal stimulus '+name)
        try:
            row,_=split(mutant);owner_reader.pf_terminal(row,owner)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted supplied PF terminal mutation '+name)
    lines=stderr[:-1].split(b'\n');index=len(lines)-3
    def encoded(row):
        changed=list(lines);changed[index]=PREFIX+json.dumps(row,separators=(',',':'),allow_nan=False).encode()
        return b'\n'.join(changed)+b'\n'
    for key in KEYS:
        row=dict(value);row[key]^=1;reject('protected_'+key,encoded(row))
    for key in KEYS:
        row=dict(value);del row[key];reject('missing_'+key,encoded(row))
    reject('missing_row',b'\n'.join(lines[:index]+lines[index+1:])+b'\n')
    reject('duplicate_row',b'\n'.join(lines[:index]+[lines[index]]+lines[index:])+b'\n')
    changed=list(lines);changed[index-1],changed[index]=changed[index],changed[index-1]
    reject('wrong_position',b'\n'.join(changed)+b'\n');reject('truncated',stderr[:-1])
    row=dict(value);row['extra']=0;reject('extra_field',encoded(row))
    changed=list(lines);changed[index]=lines[index][:-1]+b',"version":1}'
    reject('duplicate_field',b'\n'.join(changed)+b'\n')
    row=dict(value);row['cancelled']=False;reject('boolean',encoded(row))
    changed=list(lines);changed[index]=lines[index].replace(b'{',b'{ ',1)
    reject('noncanonical',b'\n'.join(changed)+b'\n')
    need(len(refused)==len(set(refused))==CONTROL_COUNT,'all22 separate PF terminal controls')
    return dict(refusals=refused,native_operations=0,original_stderr_sha256=hashlib.sha256(stderr).hexdigest())
