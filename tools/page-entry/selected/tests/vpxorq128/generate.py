#!/usr/bin/env python3
"""Generate the fixed structural VPXORQ128 corpus; no decoder or target execution."""
import argparse
import hashlib
import json
from pathlib import Path

OLD_SHA256 = '79d621d7d86cab740d69742030a6e9bff1b021a53530a40b26aa5d7ba8262fe6'
PATTERNS = [
    [[0x00,0xff,0x80,0x7f,0x01,0xfe,0x55,0xaa,0x00,0xff,0x01,0x80,0x7f,0xfe,0xaa,0x55],
     [0xff,0x00,0x7f,0x80,0xfe,0x01,0xaa,0x55,0xff,0xff,0x01,0x00,0x80,0xfe,0x55,0xaa]],
    [[0x00]*16, [0xff]*16],
    [[0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x81,0x42,0x24,0x18,0xe7,0xdb,0xbd,0x7e],
     [0x13,0x37,0xc0,0xde,0x5a,0xa5,0x69,0x96,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10]],
]

def encoding(destination, src1, src2):
    # EVEX inverted R/X/B/R' plus vvvv/V'; ModRM is register-only.
    p0 = ((1-((destination >> 3)&1)) << 7) | ((1-((src2 >> 4)&1)) << 6)
    p0 |= ((1-((src2 >> 3)&1)) << 5) | ((1-((destination >> 4)&1)) << 4) | 1
    p1 = 0x85 | ((15-(src1&15)) << 3)
    p2 = (1-((src1 >> 4)&1)) << 3
    return bytes((0x62,p0,p1,p2,0xef,0xc0|((destination&7)<<3)|(src2&7))).hex()

def rows():
    triples = [(d,(d+1)%32,(d+17)%32,'distinct') for d in range(32)]
    triples += [(d,d,(d+9)%32,'destination_src1') for d in range(32)]
    triples += [(d,(d+7)%32,d,'destination_src2') for d in range(1,32,2)]
    edges = (0,7,8,15,16,23,24,31)
    triples += [((s+11)%32,s,s,'sources_equal') for s in edges]
    triples += [(s,s,s,'all_equal') for s in edges]
    result = []
    for i,(dest,src1,src2,alias) in enumerate(triples):
        pattern = i%3
        left = PATTERNS[pattern][0]
        right = PATTERNS[pattern][0 if src1==src2 else 1]
        result.append(dict(id=i,pattern=pattern,tail=6 if i==92 else i%6+1,
                           src1=src1,src2=src2,destination=dest,alias=alias,
                           encoding=encoding(dest,src1,src2),
                           expected=bytes(a^b for a,b in zip(left,right)).hex()))
    return result

def refusals():
    base = bytes.fromhex('62a1fd00efc0')
    result = []
    def changed(name, offset, value):
        value_bytes = bytearray(base); value_bytes[offset]=value
        result.append(dict(name=name,encoding=value_bytes.hex()))
    for k in range(1,8):changed('mask'+str(k),3,k)
    changed('z1_k0',3,0x80)
    changed('b1_register',3,0x10)
    for ll in (1,2,3):changed('ll'+str(ll),3,ll<<5)
    changed('w0_vpxord',2,0x7d)
    for pp in (0,2,3):changed('pp'+str(pp),2,0xfc|pp)
    for mmap in (0,2,3):changed('map'+str(mmap),1,0xa0|mmap)
    changed('p0_fixed_bit2',1,0xa5)
    changed('p0_fixed_bit3',1,0xa9)
    changed('p1_fixed_bit2_clear',2,0xf9)
    # Full, valid memory encodings: [RAX], [RIP+256], [RAX+RDX].
    for name,hex_bytes in (
        ('memory_base','62e1fd00ef00'),
        ('memory_rip','62e1fd00ef0500010000'),
        ('memory_sib','62e1fd00ef0410')):
        result.append(dict(name=name,encoding=hex_bytes))
    for prefix in (0x66,0xf2,0xf3,0xf0,0x67,0x64,0x48):
        result.append(dict(name='prefix_%02x'%prefix,encoding=(bytes([prefix])+base).hex()))
    for n in range(1,6):result.append(dict(name='truncated_'+str(n),encoding=base[:n].hex()))
    return result

def cbytes(values):return '{'+','.join('0x%02x'%b for b in values)+'}'

def render(table, old_suffix):
    out = ['/* Fixed 96-case structural corpus; expected bytes use declared prestate only. */\n',
           'struct vpb_case { unsigned pattern,tail,src1,src2,destination; unsigned char encoding[6],expected[16]; };\n',
           'static const unsigned char vpx_patterns[3][2][16]={\n']
    for left,right in table['patterns']:out.append('  {'+cbytes(left)+','+cbytes(right)+'},\n')
    out.append('};\nstatic const struct vpb_case vpb_cases[6][16]={\n')
    for group in range(6):
        out.append(' {\n')
        for r in table['rows'][group*16:(group+1)*16]:
            fields=','.join(str(r[k]) for k in ('pattern','tail','src1','src2','destination'))
            out.append('  {'+fields+','+cbytes(bytes.fromhex(r['encoding']))+','+cbytes(bytes.fromhex(r['expected']))+'},\n')
        out.append(' },\n')
    out.append('};\n')
    # Keep the complete old declaration, all rows and closing bytes intact.
    out.append(old_suffix.decode('ascii'))
    out.append('\nstruct vpx_refusal { unsigned n; unsigned char b[15]; };\n')
    out.append('static const struct vpx_refusal vpx_refused[37]={\n')
    for r in table['refusals']:
        raw=bytes.fromhex(r['encoding'])
        out.append('  {%d,%s}, /* %s */\n'%(len(raw),cbytes(raw),r['name']))
    out.append('};\n')
    return ''.join(out).encode('ascii')

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--old-cases',type=Path,default=Path('tools/page-entry/selected/tests/vpcmpb/cases.inc'))
    ap.add_argument('--output-dir',type=Path,required=True)
    a=ap.parse_args()
    old=a.old_cases.read_bytes()
    if hashlib.sha256(old).hexdigest()!=OLD_SHA256:raise ValueError('old vector case bytes differ')
    marker=b'struct vpb_refusal '
    if old.count(marker)!=2:raise ValueError('old refusal declarations differ')
    suffix=old[old.index(marker):]
    table=dict(patterns=PATTERNS,rows=rows(),refusals=refusals(),old_refusal_rows=73)
    a.output_dir.mkdir(parents=True,exist_ok=True)
    with (a.output_dir/'cases.json').open('x') as f:
        f.write(json.dumps(table,sort_keys=True,separators=(',',':'))+'\n')
    with (a.output_dir/'cases.inc').open('xb') as f:f.write(render(table,suffix))

if __name__=='__main__':main()
