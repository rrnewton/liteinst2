#!/usr/bin/env python3
"""Generate store source data from the exact retained load table; no decoder/test."""
import argparse
import copy
import hashlib
import json
from pathlib import Path

INPUT_SHA256 = '3a6ed4cddbc3ef7b2de65a3752a76bb6271330d86833587962f5b8839a4d7c9b'
HERE = Path(__file__).resolve().parent
OVERRIDES = json.loads((HERE/'overrides.json').read_bytes())
KINDS = {'register':0, 'data':1, 'stack':2, 'rip':3, 'absolute':4}

def derive(table):
    """Pure source transformation over table and the fixed adjacent overrides."""
    if table['code'] != 1598 or len(table['cases']) != 128:
        raise ValueError('exact 128-case VEX128 load predecessor required')
    result = []
    override = {x['case_index']:x for x in OVERRIDES['rows']}
    if list(override) != list(range(64,76))+[125] or OVERRIDES['rip_displacements'] != {'negative':-16384,'positive':12288}:
        raise ValueError('closed twelve write-geometry and one indexed-lookahead overrides')
    for i,old in enumerate(table['cases']):
        if old['case_index'] != i:raise ValueError('ordered predecessor')
        row = copy.deepcopy(old)
        for key in ('promotion_index','old_total_control_index','promotion_name'):row.pop(key,None)
        raw = bytearray.fromhex(row['hex']);opcode = 2 if raw[0] == 0xc5 else 3 if raw[0] == 0xc4 else -1
        if opcode < 0 or raw[opcode] != 0x6f:raise ValueError('literal VEX load opcode')
        raw[opcode] = 0x7f
        row.update(hex=raw.hex(),src_reg=old['dest'],dest=old['src_reg'] if old['memory_kind']=='register' else None,
                   name='store_'+old['name'])
        if i in override:
            change = override[i]
            row['section'] = 'write_geometry' if 64 <= i < 76 else old['section']
            if 'hex' in change:
                # Complete new operand roles: no stale load-promotion metadata.
                row.update(dest=None,base=None,index=None,scale=1,displacement=0,disp_bytes=0,disp_offset=None,
                    operand_offset=None,index_value=None,rip_offset=None,absolute_target=None,ignored_x=False,ignored_b=False)
            row.update(change)
            if 'hex' in change:
                raw = bytes.fromhex(row['hex']);row['length'] = len(raw)
                row['vex_bytes'] = 2 if raw[0] == 0xc5 else 3;row['wig'] = 0 if row['vex_bytes']==2 else raw[2]>>7
                row['disp_offset'] = len(raw)-row['disp_bytes'] if row['disp_bytes'] else None
                row['tail'] = change.get('tail',len(raw))
        if row['memory_kind'] == 'rip':
            displacement = OVERRIDES['rip_displacements']['negative' if row['displacement']<0 else 'positive']
            raw = bytearray.fromhex(row['hex']);at = row['disp_offset']
            if row['disp_bytes'] != 4 or at is None:raise ValueError('literal RIP disp32')
            raw[at:at+4] = displacement.to_bytes(4,'little',signed=True)
            # Constants are finalized only here, during source generation.
            row.update(hex=raw.hex(),displacement=displacement,rip_offset=displacement,
                       operand_offset=row['length']-row['tail'])
        elif row['memory_kind'] == 'absolute':
            row['operand_offset'] = row['absolute_target']-0x20000000
        if not 0 <= row['src_reg'] < 16 or not 1 <= row['tail'] <= row['length'] <= 10:
            raise ValueError('bounded source/geometry')
        if row['memory_kind'] == 'register':
            if row['dest'] is None or not 0 <= row['dest'] < 16:raise ValueError('register destination')
        elif row['dest'] is not None:raise ValueError('memory destination is not an XMM')
        if i >= 76 and i <= 124 and (row['length'],row['tail']) != (old['length'],old['tail']):
            raise ValueError('all 49 fetch geometries retained')
        result.append(row)
    return result

def c_source(rows,patterns):
    out = ['/* Generated final literal7F cases; no per-lane instruction fixups. */',
           'static const unsigned char v64_patterns[3][16]={']
    for value in patterns:out.append('    {'+','.join('0x'+value[j:j+2] for j in range(0,32,2))+'},')
    out += ['};','struct vpb_case { const char *name; unsigned length; int dest; unsigned pattern,tail,kind; int src,base,index; unsigned scale; int64_t displacement; int offset; unsigned index_value; uint64_t absolute_target; unsigned char encoding[10]; };',
            'static const struct vpb_case vpb_cases[128]={']
    for row in rows:
        fields = [json.dumps(row['name']),str(row['length']),str(-1 if row['dest'] is None else row['dest']),
            str(row['pattern']),str(row['tail']),str(KINDS[row['memory_kind']]),str(row['src_reg']),
            str(-1 if row['base'] is None else row['base']),str(-1 if row['index'] is None else row['index']),
            str(row['scale']),str(row['displacement']),str(row['operand_offset'] or 0),str(row['index_value'] or 0),str(row['absolute_target'] or 0),
            '{'+','.join('0x'+row['hex'][i:i+2] for i in range(0,len(row['hex']),2))+'}']
        out.append('    {'+','.join(fields)+'},')
    return '\n'.join(out+['};',''])

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--input',type=Path,required=True)
    ap.add_argument('--output-dir',type=Path,required=True);args=ap.parse_args()
    raw=args.input.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=INPUT_SHA256:raise ValueError('exact committed load corpus hash')
    table=json.loads(raw);rows=derive(table)
    document={k:copy.deepcopy(v) for k,v in table.items() if k!='cases'}
    document.update(code=1840,cases=rows,section_counts=dict(register=32,base=16,indexed=16,write_geometry=12,fetch=49,extra=3),
        source_geometry=dict(reservation_pages=10,source_page=4,source_pages=3,pc='source+4096-tail',lower_data_page=1,upper_data_page=8),
        low_arena=dict(reservation_first=0x1ffff000,reservation_bytes=16384,writable_first=0x20000000,writable_bytes=8192,operand=0x20000100,
                       mechanism='genuine MAP_FIXED_NOREPLACE; collision fails, no alternative target or skipped case'))
    args.output_dir.mkdir(parents=True,exist_ok=True)
    values={'cases.json':json.dumps(document,sort_keys=True,separators=(',',':'))+'\n','cases.inc':c_source(rows,table['patterns_hex'])}
    for name,text in values.items():(args.output_dir/name).write_text(text)
    print(json.dumps({name:dict(bytes=len(text.encode()),sha256=hashlib.sha256(text.encode()).hexdigest()) for name,text in values.items()},sort_keys=True))

if __name__=='__main__':main()
