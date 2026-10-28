#!/usr/bin/env python3
"""Generate the literal 108-case [RDI] VPCMPEQB register/mask corpus."""
import argparse
import hashlib
import json
from pathlib import Path
import re

DONOR_SHA = 'daa1b98659238d71b73730996ba63a09ee3979757ff5daae6d16b11abbb68d3a'
SUFFIX_SHA = '4dd5d0a238ab2e5d1ff55cd551a369d0fc1226c40aeaee648aa52ab638e16cc4'
PROMOTED = (
    (33, 17, 1, '62f17540740f'),
    (34, 17, 7, '62f17540743f'),
    (39, 1, 0, '62f175487407'),
    (40, 16, 0, '62f17d407407'),
    (41, 18, 0, '62f16d407407'),
)
REFUSALS = (
    ('reserved_k_extension_r', '627175407407'),
    ('reserved_k_extension_rprime', '62e175407407'),
    ('noncanonical_x_extension', '62b175407407'),
    ('fixed_p0_bit2', '62f575407407'),
    ('fixed_p0_bit3', '62f975407407'),
    ('map0', '62f075407407'),
    ('fixed_p1_bit2_clear', '62f171407407'),
    ('pp0', '62f174407407'),
    ('pp3', '62f177407407'),
)


def encoding(source, destination):
    return bytes((0x62, 0xf1, 0x05 | ((15 - (source & 15)) << 3),
                  0x40 | ((1 - (source >> 4)) << 3), 0x74,
                  0x07 | (destination << 3))).hex()


def derive():
    rows = []

    def add(name, pattern, source, destination, tail):
        rows.append(dict(name=name, pattern=pattern, offset=(0, 257, 4032)[pattern],
                         tail=tail, source=source, destination=destination,
                         encoding=encoding(source, destination)))

    for pattern in range(3):
        for source in range(32):
            destination = (source + pattern) % 8
            add(f'pattern{pattern}_source{source}_k{destination}', pattern, source,
                destination, 1 + (source + pattern) % 6)
    for i, (old_index, source, destination, _) in enumerate(PROMOTED):
        add(f'promoted{old_index}_pattern0', 0, source, destination, 6)
        add(f'promoted{old_index}_pattern2', 2, source, destination, i + 1)
    add('original_source17_k0_pattern1', 1, 17, 0, 6)
    add('original_source17_k0_pattern2', 2, 17, 0, 3)
    return rows


def read_donor(path):
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != DONOR_SHA:
        raise ValueError('exact unchanged donor required')
    text = raw.decode()
    patterns = text[text.index('static const unsigned char v64_patterns'):
                    text.index('static const uint64_t vpc_expected')]
    expected = text[text.index('static const uint64_t vpc_expected'):
                    text.index('struct vpb_case')]
    suffix = text[text.index('struct vpb_refusal'):]
    if hashlib.sha256(suffix.encode()).hexdigest() != SUFFIX_SHA:
        raise ValueError('complete original refusal suffix required')
    values = [int(s, 16) for s in re.findall(r'0x([0-9a-f]{2})', patterns)]
    if len(values) != 192:
        raise ValueError('three complete literal 64-byte patterns required')
    return patterns, expected, suffix, [values[i:i + 64] for i in range(0, 192, 64)]


def hexbytes(values):
    return ','.join(f'0x{x:02x}' for x in values)


def generate(donor):
    patterns_c, expected_c, suffix, patterns = read_donor(donor)
    source = [1 + (17 * 17 + i * 13) % 255 for i in range(64)]
    rows = derive()
    promoted = [dict(old_index=old_index, source=s, destination=k, encoding=literal,
                     case_indices=[96 + 2 * i, 97 + 2 * i])
                for i, (old_index, s, k, literal) in enumerate(PROMOTED)]
    refusals = [dict(name=name, encoding=literal) for name, literal in REFUSALS]
    table = dict(patterns=patterns, source=source, rows=rows,
                 promoted=promoted, refusals=refusals)
    text = ('/* Canonical unmasked VPCMPEQB K0..7,ZMM0..31,[RDI].\n'
            '   Old literal patterns/masks and complete 66-row refusal suffix retained. */\n')
    text += patterns_c + expected_c
    text += 'static const unsigned char vpc_source[64]={' + hexbytes(source) + '};\n'
    text += ('struct vpb_case { const char *name; unsigned pattern,offset,tail,source,destination; '
             'unsigned char encoding[6]; };\nstatic const struct vpb_case vpb_cases[6][18]={\n')
    for group in range(6):
        text += ' {\n'
        for row in rows[18 * group:18 * (group + 1)]:
            values = ','.join(str(row[k]) for k in ('pattern', 'offset', 'tail', 'source', 'destination'))
            text += '  {"' + row['name'] + '",' + values + ',{' + hexbytes(bytes.fromhex(row['encoding'])) + '}},\n'
        text += ' },\n'
    text += '};\n' + suffix
    text += ('\n/* Additive neighbors; original vpb_refused above is byte-exact. */\n'
             'static const struct vpb_refusal vpcm_refused[]={\n')
    for name, literal in REFUSALS:
        value = bytes.fromhex(literal)
        text += '    {' + str(len(value)) + ',{' + hexbytes(value) + '}}, /* ' + name + ' */\n'
    text += '};\n'
    return table, text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--donor', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    table, text = generate(args.donor)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / 'cases.json').write_text(json.dumps(table, sort_keys=True, separators=(',', ':')) + '\n')
    (args.output_dir / 'cases.inc').write_text(text)


if __name__ == '__main__':
    main()
