"""Extract the prospectively declared, independently disassembled leaf tails."""
import sys
if sys.flags.optimize:
    raise SystemExit("Sample extraction requires assertions; optimized Python is refused")

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

out = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--binary', type=Path, default=Path('/usr/lib64/libc.so.6'))
binary_path = parser.parse_args().binary
binary = binary_path.read_bytes()
assert hashlib.sha256(binary).hexdigest() == '4fe244b698006f2a5cc7d1e6008c195dfb3ac4038ea79a6500bdde4205efb523', 'Pinned sample binary differs; no resampling is permitted'
assert len(binary) == 2553784
assert binary[:6] == b'\x7fELF\x02\x01'
elf_type, machine = struct.unpack_from('<HH', binary, 16)
assert machine == 62
phoff = struct.unpack_from('<Q', binary, 32)[0]
phentsize, phnum = struct.unpack_from('<HH', binary, 54)
assert phentsize == 56
segments = []
for index in range(phnum):
    fields = struct.unpack_from('<IIQQQQQQ', binary, phoff + index * phentsize)
    kind, flags, offset, address, _, filesz, memsz, alignment = fields
    if kind == 1 and flags & 1:
        segments.append(dict(index=index, flags=flags, file_offset=offset,
                             virtual_address=address, file_bytes=filesz,
                             memory_bytes=memsz, alignment=alignment))
disassembly = subprocess.check_output(
    ['objdump', '-d', '-Mintel', '--insn-width=16', str(binary_path)], text=True)
(out / 'libc.objdump').write_text(disassembly)
notes = subprocess.check_output(['readelf', '-n', str(binary_path)], text=True)
(out / 'libc.notes').write_text(notes)
version = subprocess.check_output(['objdump', '--version'], text=True).splitlines()[0]
build_id = re.search(r'Build ID: ([0-9a-f]+)', notes).group(1)
assert build_id == 'a39d61007783d72b0cd93628fc7a0f93d34e5434'
instructions = []
pattern = re.compile(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} +)+)\s*([^\t].*)$')
for line in disassembly.splitlines():
    match = pattern.match(line)
    if match:
        address = int(match.group(1), 16)
        code = bytes.fromhex(match.group(2))
        asm = match.group(3).split('#')[0].strip()
        instructions.append(dict(address=address, bytes=code.hex(), asm=asm))

register = re.compile(r'^(?:r(?:ax|bx|cx|dx|si|di|sp|bp)|e(?:ax|bx|cx|dx|si|di|sp|bp)|'
                      r'(?:ax|bx|cx|dx|si|di|sp|bp|al|bl|cl|dl|ah|bh|ch|dh|sil|dil|spl|bpl)|'
                      r'r(?:8|9|1[0-5])(?:d|w|b)?)$')
immediate = re.compile(r'^-?(?:0x[0-9a-f]+|[0-9]+)$')
address_term = '(?:' + register.pattern[1:-1] + r')(?:\*[1248])?|0x[0-9a-f]+|[0-9]+'
address_expression = re.compile(r'-?(?:' + address_term + r')(?:[+-](?:' + address_term + r'))*')
stack_registers = {'rsp', 'esp', 'sp', 'spl'}

def qualified(item):
    parts = item['asm'].split(None, 1)
    mnemonic = parts[0]
    operands = parts[1].split(',') if len(parts) == 2 else []
    operands = [value.strip() for value in operands]
    if mnemonic == 'nop':
        return not operands
    if mnemonic in {'inc', 'dec'}:
        return (len(operands) == 1 and register.fullmatch(operands[0])
                and operands[0] not in stack_registers)
    if mnemonic not in {'mov', 'lea', 'add', 'sub', 'cmp'} or len(operands) != 2:
        return False
    dest, source = operands
    if not register.fullmatch(dest):
        return False
    if mnemonic != 'cmp' and dest in stack_registers:
        return False
    if mnemonic == 'lea':
        if not (source.startswith('[') and source.endswith(']')):
            return False
        return bool(address_expression.fullmatch(source[1:-1]))
    return bool(register.fullmatch(source) or immediate.fullmatch(source))

unique = {}
pre_dedup = 0
returns = 0
for index, instruction in enumerate(instructions):
    if instruction['bytes'] != 'c3' or instruction['asm'] != 'ret':
        continue
    returns += 1
    for count in range(2, 9):
        if index + 1 < count:
            continue
        tail = instructions[index + 1 - count:index + 1]
        if len(bytes.fromhex(tail[0]['bytes'])) < 5:
            continue
        if not all(qualified(item) for item in tail[:-1]):
            continue
        if any(left['address'] + len(bytes.fromhex(left['bytes'])) != right['address']
               for left, right in zip(tail, tail[1:])):
            continue
        start = tail[0]['address']
        data = b''.join(bytes.fromhex(item['bytes']) for item in tail)
        owners = [segment for segment in segments
                  if segment['virtual_address'] <= start
                  and start + len(data) <= segment['virtual_address'] + segment['file_bytes']]
        assert len(owners) == 1
        segment = owners[0]
        offset = segment['file_offset'] + start - segment['virtual_address']
        assert binary[offset:offset + len(data)] == data
        pre_dedup += 1
        record = dict(virtual_address=start, file_offset=offset, segment=segment['index'],
                      bytes=data.hex(), heads=[item['address'] - start for item in tail],
                      instructions=tail,
                      rank=hashlib.sha256(b'liteinst2-a2-samples-v1' + data).hexdigest())
        prior = unique.get(data)
        if prior is None or start < prior['virtual_address']:
            unique[data] = record

population = sorted(unique.values(), key=lambda item: item['rank'])
assert (len(instructions), returns, pre_dedup, len(population)) == (367799, 6355, 543, 79), 'Pinned disassembly/population changed'
assert len(population) >= 32, f'insufficient eligible samples: {len(population)}'
manifest = dict(policy='samples-design.md', binary_name='libc.so.6',
                binary_sha256=hashlib.sha256(binary).hexdigest(), binary_bytes=len(binary),
                elf_type=elf_type, elf_machine=machine, build_id=build_id,
                objdump_version=version, executable_segments=segments,
                decoded_instructions=len(instructions), unprefixed_returns=returns,
                eligible_tails_before_deduplication=pre_dedup,
                eligible_unique_tails=len(population), selected=population[:32])
(out / 'sample-population.json').write_text(json.dumps(population, indent=2) + '\n')
(out / 'samples.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps({key:value for key,value in manifest.items() if key != 'selected'}, indent=2))
print('selected_heads', sum(len(item['heads']) for item in manifest['selected']))
