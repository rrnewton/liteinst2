"""Independent complete-disassembly geometry; native admission supplies provenance."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
import re

REG = r'r(?:ax|bx|cx|dx|si|di|sp|bp|[89]|1[0-5])'
VOLATILE = ('rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11')


def geometry(rows, va, length):
    """rows are complete objdump rows joined to the unique whole FUNC symbol."""
    assert type(va) is int and 0 < va < 1 << 64
    assert type(length) is int and 1 <= length <= 256 and va + length < 1 << 64
    assert type(rows) is list and rows
    at = va
    for pc, code, asm in rows:
        assert type(pc) is int and pc == at
        assert type(code) is bytes and 1 <= len(code) <= 15
        assert type(asm) is str and asm and asm.isascii()
        at += len(code)
    assert at == va + length
    offsets = [pc-va for pc, _, _ in rows]
    stack = {'rsp': 0}
    calls, continuations = [], []
    delta = None
    for i, (pc, code, asm) in enumerate(rows):
        words = asm.split(None, 1)
        op, args = words[0], words[1] if len(words) == 2 else ''
        if op in ('push', 'pop'):
            assert re.fullmatch(REG, args) and args != 'rsp'
            assert code[-1] in (range(0x50, 0x58) if op == 'push' else range(0x58, 0x60))
            stack['rsp'] += -8 if op == 'push' else 8
            if op == 'pop': stack.pop(args, None)
        elif op == 'mov':
            operands = args.split(','); assert len(operands) == 2
            dst, src = operands
            if re.fullmatch(REG, dst):
                value = stack.get(src) if re.fullmatch(REG, src) else None
                if dst == 'rsp': assert value is not None
                if value is None: stack.pop(dst, None)
                else: stack[dst] = value
            else:
                assert dst.startswith('QWORD PTR [') and dst.endswith(']')
                assert re.fullmatch(REG, src)
        elif op == 'lea':
            match = re.fullmatch('('+REG+r'),\[('+REG+r')(?:(\+|-)0x([0-9a-f]+))?\]', args)
            assert match and match[2] in stack
            displacement = int(match[4], 16) if match[4] else 0
            if match[3] == '-': displacement = -displacement
            stack[match[1]] = stack[match[2]] + displacement
        elif op in ('add', 'sub'):
            match = re.fullmatch(r'rsp,0x([0-9a-f]+)', args); assert match
            value = int(match[1], 16); assert 0 < value <= 256 and value % 8 == 0
            stack['rsp'] += value if op == 'add' else -value
        elif op == 'call':
            assert not calls and re.fullmatch(REG, args) and i + 1 < len(rows)
            assert (8 + stack['rsp']) % 16 == 0
            calls.append(pc-va); continuations.append(rows[i+1][0]-va)
            delta = 8-stack['rsp']
            assert re.fullmatch('mov\\s+QWORD PTR \\['+REG+r'\],rax', rows[i+1][2])
            for reg in VOLATILE: stack.pop(reg, None)
        elif op == 'ret':
            assert i == len(rows)-1 and args == '' and code == b'\xc3'
            assert calls and stack['rsp'] == 0
        else:
            raise AssertionError('outside admitted operation grammar')
        assert type(stack.get('rsp')) is int and -256 <= stack['rsp'] <= 0 and stack['rsp'] % 8 == 0
    assert len(calls) == 1 and rows[-1][2] == 'ret'
    return dict(length=length, heads=offsets, call_offset=calls[0],
                continuation_offset=continuations[0], outer_ret_offset=offsets[-1],
                subject_rsp_delta=delta, elf_va=va, body_hex=b''.join(code for _, code, _ in rows).hex())
