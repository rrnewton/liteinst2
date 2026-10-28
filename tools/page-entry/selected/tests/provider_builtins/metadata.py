"""Literal source for actual main PT_INTERP; does not emit or modify ELF bytes."""
import json
from pathlib import Path

def emit(directory):
    directory=Path(directory)
    if not directory.is_absolute()or not directory.is_dir():raise ValueError('actual unique absolute build directory')
    interpreter=directory/'li2-provider-builtins-entry.so'
    metadata=directory/'metadata.S'
    text='.section .interp,"a",@progbits\n.asciz '+json.dumps(str(interpreter))+'\n'
    text+='.section .note.GNU-stack,"",@progbits\n'
    with metadata.open('x')as out:out.write(text)
    return interpreter,metadata
