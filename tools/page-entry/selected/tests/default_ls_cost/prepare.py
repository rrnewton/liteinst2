"""Only the three reviewed diagnostic insertions; complete byte inverse required."""
import hashlib
from pathlib import Path

BEFORE_SHA = '29af2ad5816e62628c2735fa919b8ecae65dbe018f31613346025cfee9020788'
WRITER_SHA = 'dda21495e350a364e5bac0c732b95ebe5ebdf1ea216cec2d9ae77e613448715b'
AFTER_SHA = '42af64596c55326da43b254b6c827d00cae397d58aa84bb7091a269b47e1053c'
INSERTIONS = (
    ('static void handler(int sig,siginfo_t *si,void *ptr) {',
     '#include "progress.inc"\nstatic void handler(int sig,siginfo_t *si,void *ptr) {'),
    ('    checked(!handling && si && ptr,218,sig); handling=1;',
     '    checked(!handling && si && ptr,218,sig); handling=1;\n    diag_begin((unsigned)sig,(const ucontext_t *)ptr);'),
    ('    handling=0;\n}',
     '    diag_end((const ucontext_t *)ptr);\n    handling=0;\n}'),
)


def prepare_runtime(source, target, writer, writer_target):
    before=Path(source).read_bytes();payload=Path(writer).read_bytes()
    if hashlib.sha256(before).hexdigest()!=BEFORE_SHA or hashlib.sha256(payload).hexdigest()!=WRITER_SHA:
        raise ValueError('exact unmodified runtime and reviewed counter writer')
    after=before.decode()
    for old,new in INSERTIONS:
        if after.count(old)!=1:raise ValueError('one original diagnostic insertion seam')
        after=after.replace(old,new)
    restored=after
    for old,new in reversed(INSERTIONS):
        if restored.count(new)!=1:raise ValueError('one diagnostic inverse seam')
        restored=restored.replace(new,old)
    after=after.encode()
    if restored.encode()!=before or hashlib.sha256(after).hexdigest()!=AFTER_SHA:
        raise ValueError('whole original runtime inverse and exact observed runtime')
    for path,data in ((target,after),(writer_target,payload)):
        with Path(path).open('xb')as stream:stream.write(data)
    return dict(original_sha256=BEFORE_SHA,observed_sha256=AFTER_SHA,writer_sha256=WRITER_SHA,
                exact_inverse=True,insertions=3)
