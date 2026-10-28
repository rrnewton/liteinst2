"""Generate one explicit closed-environment test adapter; old carrier unchanged."""
import hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[5]
BEFORE_SHA='3361b23b0661dfccc956ce0194a6c5f48a97d8e4277599a0de264053e6f16b63'
OLD='        if fork_fds is not None:\n'
NEW='''        # Explicit finite test selector, retained in the actual launch receipt.
        selector = os.environ.get("LI2_ONESHOT_FAILURE", "")
        if not selector.isascii() or not selector.isdecimal() or str(int(selector)) != selector or not 1 <= int(selector) <= 49:
            raise ValueError("closed one-shot failure selector")
        env["LI2_ONESHOT_FAILURE"] = selector
        if fork_fds is not None:
'''
def generate(output):
    source=ROOT/'tools/page-entry/carrier.py';data=source.read_bytes()
    if hashlib.sha256(data).hexdigest()!=BEFORE_SHA or data.count(OLD.encode())!=1:
        raise ValueError('exact unmodified carrier source')
    result=data.replace(OLD.encode(),NEW.encode())
    with output.open('xb')as f:f.write(result)
    if result.replace(NEW.encode(),OLD.encode())!=data:raise ValueError('exact carrier inverse')
    return dict(bytes=len(result),sha256=hashlib.sha256(result).hexdigest())
