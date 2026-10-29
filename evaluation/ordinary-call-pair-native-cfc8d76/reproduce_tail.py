#!/usr/bin/env python3
"""Materialize the exact reviewed three-check runner; does not execute it.

The shared runner owns the original 180-second/8MiB bounds and closures.
This generator selects only the three previously UNRUN tail checks.
"""
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE_SHA = 'fa46e1b25720e73ee0e9321f091d48860cf9c23325428f991c449de1a9096ad5'
PAYLOAD_SHA = 'ebab52f268da2fa53cdcb47b38799b73e0f754b9cff0e8aadc43ef1eacde6b5e'
CHANGES = [{'before': 'repo = Path(__file__).resolve().parents[2]',
  'after': 'repo = Path(__file__).resolve().parents[3]'},
 {'before': 'args = parser.parse_args()',
  'after': 'args = parser.parse_args()\n'
           '    assert args.checks_only and not args.include_creation_identity and not '
           'args.include_reachable_allocation'},
 {'before': "required = {'fmt', 'clippy', 'check', 'workspace-default', 'serial-launch',\n"
            "                    'staged-allocation', 'prefixed-pun'}",
  'after': "required = {'serial-launch', 'staged-allocation', 'prefixed-pun'}"},
 {'before': "'Seven merge checks only; no repeated issue-specific campaign.'",
  'after': "'Only the three previously UNRUN tail checks. Original workspace timeout remains "
           "FAILED; this is not whole-seven-check acceptance.'"},
 {'before': 'compiler_jobs=4, helper_sha256=HELPER_SHA,',
  'after': 'compiler_jobs=4, helper_sha256=HELPER_SHA,\n'
           '        reserved_affinity=affinity, load_before=list(os.getloadavg()),'},
 {'before': 'finally:\n        save()',
  'after': "finally:\n        result['load_after'] = list(os.getloadavg())\n        save()"},
 {'before': "help='Run only the seven workspace and historical allocation checks after a merge.'",
  'after': "help='Run only the three previously UNRUN serial launch, staged allocation and "
           "prefixed-pun checks.'"},
 {'before': "recipe='python3 -B evaluation/admission/check_exec_identity.py --toolchain",
  'after': "recipe='python3 -B "
           'ignored/a5/cfc8d76-tail-checks-source-v1/successor-v2/tail_checks.py --toolchain'},
 {'before': 'repo = Path(__file__).resolve().parents[3]',
  'after': 'repo = Path(__file__).resolve().parents[4]'}]


def main():
    source = ROOT / 'evaluation/admission/check_exec_identity.py'
    data = source.read_bytes()
    assert hashlib.sha256(data).hexdigest() == SOURCE_SHA
    text = data.decode()
    for span in CHANGES:
        assert text.count(span['before']) == 1
        text = text.replace(span['before'], span['after'])
    data = text.encode()
    assert hashlib.sha256(data).hexdigest() == PAYLOAD_SHA
    dest = ROOT / 'ignored/a5/cfc8d76-tail-checks-source-v1/successor-v2/tail_checks.py'
    dest.parent.mkdir(parents=True, exist_ok=True)
    assert dest.parent.resolve() == dest.parent
    if dest.exists():
        assert dest.is_file() and not dest.is_symlink() and dest.read_bytes() == data
    else:
        with dest.open('xb') as stream:
            stream.write(data)
    assert dest.read_bytes() == data
    print(dest.relative_to(ROOT))


if __name__ == '__main__':
    main()
