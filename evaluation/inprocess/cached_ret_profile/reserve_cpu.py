"""Reserve the historical CPU from broad affinity, retaining the hard-pin probe."""
import argparse
import os
from pathlib import Path
import sys

ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--agent-utils', type=Path, required=True)
ap.add_argument('command', nargs=argparse.REMAINDER)
args = ap.parse_args()
command = args.command[1:] if args.command[:1] == ['--'] else args.command
assert command and not sys.flags.optimize
original = os.sched_getaffinity(0)
assert 3 in original and len(original) > 1, 'the allocator escape probe needs broad parent affinity'
sys.path.insert(0, str(args.agent_utils.resolve(strict=True)/'py'))
from dagrun import cpuset_allocator, reservation

with reservation.reserve_cores(1, tag='cached-ret-profile', sample_s=.3,
                               exclude=original-{3}) as cores:
    assert list(cores) == [3] and os.sched_getaffinity(0) == original
    result = cpuset_allocator._run_reserved_hard(
        cores, command, tag='cached-ret-profile', prog='cached-ret-profile')
raise SystemExit(result)
