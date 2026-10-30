#!/usr/bin/env python3
"""Fixed v6 D01 route; independent artifact/native/performance gates stay false."""
PROFILE = 'offline-whole-authored-adjacent-routed-jmp-short-t3-pending-2g-v1'
COLLECTOR_SHA = 'b8e61360056220b1e2a60f93f32844b36e483d08a354bccbf6b03f1a8288c4a3'


def run(args, ctx):
    assert args.placement_profile == PROFILE, 'explicit routed-JMP diagnostic profile'
    collector = ctx.load('adjacent_whole.py', COLLECTOR_SHA)
    return collector.run(args, ctx, collector.ROUTED)
