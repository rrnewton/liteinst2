"""Supplied process-profile controls; never launch a child."""
from pathlib import Path
from unittest.mock import patch


def controls(dynamic):
    native = {'cpu_seconds': 3, 'address_space_bytes': 256 * 1024**2,
              'capture_file_bytes': 1024**2, 'wall_seconds': 10}
    build = {'cpu_seconds': 30, 'address_space_bytes': 1024**3,
             'capture_file_bytes': 16 * 1024**2, 'wall_seconds': 60}
    assert dynamic.command_bounds() == native
    assert dynamic.command_bounds(build=True) == build
    detached = dynamic.command_bounds()
    detached['cpu_seconds'] = 1
    assert dynamic.command_bounds() == native
    profile = native | {'capture_file_bytes': 8 * 1024**2, 'process_count': 1}
    assert dynamic.command_bounds(bounds=profile) == profile
    invalid = [({}, False), (profile | {'extra': 1}, False), (profile, True),
               (dict(profile, process_count=True), False), (dict(profile, cpu_seconds=0), False),
               (dict(profile, wall_seconds=-1), False), (dict(profile, capture_file_bytes=1.5), False),
               (dict(profile, address_space_bytes=2**63), False)]
    names = ['native_default', 'build_default', 'detached_default', 'explicit_abi_profile']
    with patch.object(dynamic.subprocess, 'Popen', side_effect=AssertionError('unexpected Popen')) as popen, \
            patch.object(Path, 'open', side_effect=AssertionError('unexpected capture open')) as opened:
        for index, (value, is_build) in enumerate(invalid):
            try:
                dynamic.invoke(['must-not-run'], {}, Path('.'), Path('.'), 'invalid', 0,
                               build=is_build, bounds=value)
            except dynamic.Refusal as error:
                assert str(error) == 'invalid_bounds_override'
            else:
                raise AssertionError('invalid override accepted')
            names.append('invalid_before_popen_' + str(index))
        popen.assert_not_called()
        opened.assert_not_called()
    return names
