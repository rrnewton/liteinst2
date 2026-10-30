"""Explicit physical/current/verified bridge builds using the unchanged owner.

No application execution occurs here. The enclosing evaluator supplies the old
bounded run/pin/binary/alias closure and retains every command and capture.
"""
from pathlib import Path
import shutil

import maps_view as donor
import maps_current_extents as extents


PROFILES = {
    'physical': ('MAPS_MAINTAINED',),
    'current': ('MAPS_MAINTAINED', 'MAPS_CURRENT_TF'),
    'verified': ('MAPS_MAINTAINED', 'MAPS_CURRENT_TF', 'MAPS_DIFFERENTIAL'),
}
CURRENT_HEADERS = ('maps_current_ticket.h', 'maps_current_ticket.inc',
                   'fetch_current_view.h', 'fetch_current_view.inc',
                   'fetch_current_custody.h', 'fetch_current_custody.inc')
PHYSICAL_HEADERS = ('fetch_loader.inc', 'fetch_rx_transfer.inc', 'fetch_page_custody.inc')


def bridges(builder, products, private, pin, binary, aliases, run, receipt):
    donor.need(builder.extra_decoder_sources == () and builder.decoder_features == () and
               builder.record['decoder_features'] == [], 'original default eight-source decoder')
    selected = donor.SELECTED
    observer = pin(selected / 'tests/current_custody/extents.py')
    pin(Path(__file__)); pin(Path(extents.__file__)); pin(Path(donor.__file__))
    states = receipt['current_bridge_builds'] = {}
    paths = {}
    for mode, extra in PROFILES.items():
        root = private / ('bridge-' + mode); root.mkdir()
        state = states[mode] = {'status': 'failed'}

        def mode_run(label, argv, **kwargs):
            return run(mode + '-' + label, argv, **kwargs)

        bridge = donor.build_bridge(builder, products, root, pin, binary, aliases, mode_run, state, extra)
        built = state['release_build']; headers = built['headers']
        donor.need(all(str((selected / p).resolve()) in headers for p in PHYSICAL_HEADERS),
                   'every original physical-custody body in actual compiler closure')
        donor.need(all((str((selected / p).resolve()) in headers) == (mode != 'physical')
                       for p in CURRENT_HEADERS), 'exact opt-in current-custody include closure')
        _, out, err = mode_run('current-storage-symbols',
                              [builder.tools['nm'], '-S', '--defined-only', bridge],
                              profile='inspect', env=builder.environment)
        donor.need(not err, 'whole actual symbol observation')
        names = [line.split()[-1] for line in out.decode('ascii').splitlines() if line.split()]
        donor.need(all(names.count(n) == int(mode != 'physical') for n in extents.NAMES),
                   'nine current objects present only in explicit current profiles')
        if mode != 'physical':
            gdb = pin(shutil.which('gdb', path=donor.ENV['PATH']))
            environment = dict(builder.environment, MALLOC_ARENA_MAX='1')
            _, out, err = mode_run('current-storage-layout',
                [gdb, '-q', '-nx', '-batch', '-iex', 'set auto-load off',
                 '-iex', 'set debuginfod enabled off', '-iex', 'set index-cache enabled off',
                 '-iex', 'maintenance set worker-threads 1', '--readnow', '--se=' + str(bridge),
                 '-x', observer], profile='inspect', env=environment)
            donor.need(not err, 'file-only complete storage layout without diagnostics')
            observation = extents.decode(out)
            state['storage_observation'] = observation
            state['storage_proof'] = extents.check(bridge, observation, headers)
            state['storage_controls'] = extents.controls(bridge, observation, headers)
        state['status'] = 'passed'; paths[mode] = bridge
    # Aside from explicit macros and each build's private output/include path,
    # every real translation unit, compiler option and archive is identical.
    def normalized(mode):
        argv = states[mode]['release_build']['argv']
        remove = {'-DLI2_' + m + '=1' for m in PROFILES[mode]}
        parent = str(private / ('bridge-' + mode))
        return [word.replace(parent, '@bridge') for word in argv if word not in remove]
    donor.need(normalized('physical') == normalized('current') == normalized('verified'),
               'identical original eighteen-unit production recipe after explicit profile projection')
    a = states['current']['storage_observation']['symbols']
    b = states['verified']['storage_observation']['symbols']
    donor.need({n: {k: v for k, v in d.items() if k != 'address'} for n, d in a.items()} ==
               {n: {k: v for k, v in d.items() if k != 'address'} for n, d in b.items()},
               'identical complete current/verified storage ABI, independent actual addresses')
    return paths
