"""Closed C maps-profile expansion; no general shell evaluation or guest authority."""
import hashlib
from pathlib import Path
from page_selected import need

SCRIPTS = ('build.sh', 'build-loop-decoder.sh', 'build-loop-effects-decoder.sh')
PROFILES = {
    'fresh-baseline': (),
    'maintained': ('-DLI2_MAPS_MAINTAINED=1',),
    'differential': ('-DLI2_MAPS_MAINTAINED=1', '-DLI2_MAPS_DIFFERENTIAL=1'),
}
BLOCK = '# Explicit default C maps profile; Rust feature selection above is unchanged.\ncase "${LI2_MAPS_PROFILE-maintained}" in\n  maintained) set -- -DLI2_MAPS_MAINTAINED=1 ;;\n  differential) set -- -DLI2_MAPS_MAINTAINED=1 -DLI2_MAPS_DIFFERENTIAL=1 ;;\n  fresh-baseline) set -- ;;\n  *) echo "unsupported maps profile" >&2; exit 2 ;;\nesac\n'
# One literal shared compiler tail, including quoting, "$@" position and EOF.
# Changing a recipe requires an explicit reviewed successor to this whole fact.
TAIL = (1598, '011acd381664447bcf7d22156726863d852abd4c973b0bfa2572bec079e3b7d2')


def configure(environment, profile):
    need(type(environment) is dict and 'LI2_MAPS_PROFILE' not in environment and
         (profile is None or type(profile) is str and profile in PROFILES),
         'closed explicit maps selection; no inherited override')
    if profile is not None:
        environment['LI2_MAPS_PROFILE'] = profile
    return dict(requested=profile, effective='maintained' if profile is None else profile,
                implicit_default=profile is None)


def extras(path, environment, rows):
    path = Path(path)
    if path.name not in SCRIPTS:
        need(all('$@' not in row for row in rows), 'no unbound C positional arguments')
        return [()] * len(rows)
    text = path.read_text()
    need(text.count(BLOCK) == 1, 'one exact supported maps-profile shell case')
    before, tail = text.split(BLOCK)
    need('LI2_MAPS_PROFILE' not in before and 'LI2_MAPS_PROFILE' not in tail and
         (len(tail.encode()), hashlib.sha256(tail.encode()).hexdigest()) == TAIL,
         'profile is selected once immediately before exact literal C commands')
    need(len(rows) == 3 and rows[0] == ['$cc_bin', '--version', '>', '$output_dir/cc-version.txt'] and
         rows[1].count('$@') == 1 and rows[2].count('$@') == 0 and
         rows[1][rows[1].index('$@')-1] == '-DLI2_MAPS_PHASE_REUSE=1',
         'maps positional arguments occur only in the shared bridge compiler recipe')
    profile = environment.get('LI2_MAPS_PROFILE', 'maintained')
    need(type(profile) is str and profile in PROFILES, 'same exact supported shell environment profile')
    return [(), PROFILES[profile], ()]
