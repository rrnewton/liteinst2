"""Actual include closure for the separate scalar-read archive build recipe."""
from page_selected import need
from page_selected_oneshot_build import before_default, commands, UNITS, PRODUCT, BUILD
from page_selected_register_time_build import headers


def before_loop_default(label, argv, builder, pin, aliases, run, receipt):
    if label != 'selected-build':
        return before_default(label, argv, builder, pin, aliases, run, receipt)
    script = PRODUCT/'build-loop-decoder.sh'
    need(list(map(str, argv)) == [str(builder.tools['sh']), str(script)] and
         builder.extra_decoder_sources == ('region.rs', 'mov_guard.rs', 'scalar_read.rs') and
         builder.decoder_features == ('scalar-region', 'scalar-span', 'linked-epoch', 'mov-guard', 'scalar-read') and
         builder.environment['LI2_DECODER_FEATURES'] == 'scalar-read,mov-guard',
         'exact separate eleven-source scalar-read archive command and features')
    rows = commands(script, builder, BUILD, BUILD/'decoder.a', pin)
    need(rows == commands(PRODUCT/'build.sh', builder, BUILD, BUILD/'decoder.a', pin),
         'both complete C compiler recipes remain equal to the original default build')
    expected = [[str(PRODUCT.parent/x) for x in UNITS[:8]], [str(PRODUCT/'fixture_observe.c')]]
    state = receipt['default_include_closure'] = []
    for i, (command, units) in enumerate(zip(rows, expected, strict=True)):
        row = {'argv': command}; state.append(row)
        headers('default-headers-'+str(i), command, units, BUILD/'decoder.a',
                builder, pin, aliases, run, row)
