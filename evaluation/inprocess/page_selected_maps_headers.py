"""Observe actual macro-enabled recipe dependencies before each C compilation."""
from pathlib import Path
import shlex
from page_selected import fact, need


def observe(recipe, substitutions, prefix, label, builder, pin, run, receipt, aliases):
    # These pinned recipes contain only literal compiler lines after shell
    # continuation joining. Substitute the same closed values as their builds.
    lines = [line.strip() for line in recipe.read_text().replace('\\\n', ' ').splitlines()
             if line.strip().startswith('"$cc_bin" ') and '-o' in shlex.split(line)]
    need(lines, 'actual C compiler recipe present')
    rows = receipt.setdefault('header_observations', [])
    for index, line in enumerate(lines):
        argv = []
        for word in shlex.split(line):
            for old, new in sorted(substitutions.items(), key=lambda x: -len(x[0])):
                word = word.replace(old, str(new))
            need('$' not in word and '`' not in word, 'closed actual compiler substitutions')
            argv.append(word)
        need(argv[0] == str(builder.tools['cc']) and argv.count('-o') == 1 and
             argv[-2] == '-o', 'actual compiler and final output option')
        sources = [x for x in argv[1:-2] if x.endswith(('.c', '.S'))]
        need(sources and len(sources) == len(set(sources)) and all(Path(x).is_absolute() for x in sources),
             'exact distinct translation units')
        flags = [x for x in argv[1:-2] if x not in sources and not x.endswith(('.a', '.o')) and
                 not x.startswith('-Wl,') and x != '-c']
        target = 'li2_maps_headers'
        row = dict(recipe=str(recipe), recipe_bytes=fact(recipe), argv=argv, wrapper_prefix=prefix,
                   sources=sources, complete=False)
        rows.append(row)
        _, out, err = run(label+'-'+str(index), [builder.tools['cc'], *prefix, *flags,
                         '-M', '-MT', target, *sources], profile='metadata', env=builder.environment)
        need(not err, 'actual macro-enabled header observation stderr')
        rules = out.decode().replace('\\\n', ' ').splitlines()
        need(len(rules) == len(sources) and all(x.startswith(target+': ') for x in rules),
             'one complete actual dependency rule per translation unit')
        deps = set()
        for source, rule in zip(sources, rules):
            names = shlex.split(rule.split(':', 1)[1])
            need(source in names and all(Path(x).is_absolute() for x in names), 'actual source and absolute dependency paths')
            deps.update(names)
        row['headers'] = {}
        for name in sorted(deps):
            resolved = str(Path(name).resolve(strict=True));value = fact(pin(resolved))
            need(name not in aliases or aliases[name] == resolved, 'header path resolution changed')
            aliases[name] = resolved
            row['headers'][name] = dict(resolved=resolved, **value)
        need(set(sources) <= deps, 'every linked translation unit in actual dependency closure')
        if '-DLI2_MAPS_PHASE_REUSE=1' in prefix+flags:
            need(any(x.endswith('/maps_phase.h') for x in deps), 'actual macro header included')
            if any(x.endswith('/lifecycle_loader.c') for x in sources):
                need(all(any(x.endswith(tail) for x in deps) for tail in
                         ('/maps_phase.inc', '/asm/prctl.h', '/linux/prctl.h')),
                     'actual conditional implementation and external prctl headers')
        row['complete'] = True
