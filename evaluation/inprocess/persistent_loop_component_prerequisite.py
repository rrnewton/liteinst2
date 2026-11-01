"""Whole five-component custody joined to the program's fresh scalar-read archive."""
import os
from pathlib import Path
import re
import shlex

from page_selected import ENV, fact, need
from persistent_dynamic import digest
from direct_frontier_program import decode
from loop_components import run as component

ROOT = Path(__file__).resolve().parents[2]
SELECTED = ROOT/'tools/page-entry/selected'
ORDER = ('scalar_span_metadata', 'scalar_read', 'loop_envelope', 'bounded_fusion_plan', 'loop_plan')
UNIT_COUNTS = (3, 2, 3, 9, 11)


def prerequisite(path, expected_sha256, r, pin, binary, archive):
    path = pin(path)
    need(path.name == 'receipt.json' and path.parent.parent == ROOT/'target/evaluation/inprocess' and
         re.fullmatch('[0-9a-f]{64}', expected_sha256) is not None and
         fact(path)['sha256'] == expected_sha256, 'explicit whole private loop component receipt')
    a = decode(path.read_bytes()); receipt = path; directory = path.parent
    need(a['schema'] == 1 and a['profile'] == 'experimental-loop-components-v1' and
         a['status'] == 'components_passed' and a['source'] == r['source'] and a['revision'] == r['revision'] and
         a['cpu'] == r['cpu'] and a['hardware'] == r['hardware'] and a['bounds'] == component.BOUNDS and
         a['source_unchanged'] is True and a['inputs_unchanged'] is True and a['cleanup_complete'] is True and
         a['error'] is None and a['final_errors'] == [] and a['archive_builds'] == 0 and
         a['archive_source_provenance_verified'] is False and a['generated_execution'] == a['native_execution'] == 0 and
         a['owner_credit'] is a['qualification_credit'] is a['performance_credit'] is False,
         'whole same-source same-CPU component result without native or owner credit')
    for name, value in a['inputs'].items():
        need(component.fact(pin(name)) == value, 'whole component input and mode')
    for name, value in a['artifacts'].items():
        p = binary(name)
        need(p.is_relative_to(directory) and component.fact(p) == value, 'whole private component artifact')
    for name, value in a['aliases'].items():
        need(str(pin(name)) == value, 'whole component alias closure')
    for name, value in a['loader_presence'].items():
        need(Path(name).exists() == value, 'component loader configuration presence')
    module = pin(component.__file__)
    need(component.fact(module) == a['inputs'][str(module)], 'current complete component validator is the actual input')
    need({k: a['archive'][k] for k in ('bytes', 'sha256')} == fact(archive),
         'whole supplied component archive equals the freshly built scalar-read archive')
    need(tuple(component.CASES) == ORDER and set(a['components']) == set(ORDER),
         'all five original/additive component populations, with no substituted case')
    schedule = ['tool-'+n+'-dependencies' for n in ('cc', 'nm', 'python', 'git')]
    for n in ('cc1', 'collect2', 'as', 'ld'):
        schedule += ['resolve-'+n, 'tool-'+n+'-dependencies']
    schedule += ['version-'+n for n in ('cc', 'as', 'ld', 'nm', 'python', 'git')]
    schedule += ['link-'+n for n in component.LINK_NAMES]
    schedule += ['compiler-specs', 'archive-exports']
    for name in ORDER:
        schedule += [name+'-'+suffix for suffix in ('headers', 'build', 'dependencies', 'component')]
    rows = a['commands']
    need([x['name'] for x in rows] == schedule and len(set(schedule)) == len(schedule) == 60,
         'entire fixed five-component60-command schedule')
    observed = {}
    for row in rows:
        kind = 'component' if row['name'] in {n+'-component' for n in ORDER} else 'build'
        need(type(row['exit']) is int and row['expected_exit'] == row['exit'] == 0 and
             row['bounds'] == component.BOUNDS[kind] and row['capture_limit'] == 16 << 20 and
             row['environment'] == ENV and row['reaped'] is True and row['timed_out'] is False and
             row['error'] is None and row['cleanup_errors'] == [] and
             all(d['closed'] is True for d in row['descriptors']) and set(row['captures']) == {'stdout', 'stderr'},
             'every original bounded component child succeeded and completely reaped')
        streams = {}
        for key, value in row['captures'].items():
            p = pin(directory/value['file'])
            need(p.is_relative_to(directory) and fact(p) == {k: value[k] for k in ('bytes', 'sha256')},
                 'whole actual component capture')
            streams[key] = p.read_bytes()
        need(decode(pin(directory/(row['name']+'.json')).read_bytes()) == row,
             'whole retained actual component command row')
        observed[row['name']] = streams
    commands = {row['name']: row for row in rows}
    for name, count in zip(ORDER, UNIT_COUNTS, strict=True):
        case = a['components'][name]; declared = component.CASES[name]
        fixture = SELECTED/'tests'/declared.get('recipe_fixture', name)
        recipe = pin(fixture/'build.sh')
        need(case['status'] == 'passed' and case['recipe'] == component.fact(recipe) and
             fact(recipe)['sha256'] == declared['recipe_sha256'] and
             case['diagnostic_only_additions'] == ['-save-temps=obj', '-Wl,--trace'],
             'actual complete immutable component recipe and diagnostic-only additions')
        units = [str(SELECTED/x) for x in declared['units']]
        output_dir = directory/name; output = output_dir/declared.get('output_leaf', 'component')
        argv = case['original_argv']; archives = [x for x in argv if x.endswith('.a')]
        need(len(archives) == 1 and archives[0] in a['inputs'] and
             component.fact(pin(archives[0])) == a['archive'], 'one whole prebound supplied archive')
        lines = [line.strip() for line in recipe.read_text().replace('\\\n', ' ').splitlines()
                 if line.strip().startswith('"$cc_bin" ')]
        need(len(lines) == 1, 'one complete source-owned compiler recipe')
        replacements = {'$cc_bin': a['tools']['cc'], '$fixture': fixture, '$selected': SELECTED,
            '$archive': archives[0], '$output': output_dir if declared.get('output_directory') else output,
            '$root': ROOT, '$chooser': SELECTED, '$scalar': SELECTED, '$overlay': SELECTED,
            '$kind': 'metadata', '$support': SELECTED/'tests/decoder/support.c'}
        expanded = []
        for word in shlex.split(lines[0]):
            for key, value in replacements.items():
                word = word.replace(key, str(value))
            need('$' not in word and '`' not in word, 'closed exact compiler word')
            expanded.append(word)
        need(argv == expanded and argv[-2:] == ['-o', str(output)] and
             [x for x in argv if x.endswith(('.c', '.S'))] == units and
             len({Path(x).stem for x in units}) == len(units) == count,
             'complete original ordered recipe and distinct actual translation units')
        flags = [x for x in argv[1:-2] if x not in units and not x.endswith('.a') and not x.startswith(('-Wl,', '-l'))]
        need(commands[name+'-headers']['argv'] == [a['tools']['cc'], *flags, '-M', '-MT', 'call_component', *units] and
             commands[name+'-build']['argv'] == argv[:-2]+case['diagnostic_only_additions']+argv[-2:] and
             commands[name+'-component']['argv'] == [str(output)],
             'actual compiler-M/build/finite invocation exactly matches the complete recipe')
        captured = observed[name+'-headers']
        rules = captured['stdout'].decode().replace('\\\n', ' ').splitlines()
        need(not captured['stderr'] and len(rules) == count and all(x.startswith('call_component: ') for x in rules),
             'every actual complete compiler-M rule')
        headers = {str(pin(x)) for line in rules for x in shlex.split(line.split(':', 1)[1])}
        need(headers == set(case['headers']) and {str(pin(x)) for x in units} |
             {str(pin(SELECTED/x)) for x in declared['headers']} <= headers, 'whole actual compiler source/header closure')
        trace = observed[name+'-build']
        need(not trace['stderr'], 'all original compiler warning/error checks retained')
        linked = {str(Path(x).resolve(strict=True)) for x in trace['stdout'].decode().splitlines()}
        need(linked == set(case['link_inputs']) and str(pin(archives[0])) in linked and
             all(str((output_dir/(output.name+'-'+Path(p).stem+'.o')).resolve()) in linked for p in units),
             'whole actual link trace includes every generated object and the supplied archive')
        for p in units:
            for suffix in ('.i', '.s', '.o', '.su'):
                path = output_dir/(output.name+'-'+Path(p).stem+suffix)
                need(component.fact(binary(path)) == a['artifacts'][str(path)], 'whole actual compiler intermediate')
        need(component.fact(binary(output)) == case['binary'] and component.elf(output) == case['elf'],
             'actual complete component ELF and binary identity')
        for path, value in case['runtime_objects'].items():
            need(component.elf(pin(path)) == value, 'actual component runtime ELF closure')
        final = observed[name+'-component']
        need(component.component_result(name, final['stdout'], final['stderr']) == case['result'],
             'whole literal independent component result including every original model/control')
    for objects in a['tool_runtime'].values():
        for path, value in objects.items():
            need(component.elf(pin(path)) == value, 'whole actual compiler/tool runtime ELF closure')
    return dict(file=str(receipt.relative_to(ROOT)), **fact(receipt),
        status=a['status'], profile=a['profile'], archive=fact(archive),
        commands=len(rows), commands_sha256=digest(rows),
        results={name: a['components'][name]['result'] for name in ORDER},
        supplied_archive_provenance=False, fresh_program_archive_bytes_joined=True,
        emitted_execution=0, native_execution=0, owner_credit=False, qualification_credit=False, performance_credit=False)
