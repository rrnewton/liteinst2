#!/usr/bin/env python3
"""Fabricated plans/closure transitions only; no native or lifecycle proof."""
import sys
if not __debug__:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

_path = Path(__file__).resolve().with_name('reproduce.py')
_spec = importlib.util.spec_from_file_location('_selected_driver_controls', _path)
assert _spec is not None and _spec.loader is not None
driver = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(driver)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def source_fixture():
    rev = 'a' * 40
    files = {name: ('old bytes: ' + name).encode('ascii') for name in (
        '.cargo/config.toml', 'Cargo.toml', 'Cargo.lock', 'build.rs', 'src/lib.rs',
        'crates/helper/src/lib.rs', 'tools/rapid-profiler/ordinary-interval/main.rs',
        'evaluation/ordinary-selected-session/leaves.c',
        'evaluation/ordinary-selected-session/reference.c',
        'evaluation/ordinary-selected-session/oracle.py')}
    pins = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    build = dict(revision=rev, sources=pins)
    current = {str(driver.ROOT / name): {'sha256': digest} for name, digest in pins.items()}
    compiled = tuple(name for name in files if not name.endswith('/oracle.py'))
    return build, current, Git(rev, files, compiled)


class Git:
    def __init__(self, revision, files, compiled):
        self.revision, self.files = revision, dict(files)
        self.members, self.before, self.after = list(files), list(compiled), list(compiled)
        self.calls = []

    def __call__(self, *args):
        self.calls.append(args)
        if args == ('ls-tree', '-r', '--name-only', '-z', self.revision, '--',
                    '.cargo', 'src', 'crates', 'tools', 'Cargo.toml', 'Cargo.lock',
                    'build.rs', 'evaluation/ordinary-selected-session'):
            names = self.members
        elif len(args) == 2 and args[0] == 'show':
            prefix = self.revision + ':'
            assert args[1].startswith(prefix)
            return self.files[args[1][len(prefix):]]
        else:
            roots = ('.cargo', 'src', 'crates', 'tools', 'Cargo.toml', 'Cargo.lock', 'build.rs',
                     'evaluation/ordinary-selected-session/leaves.c',
                     'evaluation/ordinary-selected-session/reference.c')
            if args == ('ls-tree', '-r', '--name-only', '-z', self.revision, '--', *roots):
                names = self.before
            else:
                assert args == ('ls-files', '-z', '--', *roots)
                names = self.after
        return ('\0'.join(names) + '\0').encode('ascii')


class Recipe:
    canonical = staticmethod(canonical)

    def __init__(self, files):
        self.files = files

    def read(self, path, cap):
        assert cap == 1048576
        data = self.files[str(path)]
        assert len(data) <= cap
        return data

    @staticmethod
    def bounded_ready(run, request, app_files=False):
        assert run.safe and app_files is True
        assert request is run.rows[request['name']]['request']
        run.events.append(('ready', request['name']))


class Run:
    def __init__(self, modes):
        self.raw, self.safe = Path('/fabricated/selected'), True
        self.result = {'cells': driver.initial_rows()}
        self.modes, self.events, self.outcomes = dict(modes), [], {}
        self.rows, self.files = {}, {}
        for row in self.result['cells']:
            name = row['name']
            row.update(plan=str(self.raw / 'plans' / (name + '.json')),
                       directory=str(self.raw / (name + '-io')),
                       child=str(self.raw / (name + '-child')),
                       request={'name': name, 'argv': ['/fabricated/not-executed', name]})
            self.rows[name] = row
            self.files[row['plan']] = canonical({'name': name, 'leg': row['leg'], 'index': row['index']})

    def unchanged(self):
        assert self.safe
        self.events.append(('unchanged',))

    def bounded(self, name, directory, request, app_files=False):
        cell = request['name']
        assert name == cell + '-owner' and directory == Path(self.rows[cell]['directory'])
        assert request is self.rows[cell]['request'] and app_files is True
        assert not any(event == ('bounded', cell) for event in self.events)
        self.events.append(('bounded', cell))
        if self.modes.get(cell) == 'outer-uncertain':
            self.safe = False
            raise RuntimeError('fabricated unknown outer closure')
        return (1 if self.modes.get(cell) == 'FAILED' else 0), cell.encode('ascii'), b''

    def freeze(self, path, value):
        assert self.safe and path == self.raw / (value['name'] + '-outcome.json')
        assert str(path) not in self.outcomes
        self.outcomes[str(path)] = copy.deepcopy(value)


class Closure:
    @staticmethod
    def complete_closed_cell(run, recipe, producer, oracle, output, plan, child, code, stdout, stderr):
        # This models only the driver's transition after an existing closure join.
        # It is not a substitute for the real closure/wire/custody controls.
        name = plan['name']
        assert run.safe and child == Path(run.rows[name]['child'])
        assert stdout == name.encode('ascii') and stderr == b''
        assert plan == {'name': name, 'leg': run.rows[name]['leg'], 'index': run.rows[name]['index']}
        run.safe = False
        run.events.append(('join', name))
        mode = run.modes.get(name, 'PASS')
        if mode == 'child-uncertain':
            raise RuntimeError('fabricated unknown child closure')
        assert mode in ('PASS', 'FAILED') and code == (0 if mode == 'PASS' else 1)
        run.safe = True
        return dict(status=mode, result=dict(child_exit=0 if mode == 'PASS' else 101, normal_reaps=1),
                    observations=None if mode == 'FAILED' else dict(
                        values=[[plan['index'], int(plan['leg'] == 'installed'), 99]],
                        totals={'fabricated_cell_index': plan['index']}),
                    error=None if mode == 'PASS' else 'retained fabricated refusal')


def execution(modes=None):
    run = Run({} if modes is None else modes)
    new = dict(closure=Closure(), producer=object(), oracle=object(), output=object())
    return run, Recipe(run.files), new


class Controls(unittest.TestCase):
    def test_initial_rows_are_exact_eight_once_only_cells(self):
        rows = driver.initial_rows()
        expected = []
        for leg in ('reference', 'installed'):
            for index, variant, k, records, calls in (
                    (0, 'unstripped', 10, 12, 24), (1, 'unstripped', 1000, 1001, 2002),
                    (2, 'stripped', 10, 12, 24), (3, 'stripped', 1000, 1001, 2002)):
                expected.append(dict(leg=leg, index=index, variant=variant, k=k, n=2, epochs=520,
                                     name=f'{leg}-{variant}-k{k}', status='UNRUN', attempts=0,
                                     attempt_limit=1, retries=0, records=records, calls=calls))
        self.assertEqual(rows, expected)
        self.assertEqual(len({row['name'] for row in rows}), 8)
        self.assertEqual([sum(row['calls'] for row in rows if row['leg'] == leg)
                          for leg in ('reference', 'installed')], [4052, 4052])
        rows[0]['status'] = 'FAILED'
        self.assertEqual(driver.initial_rows(), expected)

    def test_build_argv_keeps_all_twelve_exact_commands_and_flags(self):
        tools = {name: {'path': '/fabricated/tools/' + name}
                 for name in ('gcc', 'strip', 'cargo', 'readelf', 'objdump')}
        products = Path('/fabricated/products')
        expected = [
            [tools['gcc']['path'], '-O2', '-std=c11', '-Wall', '-Wextra', '-Werror', '-fPIC',
             '-shared', '-nostdlib', '-fno-stack-protector', '-fno-asynchronous-unwind-tables',
             '-fno-unwind-tables', '-fno-tree-vectorize', '-fno-tree-slp-vectorize', '-fno-builtin',
             '-fno-ipa-icf', '-fno-toplevel-reorder', '-fno-jump-tables', '-fcf-protection=none',
             '-Wl,--build-id=none,-z,now,-z,noexecstack', str(driver.HERE / 'leaves.c'), '-o',
             '/fabricated/products/leaves.so'],
            [tools['strip']['path'], '--strip-all', '-o', '/fabricated/products/leaves-stripped.so',
             '/fabricated/products/leaves.so'],
            [tools['gcc']['path'], '-O2', '-std=c11', '-Wall', '-Wextra', '-Werror',
             '-fno-stack-protector', '-fno-optimize-sibling-calls', '-fcf-protection=none',
             str(driver.HERE / 'reference.c'), '-ldl', '-o', '/fabricated/products/reference'],
            [tools['cargo']['path'], 'build', '--release', '-p', 'rapid-profiler', '--bin',
             'ordinary-interval', '--locked', '--offline', '--jobs', '4',
             '--message-format=json-render-diagnostics'],
        ]
        files = ('leaves.so', 'leaves-stripped.so', 'reference', 'ordinary-interval')
        for name in files:
            expected.append([tools['readelf']['path'], '--wide', '--file-header', '--program-headers',
                             '--section-headers', '--symbols', '/fabricated/products/' + name])
        for name, symbol in zip(files, (None, None, 'invoke', 'liteinst_csv_call_and_store')):
            expected.append([tools['objdump']['path'], '-d', '-M', 'intel', '--insn-width=16',
                             *([] if symbol is None else ['--disassemble=' + symbol]),
                             '/fabricated/products/' + name])
        self.assertEqual(driver.build_argv(tools, products), expected)
        self.assertEqual(len(expected), 12)
        self.assertEqual(driver.BUILD_STAGES,
                         ('dso-unstripped', 'dso-stripped', 'original-reference', 'application-release',
                          'leaves.so-elf', 'leaves-stripped.so-elf', 'reference-elf', 'ordinary-interval-elf',
                          'leaves.so-disassembly', 'leaves-stripped.so-disassembly',
                          'reference-disassembly', 'ordinary-interval-disassembly'))

    def test_source_join_checks_every_old_pin_and_exact_compiled_membership(self):
        build, current, git = source_fixture()
        current[str(driver.ROOT / 'evaluation/ordinary-selected-session/new_helper.py')] = {'sha256': 'b' * 64}
        driver.source_build_join(build, current, git)
        self.assertEqual(len(git.calls), 3 + len(build['sources']))
        for path in build['sources']:
            for drift in ('old-blob', 'current-pin'):
                build, current, git = source_fixture()
                if drift == 'old-blob':
                    git.files[path] += b' changed'
                else:
                    current[str(driver.ROOT / path)]['sha256'] = '0' * 64
                with self.assertRaises(AssertionError, msg=path + '/' + drift):
                    driver.source_build_join(build, current, git)
        for drift in ('missing-pin', 'extra-pin', 'duplicate-member', 'empty-members',
                      'missing-compiled', 'extra-compiled'):
            build, current, git = source_fixture()
            if drift == 'missing-pin': del build['sources']['src/lib.rs']
            elif drift == 'extra-pin': build['sources']['not-listed.rs'] = '0' * 64
            elif drift == 'duplicate-member': git.members.append(git.members[0])
            elif drift == 'empty-members': git.members = []
            elif drift == 'missing-compiled': git.after.remove('src/lib.rs')
            else: git.after.append('src/new.rs')
            with self.assertRaises(AssertionError, msg=drift):
                driver.source_build_join(build, current, git)

        # Exercise the real shared census; all old and accuracy names execute.
        leaf = driver.load('_selected_roster_leaf', driver.ROOT / 'evaluation/ordinary-leaf-set-session/reproduce.py')
        recipe = driver.load('_selected_roster_recipe', driver.ROOT / 'evaluation/ordinary-module-session/reproduce.py')
        single = driver.load('_selected_roster_single', driver.ROOT / recipe.MODULES['single'])
        module = driver.load('_selected_roster_module', driver.ROOT / recipe.MODULES['module'])
        modules = {'single': single, 'module': module}
        prior = (tuple(single.SESSION) + tuple(single.TRACE) + recipe.CONSUMER +
                 tuple(module.MODULE_TESTS) + tuple(module.CSV_TESTS) + recipe.OWNER_CONTROLS + recipe.REUSE_CONTROLS)
        old = prior + leaf.APP_CONTROLS[:16]
        accuracy = (
            'normal::leaf_set::accuracy_tests::accuracy_ready_binds_actual_period_and_old_headers_remain_literal',
            'normal::leaf_set::accuracy_tests::consumer_refuses_legacy_substitution_wrong_k_epochs_calls_or_transport_options',
            'normal::leaf_set::accuracy_tests::arm_wire_keeps_actual_observations_and_late_completed_arms',
            'normal::leaf_set::selected::accuracy_tests::full_matrix_preserves_every_selected_function_and_full_input_denominator',
            'normal::leaf_set::selected::accuracy_tests::invalid_accuracy_profile_and_selection_refuse_before_table_loading',
            'normal::leaf_set::selected::accuracy_tests::table_refusal_remains_terminal_and_old_parser_does_not_accept_new_k_or_grammar',
            'normal::leaf_set::counter::tests::failed_acquisition_and_close_keep_all_raw_attribute_bytes_and_absences',
            'normal::leaf_set::counter::tests::short_and_failed_reads_preserve_return_errno_length_buffer_and_both_clocks',
            'normal::leaf_set::counter::tests::numeric_extremes_fit_350_without_scaling_id_loss_or_debug_fields',
            'normal::session::io::accuracy_tests::complete_rosters_fit_only_the_explicit_accuracy_output_capacity',
            'normal::session::io::accuracy_tests::both_caps_refuse_one_byte_over_without_discarding_pending_output',
        )
        self.assertEqual(leaf.ACCURACY_CONTROLS, accuracy)
        self.assertEqual(leaf.APP_CONTROLS[16:27], accuracy)
        self.assertEqual(len(old), 68)
        self.assertEqual(len(driver.SELECTED_RUST), 24)
        self.assertEqual(len(accuracy), 11)
        wanted = prior + leaf.APP_CONTROLS + driver.SELECTED_RUST
        inventory = list(wanted) + ['unrelated::test']
        with patch.object(leaf, 'ordinary_inventory', wraps=leaf.ordinary_inventory) as inherited:
            self.assertEqual(driver.selected_inventory(inventory, leaf, recipe, modules), wanted)
            inherited.assert_called_once_with(inventory, recipe, single, module)
        self.assertEqual(len(wanted), 112)
        self.assertEqual(set(wanted), set(old + driver.SELECTED_RUST + accuracy + leaf.PHASE_CONTROLS))
        for name in wanted:
            for changed in ([n for n in inventory if n != name], inventory + [name]):
                with self.assertRaises(AssertionError, msg=name):
                    driver.selected_inventory(changed, leaf, recipe, modules)
        with self.assertRaises(AssertionError):
            driver.selected_inventory(list(old + driver.SELECTED_RUST), leaf, recipe, modules)
        self.assertEqual(len(leaf.PHASE_CONTROLS),9)
        self.assertEqual(leaf.APP_CONTROLS[27:],leaf.PHASE_CONTROLS)
        with self.assertRaises(AssertionError):
            driver.selected_inventory(list(old+driver.SELECTED_RUST+accuracy),leaf,recipe,modules)
        prefixes = leaf.PHASE_PREFIXES + ('normal::leaf_set::accuracy_tests::',
                    'normal::leaf_set::selected::accuracy_tests::',
                    'normal::leaf_set::counter::tests::',
                    'normal::session::io::accuracy_tests::',
                    'normal::leaf_set::tests::', 'normal::session::io::tests::',
                    'normal::selected_session_controls::')
        for prefix in prefixes:
            with self.assertRaises(AssertionError, msg=prefix):
                driver.selected_inventory(inventory + [prefix + 'unregistered'], leaf, recipe, modules)
        for name in accuracy:
            changed = [n if n != name else name.rsplit('::', 1)[0] + '::unregistered' for n in inventory]
            with self.assertRaises(AssertionError, msg=name):
                driver.selected_inventory(changed, leaf, recipe, modules)

    def test_symbol_suffix_keeps_every_contiguous_byte_and_refuses_bad_headers(self):
        prefix = b'ELF Header:\n  Machine: Advanced Micro Devices X86-64\n\nSection Headers:\n  data\n'
        suffix = (b"Symbol table '.dynsym' contains 3 entries:\nall dynamic rows\n\n"
                  b"Symbol table '.symtab' contains 7 entries:\nall static rows\ntrailing bytes\n")
        raw = prefix + suffix
        self.assertEqual(driver.symbol_suffix(raw), suffix)
        for bad in (b'', suffix, b'prefix\n' + raw, raw.replace(b'ELF Header:\n', b'ELF Header:\r\n'),
                    raw.replace(b"'.dynsym'", b"'.wrong'"), raw + b'\n' + suffix):
            with self.assertRaises(AssertionError):
                driver.symbol_suffix(bad)

    def test_copy_source_substitution_refuses_before_identity_or_copy(self):
        original, changed = b'original retained DSO', b'changed but stable DSO'
        def pin(data):
            return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
        for data, retained, build_pin in (
                (changed, pin(original), pin(original)),
                (original, pin(changed), pin(original)),
                (original, pin(original), pin(changed))):
            run = type('CopyRun', (), {})()
            run.raw = Path('/fabricated/copies')
            run.retained = {'/fabricated/build/products/leaves.so': retained}
            recipe = type('CopyRecipe', (), {})()
            reads = []
            def read(path, cap):
                self.assertEqual((path, cap), (Path('/fabricated/build/products/leaves.so'), 1048576))
                reads.append(path)
                return data
            recipe.read, recipe.pin = read, pin
            # No filesystem operation is allowed; removing the pin check must
            # fail this test with RuntimeError rather than accidentally refuse.
            with patch.object(driver.Path, 'mkdir') as mkdir, \
                    patch.object(driver.Path, 'stat', side_effect=RuntimeError('identity before byte join')) as stat, \
                    patch.object(driver, 'write_blob', side_effect=RuntimeError('copy before byte join')) as write:
                with self.assertRaises(AssertionError):
                    driver.freeze_cells(run, recipe, {}, {'products': {'leaves.so': build_pin}},
                                        Path('/fabricated/build/result.json'), (), {})
                mkdir.assert_called_once_with()
                stat.assert_not_called()
                write.assert_not_called()
            self.assertEqual(reads, [Path('/fabricated/build/products/leaves.so')])

    def test_execute_all_eight_cells_once_after_all_references_pass(self):
        run, recipe, new = execution()
        self.assertTrue(driver.execute_cells(run, recipe, new))
        cells = run.result['cells']
        self.assertEqual([event[1] for event in run.events if event[0] == 'bounded'],
                         [row['name'] for row in cells])
        self.assertTrue(all(row['status'] == 'PASS' and row['attempts'] == 1 for row in cells))
        self.assertEqual(len(run.outcomes), 8)
        for row in cells:
            values = [[row['index'], int(row['leg'] == 'installed'), 99]]
            self.assertEqual(row['values_sha256'], hashlib.sha256(canonical(values)).hexdigest())
            self.assertEqual(row.get('totals'), {'fabricated_cell_index': row['index']}
                             if row['leg'] == 'installed' else None)
        events = copy.deepcopy(run.events)
        with self.assertRaises(AssertionError):
            driver.execute_cells(run, recipe, new)
        self.assertEqual(run.events, events)

    def test_reference_failure_is_retained_and_all_installed_cells_stay_unrun(self):
        failed = 'reference-unstripped-k1000'
        run, recipe, new = execution({failed: 'FAILED'})
        original_installed = copy.deepcopy(run.result['cells'][4:])
        self.assertFalse(driver.execute_cells(run, recipe, new))
        self.assertEqual([row['status'] for row in run.result['cells'][:4]], ['PASS', 'FAILED', 'PASS', 'PASS'])
        self.assertTrue(all(row['attempts'] == 1 for row in run.result['cells'][:4]))
        self.assertEqual(run.result['cells'][4:], original_installed)
        row = run.rows[failed]
        self.assertEqual((row['error'], row['child_exit'], row['normal_reaps']),
                         ('retained fabricated refusal', 101, 1))
        self.assertNotIn('values_sha256', row)
        self.assertEqual(len(run.outcomes), 4)

    def test_closed_installed_failure_keeps_later_single_attempts(self):
        failed = 'installed-unstripped-k10'
        run, recipe, new = execution({failed: 'FAILED'})
        self.assertFalse(driver.execute_cells(run, recipe, new))
        cells = run.result['cells']
        self.assertEqual([row['status'] for row in cells], ['PASS'] * 4 + ['FAILED'] + ['PASS'] * 3)
        self.assertTrue(all(row['attempts'] == row['attempt_limit'] == 1 and row['retries'] == 0 for row in cells))
        self.assertEqual(len(run.outcomes), 8)
        self.assertEqual(run.rows[failed]['error'], 'retained fabricated refusal')
        self.assertNotIn('values_sha256', run.rows[failed])

    def test_uncertain_outer_or_child_closure_stops_all_later_unchanged_cells(self):
        for index in (1, 5):
            for mode in ('outer-uncertain', 'child-uncertain'):
                name = driver.initial_rows()[index]['name']
                run, recipe, new = execution({name: mode})
                untouched = copy.deepcopy(run.result['cells'][index + 1:])
                with self.assertRaises(RuntimeError):
                    driver.execute_cells(run, recipe, new)
                self.assertFalse(run.safe)
                self.assertEqual(run.result['cells'][index + 1:], untouched)
                self.assertEqual([event[1] for event in run.events if event[0] == 'bounded'],
                                 [row['name'] for row in run.result['cells'][:index + 1]])
                self.assertTrue(all(row['status'] == 'PASS' and row['attempts'] == 1
                                    for row in run.result['cells'][:index]))
                self.assertEqual((run.rows[name]['status'], run.rows[name]['attempts']), ('FAILED', 1))
                self.assertEqual(len(run.outcomes), index)


if __name__ == '__main__':
    unittest.main()
