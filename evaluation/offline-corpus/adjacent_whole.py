#!/usr/bin/env python3
"""D01 custody and producer declarations only; W01/N01 remain unevaluated."""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys

assert not sys.flags.optimize, 'assertions required'
MIB = 1048576
PROGRAMS = ('checksum', 'rle-roundtrip')
COUNTS = {'checksum': (80, 16), 'rle-roundtrip': (107, 26)}
PROFILE = 'offline-whole-authored-adjacent-b2-short-t3-pending-2g-v1'
IMPORTER = 'elf-disassembly-null-jumps-adjacent-b2-short-t3-pending-v1'
CAPTURE = 'offline-whole-capture-adjacent-b2-u2-l1-j2-v1'
BUILDER_SHA = '0def6474c15584dd168b74c2338311caa53d1864ab01d5805cb3a05c62960592'
OUTPUT_BYTES = 64 * MIB
FILE_BYTES = 16 * MIB
MEMBERS = 256
FAMILY = [['neighbor_victims', 'short-only'], ['neighbor_ownership', 'inherited-t3'],
          ['pending_selected', 'full-instruction-ownership'], ['adjacent_b2', 'fallback-two-site-v1']]
FALSE_FLAGS = ('artifact_complete', 'independent_artifact_verified', 'qualification_complete',
               'classification_complete', 'native_correctness_complete', 'corpus_success_claimed',
               'performance_eligible')
PRODUCT = {'adjacent-b2-evidence.txt', 'bundle-index.tsv', 'disassembly-inventory.tsv',
           'disassembly-policy.txt', 'disassembly.txt', 'ledger.tsv', 'metadata.li2meta',
           'planning-profile.tsv', 'report.tsv', 'selection.txt', 'target.tsv'}
COMPLETE_ONLY = {'candidate.elf', 'source.li2sparse', 'plan-ledger.tsv'}
TEXT = {'COMPLETE', 'bundle-index.tsv', 'disassembly-inventory.tsv', 'disassembly-policy.txt',
        'disassembly.txt', 'planning-profile.tsv', 'report.tsv', 'selection.txt', 'program-failure.tsv',
        'target.tsv'}
sha = lambda data: hashlib.sha256(data).hexdigest()


class Failure(Exception):
    def __init__(self, stage, detail):
        super().__init__(stage + ': ' + detail)
        self.stage, self.detail = stage, detail


class CustodyFailure(Failure):
    pass


class ClosedOutputFailure(Failure):
    def __init__(self, error, producer_exit):
        super().__init__(error.stage, error.detail)
        self.producer_exit = producer_exit


def need(ok, stage, detail):
    if not ok:
        raise Failure(stage, detail)


def uint(value):
    need(type(value) is str and len(value) <= 20 and re.fullmatch(r'0|[1-9][0-9]*', value) is not None,
         'shape', 'canonical integer')
    result = int(value)
    need(result <= (1 << 64) - 1, 'shape', 'integer overflow')
    return result


def table(raw):
    need(type(raw) is bytes and raw.endswith(b'\n') and len(raw) <= MIB,
         'shape', 'text size/final LF')
    need(re.fullmatch(rb'[\x20-\x7e\t\n]+', raw) is not None, 'shape', 'ASCII/LF')
    return [line.split('\t') for line in raw.decode('ascii')[:-1].split('\n')]


def stamp(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns]


class OutputReader:
    """One program's cumulative actual reads; cached bytes are not reread."""
    def __init__(self, root):
        self.root = Path(root)
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.anchor = stamp(os.fstat(self.fd))[:2]
        self.used = 0
        self.records = {}
        self.directories = {}

    def close(self):
        os.close(self.fd)

    def directory(self, relative=''):
        parts = relative.split('/') if relative else []
        need(all(re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', p) and p not in ('.', '..')
                 for p in parts), 'output-path', 'directory components')
        # A duplicated descriptor shares scandir's directory offset. Open a fresh
        # file description so repeated bounded membership checks start at zero.
        fd = os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.fd)
        path = ''
        try:
            for part in parts:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd); fd = child
                path = path + '/' + part if path else part
                observed = stamp(os.fstat(fd))
                need(path not in self.directories or self.directories[path] == observed,
                     'output-identity', 'directory changed')
                self.directories[path] = observed
            return fd
        except BaseException:
            os.close(fd)
            raise

    def names(self, relative):
        fd = self.directory(relative)
        try:
            names = []
            with os.scandir(fd) as entries:
                for entry in entries:
                    need(len(names) < MEMBERS, 'output-bound', 'member count')
                    need(re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', entry.name) is not None
                         and entry.name not in ('.', '..'), 'output-path', 'member name')
                    names.append(entry.name)
            return sorted(names)
        finally:
            os.close(fd)

    def _open(self, relative):
        parts = relative.split('/')
        need(parts and all(re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', p) and p not in ('.', '..')
                           for p in parts), 'output-path', 'file components')
        parent = self.directory('/'.join(parts[:-1]))
        try:
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode), 'output-type', 'regular file required')
            need(stamp(info) == stamp(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)),
                 'output-identity', 'open path changed')
            return fd, parent, parts[-1], info
        except BaseException:
            if 'fd' in locals():
                os.close(fd)
            os.close(parent)
            raise

    def read(self, relative, cap=FILE_BYTES, keep=0):
        fd, parent, name, before = self._open(relative)
        try:
            identity = stamp(before)
            need(before.st_size <= cap, 'output-bound', 'per-file bound')
            if relative in self.records:
                row = self.records[relative]
                need(row['stat'] == identity and keep <= row['keep'],
                     'output-identity', 'changed file or uncached reread')
                return row
            need(before.st_size <= OUTPUT_BYTES - self.used,
                 'output-bound', '64 MiB aggregate bound')
            digest, data, left = hashlib.sha256(), bytearray(), before.st_size
            while left:
                block = os.read(fd, min(left, 65536))
                need(bool(block), 'output-identity', 'short file')
                self.used += len(block)
                digest.update(block)
                if len(data) < keep:
                    data.extend(block[:keep - len(data)])
                left -= len(block)
            need(identity == stamp(os.fstat(fd)) ==
                 stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                 'output-identity', 'file changed during read')
            row = dict(bytes=before.st_size, sha256=digest.hexdigest(), stat=identity,
                       data=bytes(data), keep=keep)
            self.records[relative] = row
            return row
        finally:
            os.close(fd); os.close(parent)

    def bytes(self, relative, cap=MIB):
        row = self.read(relative, cap, cap)
        need(len(row['data']) == row['bytes'], 'output-bound', 'uncached full text')
        return row['data']

    def verify(self):
        need(stamp(os.lstat(self.root))[:2] == self.anchor and
             stamp(os.fstat(self.fd))[:2] == self.anchor, 'output-identity', 'root changed')
        for relative, row in self.records.items():
            fd, parent, name, before = self._open(relative)
            try:
                need(stamp(before) == row['stat'], 'output-identity', 'retained file changed')
            finally:
                os.close(fd); os.close(parent)


    def seal(self, *, allow_incomplete=False):
        """Freeze known custody without promoting an initial collection refusal."""
        def directory_record(relative, identity):
            record = dict(stat=identity)
            try:
                record['members'] = self.names(relative)
            except Failure as error:
                initial_limit = (error.stage, error.detail) in (
                    ('output-bound', 'member count'), ('output-path', 'member name'))
                if not allow_incomplete or not initial_limit:
                    raise
                # No full membership was established. Preserve the exact directory
                # identity and refusal; later checks must not retry its enumeration.
                record.update(members=None, membership_failure=error_row(error))
            return record
        self.verify()
        root = stamp(os.fstat(self.fd))
        need(root == stamp(os.lstat(self.root)), 'output-identity', 'root changed at retention')
        directories = {'': directory_record('', root)}
        for relative in sorted(self.directories):
            directories[relative] = directory_record(relative, list(self.directories[relative]))
        self.verify_retained(directories)
        return directories

    def verify_retained(self, directories):
        """No-follow stat and bounded membership checks against the saved snapshot."""
        self.verify()
        for relative, expected in directories.items():
            fd = self.directory(relative)
            try:
                need(stamp(os.fstat(fd)) == expected['stat'],
                     'output-identity', 'retained directory changed')
            finally:
                os.close(fd)
            if expected['members'] is not None:
                need(self.names(relative) == expected['members'],
                     'output-identity', 'retained directory membership changed')
        self.verify()
        need(stamp(os.fstat(self.fd)) == directories['']['stat'] ==
             stamp(os.lstat(self.root)), 'output-identity', 'retained root changed')

    def pins(self):
        return {name: {key: row[key] for key in ('bytes', 'sha256', 'stat')}
                for name, row in sorted(self.records.items())}


class OutputCustody:
    """The whole run owns retained readers until its final identity check and close."""
    def __init__(self):
        self.retained = []
        self.failures = {}

    def fail(self, program, row, error):
        # Keep the original producer verdict, failure, pins and byte accounting.
        self.failures.setdefault(program, error_row(error))
        row['output_stability'] = 'FAILED'
        row['output_stability_failure'] = self.failures[program]
        row['diagnostic_capture_complete'] = False

    def adopt(self, program, row, reader):
        self.retained.append((program, row, reader))
        try:
            row['output_directories'] = reader.seal(
                allow_incomplete=not row['diagnostic_capture_complete'])
            row['output_membership_complete'] = all(
                d['members'] is not None for d in row['output_directories'].values())
            row['output_stability'] = ('RETAINED' if row['output_membership_complete']
                                       else 'RETAINED_INCOMPLETE')
        except Exception as error:
            self.fail(program, row, error)

    def verify(self):
        for program, row, reader in self.retained:
            if program in self.failures:
                continue
            try:
                reader.verify_retained(row['output_directories'])
            except Exception as error:
                self.fail(program, row, error)
        if self.failures:
            raise CustodyFailure('retained-output-stability', 'previous output identity or membership changed')

    def finalize(self, report):
        try:
            try:
                self.verify()
            except Exception as error:
                report['output_stability_failure'] = error_row(error)
        finally:
            for program, row, reader in self.retained:
                try:
                    reader.close()
                except Exception as error:
                    self.fail(program, row, error)
                if program not in self.failures:
                    row['output_stability'] = ('VERIFIED' if row['output_membership_complete']
                                               else 'VERIFIED_INCOMPLETE')
            report['retained_output_stability_complete'] = not self.failures and all(
                row['output_membership_complete'] for _, row, _ in self.retained)
            if self.failures:
                report['retained_output_failures'] = dict(self.failures)



def program_row(program):
    heads, selected = COUNTS[program]
    return dict(status='UNRUN', expected_heads=heads, expected_selected=selected,
                observed_heads=None, observed_selected=None, producer_candidate_complete=None,
                producer_exit=None, producer_roster_join=False, producer_dispatches=0,
                material_calls=0, diagnostic_capture_complete=False,
                deferred_checks=dict(W01='NOT_EVALUATED', N01='NOT_EVALUATED'),
                **dict.fromkeys(FALSE_FLAGS, False))


def summary():
    return dict(milestone='D01_FULL_ROSTER_PRODUCER_DIAGNOSTIC', placement_profile=PROFILE,
                capture_profile=CAPTURE, importer_profile=IMPORTER,
                adjacent_upper=2, adjacent_lower=1, adjacent_joint=2,
                expected_programs=2, expected_heads=187, expected_selected=42,
                aggregate_output_read_bytes_per_program=OUTPUT_BYTES,
                configuration_complete=False, diagnostic_capture_complete=False,
                diagnostic_status='INCOMPLETE', programs={p: program_row(p) for p in PROGRAMS},
                deferred_checks=dict(W01='NOT_EVALUATED', N01='NOT_EVALUATED'),
                **dict.fromkeys(FALSE_FLAGS, False))


def finish(report):
    rows = list(report['programs'].values())
    report['diagnostic_capture_complete'] = all(r['diagnostic_capture_complete'] for r in rows) and 'error' not in report
    declarations = all(r['status'] == 'PRODUCER_COMPLETE_UNVERIFIED' for r in rows)
    if declarations and report['diagnostic_capture_complete'] and report['configuration_complete'] and 'error' not in report:
        report['diagnostic_status'] = 'COMPLETE_UNVERIFIED'
        return 0
    report['diagnostic_status'] = 'FAILED_OR_INCOMPLETE'
    return 2 if declarations and report['diagnostic_capture_complete'] and 'error' not in report else 1


def selected_rows(program, material):
    records = table(material['source-inventory.tsv'])
    need(records[0] == ['role', 'index', 'pc', 'file_offset', 'length', 'selected_jump'],
         'material-roster', 'inventory header')
    heads, count = COUNTS[program]
    need(len(records) == heads + 1, 'material-roster', 'all heads')
    expected_roles = [('start', 61), ('kernel', heads - 62), ('hook', 1)]
    at, selected = 1, []
    selected_by_role = {}
    for role, population in expected_roles:
        selected_by_role[role] = 0
        for index in range(population):
            row = records[at]; at += 1
            need(len(row) == 6 and row[:2] == [role, str(index)] and row[5] in ('0', '1'),
                 'material-roster', 'head role/index/selection')
            pc, offset, length = map(uint, row[2:5])
            need(1 <= length <= 15, 'material-roster', 'head length')
            if row[5] == '1':
                selected_by_role[role] += 1
                selected.append([str(len(selected) + 1), str(pc), str(length), str(offset)])
    need(len(selected) == count and selected_by_role ==
         {'start': 14, 'kernel': count - 14, 'hook': 0}, 'material-roster', 'all selected jumps')
    return selected


def check_material(program, result, material, original):
    heads, selected = COUNTS[program]
    need(result['profile'] == PROFILE and result['program'] == program and
         result['adjacent_b2'] == 'fallback-two-site-v1' and
         all(type(result[key]) is int for key in ('adjacent_upper', 'adjacent_lower', 'adjacent_joint')) and
         [result['adjacent_upper'], result['adjacent_lower'], result['adjacent_joint']] == [2, 1, 2] and
         result['neighbor_victims'] == 'short-only' and result['neighbor_ownership'] == 'inherited-t3' and
         result['pending_selected'] == 'full-instruction-ownership' and
         result['qualification_complete'] is False and result['importer_verified'] is False,
         'material', 'profile/budget/qualification')
    need([result['source_expected_heads'], result['source_expected_jumps']] == [heads, selected],
         'material', 'literal denominator')
    need(set(material) <= {'ledger.txt', 'policy.txt', 'source-inventory.tsv'},
         'material', 'diagnostic members')
    if result['status'] != 'MATERIALS_READY':
        need(result['status'] == 'MATERIALS_REFUSED', 'material', 'status')
        return None
    need(set(material) == {'ledger.txt', 'policy.txt', 'source-inventory.tsv'} and
         [result['roster_checked_heads'], result['roster_checked_jumps']] == [heads, selected],
         'material', 'full checked roster')
    selected_rows(program, material)
    rows = material['policy.txt'].decode('ascii').splitlines()
    need(rows[:8] == ['LI2DISASM-POLICY 5', 'original ' + sha(original),
         'ledger ' + sha(material['ledger.txt']), 'neighbor-victims short-only',
         'neighbor-ownership inherited-t3', 'pending-selected full-instruction-ownership',
         'adjacent-b2 fallback-two-site-v1', 'adjacent-b2-budgets 2 1 2'],
         'material', 'v5 literal prefix')
    need(rows[8].startswith('target ') and rows[9:13] == ['domain 1', 'carrier 4718592',
         'limits 1048576 32 32 131072 128 2097152 1048576 128 2147483648', 'null-hook 4206592']
         and len(rows) == 13 + 3 * selected, 'material', 'unchanged complete policy limits')
    for sid in range(1, selected + 1):
        at = 13 + (sid - 1) * 3
        need(rows[at] == f'search {sid} preferred 64 256 64 none 256 4096',
             'material', 'unchanged singleton search')
        for row, role in zip(rows[at + 1:at + 3], ('selected', 'victim')):
            cells = row.split(' ')
            need(len(cells) == 7 and cells[:3] == ['allocation', str(sid), role] and
                 cells[4:6] == ['1', '4096'], 'material', 'unchanged cap-1 allocation')
    return selected_rows(program, material)


def check_stdout(raw, stderr, code):
    need(type(code) is int and code in (0, 2), 'producer-response', 'non-normal producer exit')
    expected = (f'profile={IMPORTER} candidate_complete={"true" if code == 0 else "false"} '
                'qualification_complete=false\n').encode('ascii')
    need(raw == expected and stderr == b'', 'producer-response', 'exact normal response')


def index_rows(raw, prefix):
    rows = table(raw)
    need(rows[:len(prefix)] == prefix, 'output-index', 'exact header')
    result = {}
    for row in rows[len(prefix):]:
        need(len(row) == 4 and row[0] == 'file' and
             re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', row[1]) is not None and
             row[1] not in ('.', '..') and row[1] not in result,
             'output-index', 'member shape/uniqueness')
        size = uint(row[2])
        need(re.fullmatch(r'[0-9a-f]{64}', row[3]) is not None, 'output-index', 'digest')
        result[row[1]] = dict(bytes=size, sha256=row[3])
    need(list(result) == sorted(result) and len(result) <= MEMBERS, 'output-index', 'ordered count')
    return result


def check_inventory(raw, selected, original, material):
    rows = table(raw)
    prefix = [['LI2DISASSEMBLY-INVENTORY', '1'], ['profile', IMPORTER], *FAMILY,
              ['original_sha256', sha(original)], ['ledger_sha256', sha(material['ledger.txt'])],
              ['complete_jump_count', str(len(selected))], ['qualification_complete', 'false'],
              ['id', 'pc', 'length', 'file_offset', 'region_pc', 'region_length', 'block_pc', 'block_length']]
    need(rows[:len(prefix)] == prefix, 'producer-roster', 'inventory prefix')
    records = rows[len(prefix):]
    need(len(records) == len(selected) and all(len(row) == 8 for row in records) and
         [row[:4] for row in records] == selected, 'producer-roster', 'complete inventory coordinates')
    regions = []
    for line in material['ledger.txt'].decode('ascii').splitlines():
        if line.startswith('region '):
            _, pc, offset, length = line.split(' ')
            regions.append((uint(pc), uint(offset), uint(length)))
    for row in records:
        _, pc, length, offset, region, size, block, block_size = map(uint, row)
        need((region, offset - (pc - region), size) in regions and
             region <= block <= pc and pc + length <= block + block_size <= region + size,
             'producer-roster', 'region owner/block bounds')


def check_selection(raw, selected, original):
    need(len(raw) <= MIB and raw.endswith(b'\n') and
         re.fullmatch(rb'[\x20-\x7e\n]+', raw) is not None, 'producer-roster', 'selection text')
    rows = raw.decode('ascii').splitlines()
    prefix = ['LI2TOOL 1', 'original ' + sha(original), 'neighbor-victims short-only',
              'neighbor-ownership inherited-t3', 'pending-selected full-instruction-ownership',
              'adjacent-b2 fallback-two-site-v1', 'adjacent-b2-budgets 2 1 2']
    need(rows[:7] == prefix, 'producer-roster', 'selection profile prefix')
    records = [row.split(' ') for row in rows if row.startswith('site ')]
    need(len(records) == len(selected) and all(len(row) == 14 for row in records) and
         [row[1:5] for row in records] == selected, 'producer-roster', 'selection coordinates')
    return sha(raw)


def check_report(raw, selected, original, selection, complete):
    rows = table(raw)
    prefix = [['LI2REPORT', '1'], ['original_sha256', sha(original)],
              ['selection_sha256', selection], ['candidate_complete', str(complete).lower()],
              ['qualification_complete', 'false'],
              ['site', 'pc', 'file_offset', 'length', 'core_tactic', 'candidate_emitted',
               'refusal_code', 'stage', 'detail_hex']]
    need(rows[:6] == prefix, 'producer-roster', 'report header')
    records = rows[6:]
    need(len(records) == len(selected) and all(len(row) == 9 for row in records),
         'producer-roster', 'complete report shape')
    need([row[:4] for row in records] == [[r[0], r[1], r[3], r[2]] for r in selected],
         'producer-roster', 'complete report coordinates')
    for row in records:
        need(row[5] == str(complete).lower() and
             re.fullmatch(r'(?:[0-9a-f]{2})*', row[8]) is not None,
             'producer-roster', 'emitted/diagnostic declaration')
        if complete:
            need(row[4] != 'none' and row[6:] == ['none', 'none', ''],
                 'producer-roster', 'complete producer declaration')
        else:
            need(uint(row[6]) > 0 and row[7] not in ('', 'none'),
                 'producer-roster', 'whole-selection refusal declaration')


def check_evidence(prefix, selection, count):
    lines = prefix.split(b'\n')
    need(len(lines) >= 11 and lines[10].startswith(b'resources\t'),
         'producer-evidence', 'diagnostic suffix delimiter')
    rows = [line.decode('ascii').split('\t') for line in lines[:10]] + [['resources']]
    need(len(rows) == 11 and rows[0] == ['LI2ADJACENT-EVIDENCE', '1'] and
         rows[1] == ['selection_sha256', selection] and rows[2] == ['selected_count', str(count)] and
         rows[6:8] == [['qualification_complete', 'false'], ['classification_complete', 'false']] and
         rows[10][0] == 'resources', 'producer-evidence', 'stable prefix')
    need([r[0] for r in rows[3:6]] == ['baseline_calls', 'pair_calls', 'adjacent_counts'] and
         [len(r) for r in rows[3:6]] == [2, 2, 4] and
         rows[8][0] == 'legacy_image_slots' and len(rows[8]) == 2 and
         rows[9][0] == 'combined_image_work_upper_bound' and len(rows[9]) == 2,
         'producer-evidence', 'scalar shape')
    baseline, pairs = uint(rows[3][1]), uint(rows[4][1])
    upper, lower, joint = map(uint, rows[5][1:])
    legacy, combined = uint(rows[8][1]), uint(rows[9][1])
    need(baseline == count and pairs <= count // 2 and upper <= 2 * pairs and
         lower <= pairs and joint <= 2 * pairs and joint <= upper and
         combined == legacy + upper + lower <= (1 << 64) - 1,
         'producer-evidence', 'fixed budget arithmetic')
    return dict(baseline_calls=baseline, pair_calls=pairs, upper=upper, lower=lower, joint=joint,
                legacy_image_slots=legacy, combined_image_work_upper_bound=combined,
                debug_association_verified=False)


def check_product(reader, program, original, material, code):
    root = 'importer/product'
    names = reader.names(root)
    observed = {}
    for name in names:
        cap = MIB if name in TEXT else 2 * MIB if name == 'candidate.elf' else FILE_BYTES
        keep = cap if name in TEXT or (name == 'ledger.tsv' and code == 2) else 8192 if name == 'adjacent-b2-evidence.txt' else 0
        observed[name] = reader.read(root + '/' + name, cap, keep)
    need(reader.names(root) == names, 'output-identity', 'membership changed')
    need('COMPLETE' in observed, 'output-index', 'missing COMPLETE')
    prefix = [['LI2DISASSEMBLY-DIRECTORY', '1'], ['profile', IMPORTER],
              ['observed_original_sha256', sha(original)],
              ['candidate_complete', 'true' if code == 0 else 'false'],
              ['qualification_complete', 'false']]
    recorded = index_rows(observed['COMPLETE']['data'], prefix)
    need(set(recorded) == set(names) - {'COMPLETE'}, 'output-index', 'actual membership')
    for name, row in recorded.items():
        need(row == {k: observed[name][k] for k in ('bytes', 'sha256')},
             'output-index', 'member size/hash')
    selected = selected_rows(program, material)
    need(observed['disassembly.txt']['data'] == material['ledger.txt'] and
         observed['disassembly-policy.txt']['data'] == material['policy.txt'],
         'producer-identity', 'exact ledger/policy')
    selection = None
    if 'disassembly-inventory.tsv' in names:
        check_inventory(observed['disassembly-inventory.tsv']['data'], selected, original, material)
    if 'selection.txt' in names:
        selection = check_selection(observed['selection.txt']['data'], selected, original)
    if 'program-failure.tsv' in names:
        base = {'COMPLETE', 'disassembly.txt', 'disassembly-policy.txt', 'program-failure.tsv'}
        shapes = [base, base | {'disassembly-inventory.tsv'},
                  base | {'disassembly-inventory.tsv', 'selection.txt'}]
        need(code == 2 and set(names) in shapes, 'output-shape', 'preparation refusal')
        rows = table(observed['program-failure.tsv']['data'])
        prefix = [['LI2DISASSEMBLY-FAILURE', '1'], ['profile', IMPORTER],
                  ['observed_original_sha256', sha(original)],
                  ['expected_ledger_sha256', sha(material['ledger.txt'])],
                  ['expected_policy_sha256', sha(material['policy.txt'])],
                  ['qualification_complete', 'false']]
        need(rows[:6] == prefix and len(rows) == 7 and len(rows[6]) == 2 and
             rows[6][0] == 'detail_hex' and re.fullmatch(r'(?:[0-9a-f]{2})+', rows[6][1]),
             'output-shape', 'preparation failure record')
        reader.verify()
        return dict(producer_candidate_complete=False, producer_roster_join=False,
                    preparation_failure=True, selection_sha256=selection)
    expected = PRODUCT | {'COMPLETE'} | {f'site-{r[0]}.diagnostics.txt' for r in selected}
    images = sorted(name for name in names if re.fullmatch(r'image-[0-9]{4}\.bin', name))
    if code == 0:
        need(1 <= len(images) <= 32 and images == [f'image-{i:04}.bin' for i in range(len(images))],
             'output-shape', 'contiguous bounded images')
        expected |= COMPLETE_ONLY | set(images)
    need(set(names) == expected, 'output-shape', 'exact Product file set')
    bundle = index_rows(observed['bundle-index.tsv']['data'],
        [['LI2BUNDLE', '1'], ['original_sha256', sha(original)], ['qualification_complete', 'false'],
         ['consumer_action', 'RuntimeScan-while-gated-until-qualified']])
    need(bundle == {name: row for name, row in recorded.items() if name != 'bundle-index.tsv'},
         'output-index', 'exact nested bundle membership')
    expected_profile = [['LI2PLANNING', '1'], ['profile', IMPORTER], *FAMILY,
        ['adjacent_upper', '2'], ['adjacent_lower', '1'], ['adjacent_joint', '2'],
        ['scope', 'artifact-code-regions-not-functions'], ['entries', 'all-verified-instruction-heads'],
        ['original_sha256', sha(original)], ['ledger_sha256', sha(material['ledger.txt'])],
        ['policy_sha256', sha(material['policy.txt'])], ['selection_sha256', selection],
        ['complete_jump_count', str(len(selected))], ['qualification_complete', 'false']]
    need(table(observed['planning-profile.tsv']['data']) == expected_profile,
         'producer-identity', 'exact planning profile')
    check_report(observed['report.tsv']['data'], selected, original, selection, code == 0)
    evidence = check_evidence(observed['adjacent-b2-evidence.txt']['data'], selection, len(selected))
    if code == 2:
        ledger = reader.bytes(root + '/ledger.tsv', FILE_BYTES)
        need(ledger == (f'LI2ADJACENT-NO-CANDIDATE\t1\nselection_sha256\t{selection}\n'
                        'qualification_complete\tfalse\n').encode('ascii'),
             'output-shape', 'refused ledger')
    reader.verify()
    return dict(producer_candidate_complete=code == 0, producer_roster_join=True,
                preparation_failure=False, selection_sha256=selection, scalar_evidence=evidence,
                image_count=len(images), independent_image_associations_verified=False)


def json_value(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'json', 'duplicate key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def check_closed(reader, request, helper_sha, command):
    root = 'importer/'
    parent = json_value(reader.bytes(root + 'parent-closed.json'))
    receipt = json_value(reader.bytes(root + 'receipt.json'))
    need(parent['wait_returned'] is True and parent['error'] is None and
         receipt['absence_proof'] == 'ECHILD' and receipt['cleanup_error'] is None,
         'closure', 'parent/ECHILD')
    request_raw = reader.bytes(root + 'request.json')
    need(json_value(request_raw) == request and sha(request_raw) == receipt['request_sha256'] and
         receipt['helper_sha256'] == helper_sha and receipt['inputs_unchanged'] is True,
         'closure', 'request/helper/input identity')
    need(type(receipt['exit']) is int and type(parent['exit']) is int and
         parent['exit'] == (0 if receipt['exit'] == 0 else 1) and
         receipt['wall_timeout'] is False and receipt['aborted'] is None and
         receipt['cleanup_events'] == receipt['unexpected_descendants'] == [],
         'closure', 'exit/limits/cleanup')
    need(json_value(reader.bytes(root + 'command.json')) == command, 'closure', 'exact supervisor command')
    streams = {}
    try:
        for stream in ('stdout', 'stderr'):
            row = reader.read(root + stream + '.txt', FILE_BYTES, 1024)
            need(row['sha256'] == receipt[stream + '_sha256'], 'closure', 'stream identity')
            streams[stream] = row
        need(reader.bytes(root + 'helper.stderr') == b'', 'closure', 'helper stderr')
        reader.read(root + 'helper.stdout', FILE_BYTES)
        reader.verify()
    except Failure as error:
        if error.stage == 'output-bound':
            # ECHILD, parent wait and the exact request/command are already bound.
            # Collection is incomplete, but another program may run safely.
            raise ClosedOutputFailure(error, receipt['exit']) from error
        raise
    return receipt['exit'], streams


def invoke(ctx, directory, argv, env, tools):
    request = dict(argv=argv, cwd=str(ctx.ROOT), env=env, stdout=str(directory / 'stdout.txt'),
                   stderr=str(directory / 'stderr.txt'), cpu_seconds=20, wall_seconds=30, file_bytes=FILE_BYTES)
    ctx.B.write(directory / 'request.json', request)
    command = [tools['timeout']['path'], '--signal=TERM', '--kill-after=10s', '40s',
               tools['python']['path'], '-B', tools['helper']['path'], '--request',
               str(directory / 'request.json'), '--receipt', str(directory / 'receipt.json')]
    command_record = dict(argv=command, cwd=str(ctx.ROOT), env=env, parent_seconds=55, cleanup_seconds=10)
    ctx.B.write(directory / 'command.json', command_record)
    child = None; parent = dict(wait_returned=False, exit=None, error=None)
    try:
        with (directory / 'helper.stdout').open('xb') as stdout, (directory / 'helper.stderr').open('xb') as stderr:
            child = subprocess.Popen(command, cwd=ctx.ROOT, env=env, stdin=subprocess.DEVNULL,
                                     stdout=stdout, stderr=stderr, start_new_session=True)
            try:
                child.wait(timeout=55); parent['wait_returned'] = True
            except BaseException as error:
                parent['error'] = type(error).__name__
                if child.poll() is None:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                child.wait(timeout=10); parent['wait_returned'] = True
                raise
    finally:
        parent['exit'] = child.returncode if child else None
        ctx.B.write(directory / 'parent-closed.json', parent)
    return request, command_record


def check_capture_labels(plan, captured, builder):
    expected = builder.labels()
    need(all(type(plan.get(k)) is type(v) and type(captured.get(k)) is type(v) and
             plan[k] == v and captured[k] == v for k, v in expected.items()),
         'capture', 'exact adjacent capture labels')
    need(plan['qualification_complete'] is captured['qualification_complete'] is False,
         'capture', 'qualification')


def authenticate_capture(ctx, args, report):
    read = ctx.read
    jread = lambda path: json_value(read(path, cap=MIB))
    builder = ctx.load('build_adjacent_whole.py', BUILDER_SHA)
    capture = args.capture
    raw = read(capture / 'closed.json', cap=MIB)
    need(sha(raw) == args.capture_sha256, 'capture', 'root frozen capture hash')
    captured, plan = json_value(raw), jread(capture / 'planned.json')
    check_capture_labels(plan, captured, builder)
    need(captured['revision'] == plan['revision'] and
         re.fullmatch(r'[0-9a-f]{40}', captured['revision']), 'capture', 'revision')
    env, tools = plan['env'], plan['tools']
    need(set(tools) == {'python', 'helper', 'as', 'ld', 'objdump', 'timeout', 'cargo', 'rustc'},
         'capture', 'tool population')
    bin_dir = Path(tools['cargo']['path']).parent
    expected_env = dict(HOME=env['HOME'], CARGO_HOME=env['CARGO_HOME'],
        PATH=str(bin_dir) + ':/usr/bin:/bin', RUSTC=str(bin_dir / 'rustc'),
        RUSTDOC=str(bin_dir / 'rustdoc'), CARGO_TARGET_DIR=str(ctx.ROOT / 'target'),
        CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4', CARGO_NET_OFFLINE='true',
        CARGO_TERM_COLOR='never', CARGO_PROFILE_RELEASE_OPT_LEVEL='3',
        CARGO_PROFILE_RELEASE_DEBUG='0', CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true',
        CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true', LC_ALL='C', LANG='C',
        PYTHONDONTWRITEBYTECODE='1')
    need(env == expected_env and tools['rustc']['path'] == env['RUSTC'] and
         Path(env['HOME']).is_absolute() and Path(env['CARGO_HOME']).is_absolute(),
         'capture', 'exact environment')
    configuration_complete = all(v['state'] != 'READ_DENIED' for v in plan['configurations'].values())
    need(captured['configuration_complete'] is plan['configuration_complete'] is configuration_complete,
         'capture', 'configuration declaration')
    git = lambda *a: subprocess.check_output(['/usr/bin/git', '-C', str(ctx.ROOT), *a],
                                             env=env, timeout=15)
    current = git('rev-parse', 'HEAD').decode().strip()
    need(not git('diff', '--binary', 'HEAD', '--'), 'capture', 'clean tracked source')
    need(git('show', current + ':evaluation/offline-corpus/reproduce_whole.py') ==
         read(Path(ctx.reproducer_file), cap=MIB), 'capture', 'current reproducer source')
    need(not git('diff', '--binary', captured['revision'], current, '--',
         'Cargo.toml', 'Cargo.lock', 'build.rs', '.cargo', 'src', 'crates', 'tools/elf-rewrite', 'tests/support'),
         'capture', 'current exact Rust build source')
    phases = builder.phase_plan(ctx.ROOT, capture, tools, ctx.HERE)
    need(plan['phases'] == phases and set(captured['results']) == {p['name'] for p in phases},
         'capture', 'entire fixed phase plan')
    inputs = {str(Path(builder.__file__)), str(Path(ctx.B.__file__)), str(ctx.HERE / 'layout.ld'),
              str(ctx.ROOT / 'Cargo.toml'), str(ctx.ROOT / 'Cargo.lock'),
              *(str(ctx.HERE / (p + '.S')) for p in PROGRAMS)}
    need(set(plan['inputs']) == inputs and
         all(captured['files'][p] == value for p, value in plan['inputs'].items()),
         'capture', 'exact initial source inputs')
    expected_files = set(inputs)
    for phase in phases:
        status = captured['results'][phase['name']]['status']
        need(status in ('PASS', 'FAILED', 'UNRUN'), 'capture', 'phase status')
        if status == 'PASS':
            need(all(captured['results'][name]['status'] == 'PASS' for name in phase['dependencies']),
                 'capture', 'PASS dependency closure')
            expected_files.update(phase.get('outputs', []))
            if 'product' in phase:
                expected_files.add(phase['product'])
    need(set(captured['files']) == expected_files, 'capture', 'complete watched file set')
    for path, pin in captured['files'].items():
        read(Path(path), pin)
    for path in (ctx.reproducer_file, __file__, builder.__file__, ctx.B.__file__, ctx.H.__file__,
                 ctx.D.__file__, ctx.D.C.__file__, ctx.D.T.__file__):
        read(Path(path), cap=MIB)
    for pin in tools.values():
        read(Path(pin['path']), pin)
    need(tools['helper']['sha256'] == ctx.B.HELPER_SHA and
         tools['helper']['path'] == str(ctx.ROOT / 'tools/unwind-oracle/bounded_command.py') and
         ctx.B.identity(sys.executable) == tools['python'], 'capture', 'helper/Python')
    need(ctx.B.configuration(ctx.ROOT, Path(env['CARGO_HOME'])) == plan['configurations'],
         'capture', 'configuration identity')

    def stable():
        try:
            need(all(ctx.B.identity(path) == pin for path, pin in ctx.PINS.items()) and
                 git('rev-parse', 'HEAD').decode().strip() == current and
                 not git('diff', '--binary', 'HEAD', '--') and
                 ctx.B.configuration(ctx.ROOT, Path(env['CARGO_HOME'])) == plan['configurations'],
                 'custody', 'source/configuration changed')
        except Exception as error:
            raise CustodyFailure('custody', str(error)) from error

    streams = {}
    for phase in phases:
        name = phase['name']; row = captured['results'][name]
        if row['status'] == 'UNRUN':
            continue
        directory = capture / name
        cpu, wall, mib = phase['limits']
        request = dict(argv=phase['argv'], cwd=str(ctx.ROOT), env=env,
                       stdout=str(directory / 'stdout.txt'), stderr=str(directory / 'stderr.txt'),
                       cpu_seconds=cpu, wall_seconds=wall, file_bytes=mib * MIB)
        expected_command = dict(argv=[tools['timeout']['path'], '--signal=TERM', '--kill-after=10s',
            str(wall + 10) + 's', tools['python']['path'], '-B', tools['helper']['path'], '--request',
            str(directory / 'request.json'), '--receipt', str(directory / 'receipt.json')],
            env=env, cwd=str(ctx.ROOT), parent_seconds=wall + 25, cleanup_seconds=10)
        need(jread(directory / 'command.json') == expected_command, 'capture', 'supervisor command')
        code, phase_streams = ctx.closed(directory, request, row)
        read(directory / 'helper.stdout', cap=mib * MIB)
        if row['status'] == 'PASS':
            need(code == 0, 'capture', 'PASS phase failed closure')
            streams[name] = phase_streams
            if 'product' in phase:
                builder.check_artifact(phase_streams['stdout'], phase)
                read(Path(phase['product']), captured['files'][phase['product']])
    need(all(name in streams for name in ('build-adjacent_b2_disassembly_sites',
         'build-elf-exec-oracle', 'target')), 'capture', 'required release/target build')
    binary = ctx.ROOT / 'target/release/examples/adjacent_b2_disassembly_sites'
    read(binary, captured['files'][str(binary)])
    stable()
    report.update(capture_revision=captured['revision'], current_revision=current,
                  configuration_complete=configuration_complete, capture_results=captured['results'])
    return dict(plan=plan, captured=captured, streams=streams, binary=binary,
                env=env, tools=tools, stable=stable)


def error_row(error):
    return dict(stage=getattr(error, 'stage', 'exception'), error=type(error).__name__,
                detail=str(error)[:2048])


def drive_programs(report, action):
    for program in PROGRAMS:
        row = report['programs'][program]
        try:
            action(program, row)
        except CustodyFailure as error:
            row['status'] = 'FAILED'
            row['failure'] = error_row(error)
            report['error'] = error_row(error)
            for other in PROGRAMS:
                if report['programs'][other]['status'] == 'UNRUN':
                    report['programs'][other]['blocked_by'] = error_row(error)
            break
        except Exception as error:
            row['status'] = 'FAILED'
            row['failure'] = error_row(error)


def importer_arguments(binary, original, directory, material):
    return [str(binary), str(original), str(directory / 'ledger.txt'), sha(material['ledger.txt']),
            str(directory / 'policy.txt'), sha(material['policy.txt']), str(directory / 'importer/product')]


def program_attempt(ctx, args, captured, program, row):
    directory = args.output / program
    directory.mkdir(mode=0o700)
    reader = None
    row['status'] = 'MATERIALS_REFUSED'
    try:
        captured['stable']()
        capture = args.capture
        streams, pins = captured['streams'], captured['captured']['files']
        for suffix in ('as', 'ld', 'disassemble-_start', 'disassemble-kernel', 'disassemble-null_hook'):
            need(program + '-' + suffix in streams, 'material-inputs', 'required program capture phase')
        inputs = {key: ctx.read(capture / program / name, pins[str(capture / program / name)], ctx.D.CAP)
                  for key, name in [('original', 'original'), ('object', 'subject.o')]}
        inputs.update(source=ctx.read(ctx.HERE / (program + '.S'), pins[str(ctx.HERE / (program + '.S'))], ctx.D.CAP),
                      linker=ctx.read(ctx.HERE / 'layout.ld', pins[str(ctx.HERE / 'layout.ld')], ctx.D.CAP),
                      target=streams['target']['stdout'])
        disassembly = {role: streams[program + '-disassemble-' + symbol]['stdout']
                       for role, symbol in ctx.H.SYMBOLS.items()}
        ctx.B.write(directory / 'raw-input-hashes.json',
                    dict(inputs={key: sha(value) for key, value in inputs.items()},
                         objdump={key: sha(value) for key, value in disassembly.items()}))
        inputs['heads'] = ctx.H.capture(program, inputs['original'], inputs['object'], disassembly)
        need(type(inputs['heads']) is bytes and len(inputs['heads']) <= MIB,
             'material', 'head transport bound')
        with (directory / 'heads.txt').open('xb') as stream:
            stream.write(inputs['heads'])
        expected = {key: sha(value) for key, value in inputs.items()}
        ctx.B.write(directory / 'input-hashes.json', expected)
        row['material_calls'] += 1
        result = ctx.D.attempt_adjacent_b2(program, inputs, expected, upper=2, lower=1, joint=2)
        material = result['files']
        for name, data in material.items():
            need(name in {'ledger.txt', 'policy.txt', 'source-inventory.tsv'} and
                 type(data) is bytes and len(data) <= MIB, 'material', 'bounded known member')
            with (directory / name).open('xb') as stream:
                stream.write(data)
        retained = {key: value for key, value in result.items() if key != 'files'}
        ctx.B.write(directory / 'materials.json',
                    dict(retained, files={name: dict(bytes=len(data), sha256=sha(data)) for name, data in material.items()}))
        row['materials'] = retained
        reader = OutputReader(directory)
        for name in ['raw-input-hashes.json', 'heads.txt', 'input-hashes.json', 'materials.json', *sorted(material)]:
            record = reader.read(name, MIB)
            if name in material:
                need(record['bytes'] == len(material[name]) and record['sha256'] == sha(material[name]),
                     'material-identity', 'written material bytes')
            if name == 'heads.txt':
                need(record['bytes'] == len(inputs['heads']) and record['sha256'] == sha(inputs['heads']),
                     'material-identity', 'written head transport')
        selected = check_material(program, result, material, inputs['original'])
        captured['stable']()
        if selected is None:
            reader.verify()
            row['diagnostic_capture_complete'] = True
            return
        row.update(observed_heads=COUNTS[program][0], observed_selected=len(selected))
        attempt = directory / 'importer'; attempt.mkdir()
        argv = importer_arguments(captured['binary'], capture / program / 'original', directory, material)
        captured['stable']()
        row['status'] = 'PRODUCER_FAILED'
        reader.verify()
        row['producer_dispatches'] += 1
        try:
            request, command = invoke(ctx, attempt, argv, captured['env'], captured['tools'])
            code, streams = check_closed(reader, request, ctx.B.HELPER_SHA, command)
        except ClosedOutputFailure as error:
            row['producer_exit'] = error.producer_exit
            raise
        except Exception as error:
            raise CustodyFailure('producer-closure', str(error)) from error
        row['producer_exit'] = code
        row['producer_stdout'] = {key: streams['stdout'][key] for key in ('bytes', 'sha256')}
        row['producer_stderr'] = {key: streams['stderr'][key] for key in ('bytes', 'sha256')}
        captured['stable']()
        if code not in (0, 2):
            try:
                collect_partial(reader)
            except Exception as error:
                row['retention_failure'] = error_row(error)
            row['failure'] = dict(stage='producer-exit', error='ProducerError', detail=str(code))
            return
        try:
            need(streams['stdout']['bytes'] == len(streams['stdout']['data']) and
                 streams['stderr']['bytes'] == len(streams['stderr']['data']),
                 'producer-response', 'bounded exact response')
            check_stdout(streams['stdout']['data'], streams['stderr']['data'], code)
            row['producer_candidate_complete'] = code == 0
            row.update(check_product(reader, program, inputs['original'], material, code))
            reader.verify()
        except Exception as error:
            if getattr(error, 'stage', None) != 'output-bound':
                try:
                    collect_partial(reader)
                except Exception as retention:
                    row['retention_failure'] = error_row(retention)
            raise
        row['status'] = 'PRODUCER_COMPLETE_UNVERIFIED' if code == 0 else 'PRODUCER_REFUSED'
        row['diagnostic_capture_complete'] = True
    finally:
        if reader is not None:
            row['output_read_bytes'] = reader.used
            row['output_files'] = reader.pins()
            owner = captured.get('output_custody')
            if owner is None:
                reader.close()
            else:
                owner.adopt(program, row, reader)


def collect_partial(reader):
    """Retain safe bounded hashes only; never treats partial output as a Product."""
    names = reader.names('importer/product')
    for name in names:
        cap = MIB if name in TEXT else 2 * MIB if name == 'candidate.elf' else FILE_BYTES
        reader.read('importer/product/' + name, cap)
    need(reader.names('importer/product') == names, 'output-identity', 'partial membership changed')
    reader.verify()


def run(args, ctx):
    report = summary()
    report.update(capture=str(args.capture), capture_sha256=args.capture_sha256)
    capture, output = args.capture, args.output
    need(capture.is_absolute() and capture.resolve(strict=True) == capture and
         capture.is_relative_to(ctx.ROOT / 'ignored'), 'arguments', 'canonical capture')
    need(output.is_absolute() and output.is_relative_to(ctx.ROOT / 'ignored') and
         not output.is_relative_to(capture) and not os.path.lexists(output) and
         output.parent.resolve(strict=True) == output.parent, 'arguments', 'new output')
    need(re.fullmatch(r'[0-9a-f]{64}', args.capture_sha256), 'arguments', 'capture SHA')
    output.mkdir(mode=0o700)
    custody = OutputCustody()
    try:
        captured = authenticate_capture(ctx, args, report)
        captured['output_custody'] = custody
        input_stable = captured['stable']
        def stable():
            input_stable()
            custody.verify()
        captured['stable'] = stable
        ctx.B.write(output / 'inputs.json', dict(report=report, first_pins=ctx.PINS, build_plan=captured['plan']))
        drive_programs(report, lambda program, row: program_attempt(ctx, args, captured, program, row))
        input_stable()
    except Exception as error:
        report['error'] = error_row(error)
        for row in report['programs'].values():
            if row['status'] == 'UNRUN':
                row['blocked_by'] = error_row(error)
    except BaseException as error:
        report['error'] = error_row(error)
        for row in report['programs'].values():
            if row['status'] == 'UNRUN':
                row['blocked_by'] = error_row(error)
        raise
    finally:
        custody.finalize(report)
        code = finish(report)
        ctx.B.write(output / 'closed.json', dict(report, first_pins=ctx.PINS))
    return code
