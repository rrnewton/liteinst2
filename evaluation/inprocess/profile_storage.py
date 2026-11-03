"""Whole-output admission for bounded passive profiles; no truncation or filtering."""
import hashlib
import json
from pathlib import Path
import stat
import subprocess


def need(ok, why):
    if not ok: raise ValueError(why)


class SlotGuard:
    """Admission before complete writes; no source, sample or output rewriting."""
    CAP = 20_000_000_000
    META = 16 << 20

    def __init__(self, root, output, perf_file_bytes):
        self.root = root
        self.output = output
        self.perf_file_bytes = perf_file_bytes
        self.du = Path('/usr/bin/du')
        data = self.du.read_bytes()
        self.du_fact = dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                            mode=stat.S_IMODE(self.du.stat().st_mode))
        self.active = False
        self.exports = {output/'capture'/name for name in
                        ('samples.json', 'maps.json', 'unwound.json', 'attribution.json')}
        self.record = dict(version=1, slot_cap=self.CAP, metadata_reserve=self.META,
            du=self.du_fact, exclusive_runtime_writer_required=True, checks=[], adapters_restored=True,
            scope='Whole du allocation plus prospective complete bytes and unchanged child-file ceilings. '
                  'No concurrent runtime/build or unbounded slot writer is permitted.')

    def reserve(self, added, label, future=0):
        need(type(added) is int and added >= 0 and type(future) is int and future >= 0,
             'literal nonnegative storage reservation')
        data = self.du.read_bytes()
        need(len(data) == self.du_fact['bytes'] and hashlib.sha256(data).hexdigest() == self.du_fact['sha256'] and
             stat.S_IMODE(self.du.stat().st_mode) == self.du_fact['mode'], 'exact read-only allocation tool')
        argv = [str(self.du), '-sx', '-B1', str(self.root)]
        observed = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=30, env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'})
        suffix = ('\t'+str(self.root)+'\n').encode()
        need(observed.returncode == 0 and observed.stderr == b'' and observed.stdout.endswith(suffix) and
             len(observed.stdout) <= len(suffix)+32, 'complete actual slot-allocation observation')
        number = observed.stdout[:-len(suffix)]
        need(number and number.isdigit(), 'literal nonnegative allocated-byte count')
        used = int(number); rounded = (added+4095)//4096*4096
        accepted = used+rounded+future+self.META < self.CAP
        self.record['checks'].append(dict(label=label, argv=argv, exit=0, allocated_bytes=used,
            complete_new_bytes=added, rounded_new_bytes=rounded, future_child_bytes=future,
            metadata_bytes=self.META, accepted=accepted))
        need(accepted, 'storage admission refused before '+label+'; complete observation retained as failed')

    def install(self):
        need(not self.active and self.perf_file_bytes == 128 << 20,
             'one scoped adapter with unchanged observer file limit')
        self.old_text = Path.write_text; self.old_bytes = Path.write_bytes
        def checked_text(path, data, encoding=None, errors=None, newline=None):
            if path.absolute() in self.exports:
                need(type(data) is str and data.isascii() and encoding is errors is newline is None and
                     not path.exists(), 'complete original ASCII-escaped JSON and default text-write parameters')
                # Shared json.dumps uses ensure_ascii=True: len(data) is the exact UTF-8 byte count.
                self.reserve(len(data), 'export '+path.name, 2*self.perf_file_bytes)
            return self.old_text(path, data, encoding=encoding, errors=errors, newline=newline)
        def checked_bytes(path, data):
            if path.absolute() in self.exports:
                need(type(data) is bytes and not path.exists(), 'complete original UTF-8 byte export')
                self.reserve(len(data), 'export '+path.name, 2*self.perf_file_bytes)
            return self.old_bytes(path, data)
        self.checked_text = checked_text; self.checked_bytes = checked_bytes
        Path.write_text = checked_text; Path.write_bytes = checked_bytes
        self.active = True; self.record['adapters_restored'] = False

    def restore(self):
        if not self.active: return
        unchanged = Path.write_text is self.checked_text and Path.write_bytes is self.checked_bytes
        Path.write_text = self.old_text; Path.write_bytes = self.old_bytes
        self.active = False; self.record['adapters_restored'] = True
        need(unchanged, 'scoped export adapters were not replaced')

    def receipt(self, value):
        # Reserve the whole unchanged serialization, not a shortened fallback receipt.
        encoder = json.JSONEncoder(sort_keys=True, indent=2, allow_nan=False)
        size = sum(len(part.encode('utf-8')) for part in encoder.iterencode(value))+1
        self.reserve(size+4096, 'final complete receipt')
        actual = sum(len(part.encode('utf-8')) for part in encoder.iterencode(value))+1
        need(actual <= size+4096, 'bounded receipt growth from its own allocation record')
