"""Supplied ELF/namespace controls; no target loader or admission execution."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import namespace as ns
from namespace_tests import supplied


def image(needed=(), soname=None, interpreter=None, search_tag=None):
    strings = bytearray(b"\0")
    tags = [(5, 512), (10, 0)]
    for tag, name in [(1, name) for name in needed] + ([(14, soname)] if soname else []):
        tags.append((tag, len(strings)))
        strings.extend(name.encode("ascii") + b"\0")
    tags[1] = (10, len(strings))
    if search_tag is not None:
        tags.append((search_tag, 0))
    tags.append((0, 0))
    data = supplied(tags, bytes(strings))
    if interpreter is not None:
        path = os.fsencode(interpreter) + b"\0"
        assert len(path) <= 256
        header = list(ns.EH.unpack_from(data))
        header[10] = 3
        ns.EH.pack_into(data, 0, *header)
        ns.PH.pack_into(data, 176, 3, 4, 768, 0, 0, len(path), len(path), 1)
        data[768:768 + len(path)] = path
    return bytes(data)


class LateNamespace(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.interp = self.put("ld-supplied.so")
        self.original = self.put("main", needed=("libbase.so",), interpreter=self.interp)
        self.put("libbase.so", needed=("libshared.so",))
        self.put("libshared.so")
        self.put("liblate.so", needed=("libshared.so", "libleaf.so"))
        self.put("libleaf.so")
        self.args = (self.original, [self.root], hashlib.sha256(self.original.read_bytes()).digest(),
                     hashlib.sha256(self.interp.read_bytes()).digest())

    def put(self, name, **kwargs):
        path = self.root / name
        path.write_bytes(image(soname=name, **kwargs))
        return path

    def test_default_exact_and_late_transitive_order(self):
        original, description = ns.plan(*self.args)
        self.assertEqual(ns.plan(*self.args, late_sonames=()), (original, description))
        self.assertEqual(ns.plan(*self.args, late_sonames=[]), (original, description))
        self.assertEqual([p["path"].name for p in original], ["libbase.so", "libshared.so"])
        self.assertNotIn("late_preauthorization", description)
        objects, expanded = ns.plan(*self.args, late_sonames=["liblate.so"])
        self.assertEqual(objects[:2], original)
        self.assertEqual([p["path"].name for p in objects],
                         ["libbase.so", "libshared.so", "liblate.so", "libleaf.so"])
        late = expanded.pop("late_preauthorization")
        self.assertEqual(expanded, description)
        self.assertEqual(late, {"scope": "sealed_inputs_only_not_loaded_or_admitted",
                               "startup_object_count": 2,
                               "requested": [{"soname": "liblate.so", "object_index": 2}],
                               "additional_object_indexes": [2, 3]})

    def test_prepared_manifest_binds_exact_sealed_bytes(self):
        objects, _ = ns.plan(*self.args, late_sonames=["liblate.so"])
        with mock.patch.object(os, "execve", side_effect=AssertionError("preparation must not exec")):
            fds, directory = ns.prepare(self.original, [self.root], self.root / "namespace",
                                        self.args[2], self.args[3], late_sonames=["liblate.so"])
        try:
            record = json.loads((directory / "namespace.json").read_text())
            self.assertEqual(record["status"], "prepared_not_executed")
            self.assertEqual(len(fds), 4)
            self.assertEqual(record["late_preauthorization"]["requested"],
                             [{"soname": "liblate.so", "object_index": 2}])
            self.assertEqual(record["late_preauthorization"]["additional_object_indexes"], [2, 3])
            for fd, item, row in zip(fds, objects, record["objects"], strict=True):
                self.assertEqual(os.pread(fd, ns.MAX_FILE + 1, 0), item["bytes"])
                self.assertEqual(row["fd"], fd)
                self.assertEqual(row["size"], len(item["bytes"]))
                self.assertEqual(row["sha256"], hashlib.sha256(item["bytes"]).hexdigest())
                self.assertEqual(row["seals"], ns.SEALS)
                self.assertEqual(fcntl.fcntl(fd, fcntl.F_GET_SEALS), ns.SEALS)
                for name in row["names"]:
                    self.assertEqual(os.readlink(directory / name), "/proc/self/fd/" + str(fd))
        finally:
            for fd in reversed(fds):
                os.close(fd)

    def test_plain_names_duplicates_and_request_bound(self):
        invalid = [(None,), (b"liblate.so",), ("",), (".",), ("..",), ("a/b",),
                   ("../a",), ("a b",), ("a\0b",), ("\u00e9.so",), ("x" * 256,)]
        for names in invalid:
            with self.subTest(names=names), self.assertRaisesRegex(ValueError, "plain SONAME"):
                ns.plan(*self.args, late_sonames=names)
        for value in (None, "liblate.so", {"liblate.so"}, tuple("lib%d.so" % i for i in range(33))):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "list bound/type"):
                ns.plan(*self.args, late_sonames=value)
        with self.assertRaisesRegex(ValueError, "duplicate late SONAME"):
            ns.plan(*self.args, late_sonames=["liblate.so", "liblate.so"])
        self.put("x" * 255)
        self.assertEqual(len(ns.plan(*self.args, late_sonames=["x" * 255])[0]), 3)

    def test_existing_aliases_and_cycles_keep_original_rules(self):
        (self.root / "libalias.so").symlink_to("liblate.so")
        objects, description = ns.plan(*self.args, late_sonames=["libalias.so", "liblate.so", "libbase.so"])
        self.assertEqual(len(objects), 4)
        self.assertEqual(description["late_preauthorization"]["requested"],
                         [{"soname": "libalias.so", "object_index": 2},
                          {"soname": "liblate.so", "object_index": 2},
                          {"soname": "libbase.so", "object_index": 0}])
        self.put("libleaf.so", needed=("liblate.so",))
        self.assertEqual(len(ns.plan(*self.args, late_sonames=["liblate.so"])[0]), 4)

    def test_late_missing_search_and_ambiguous_names_refuse(self):
        with self.assertRaisesRegex(ValueError, "absent from explicit roots"):
            ns.plan(*self.args, late_sonames=["missing.so"])
        (self.root / "libleaf.so").unlink()
        with self.assertRaisesRegex(ValueError, "absent from explicit roots"):
            ns.plan(*self.args, late_sonames=["liblate.so"])
        self.put("libleaf.so")
        self.put("liblate.so", search_tag=29)
        with self.assertRaisesRegex(ValueError, "search/audit/filter"):
            ns.plan(*self.args, late_sonames=["liblate.so"])
        (self.root / "liblate.so").write_bytes(image(soname="libbase.so"))
        with self.assertRaisesRegex(ValueError, "ambiguous dependency SONAME"):
            ns.plan(*self.args, late_sonames=["liblate.so"])

    def test_startup_and_late_objects_share_original_capacity(self):
        for index in range(31):
            self.put("chain%d.so" % index,
                     needed=(("chain%d.so" % (index + 1),) if index < 29 else ()))
        self.assertEqual(len(ns.plan(*self.args, late_sonames=["chain0.so"])[0]), 32)
        self.put("chain29.so", needed=("chain30.so",))
        with self.assertRaisesRegex(ValueError, "sealed dependency count"):
            ns.plan(*self.args, late_sonames=["chain0.so"])

    def test_loader_cli_passes_only_explicit_late_roots(self):
        import carrier
        argv = ["carrier.py", "exec-loader", "--library-root", str(self.root),
                "--namespace", str(self.root / "unused"), "--late-soname", "liblate.so",
                "--late-soname", "libleaf.so", "carrier", "original", "--", "original"]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(carrier, "execute_loader") as call:
            carrier.main()
        self.assertEqual(call.call_count, 1)
        self.assertEqual(call.call_args.kwargs,
                         {"disable_rseq": False, "provider_policy": None,
                          "late_sonames": ["liblate.so", "libleaf.so"]})
        self.assertEqual(call.call_args.args[4], ["original"])
        self.assertEqual(call.call_args.args,
                         (Path("carrier"), Path("original"), [self.root],
                          self.root / "unused", ["original"]))
        # argparse consumes an option delimiter; it is not application argv.
        # The no-late invocation retains all original parser/dispatch defaults.
        for delimiter in ([], ["--"]):
            argv = ["carrier.py", "exec-loader", "--library-root", str(self.root),
                    "--namespace", str(self.root / "unused"), "carrier", "original"]
            argv += delimiter + ["original", "native"]
            with self.subTest(delimiter=delimiter), mock.patch.object(sys, "argv", argv), \
                    mock.patch.object(carrier, "execute_loader") as call:
                carrier.main()
            self.assertEqual(call.call_count, 1)
            self.assertEqual(call.call_args.args,
                             (Path("carrier"), Path("original"), [self.root],
                              self.root / "unused", ["original", "native"]))
            self.assertEqual(call.call_args.kwargs,
                             {"disable_rseq": False, "provider_policy": None,
                              "late_sonames": []})


if __name__ == "__main__":
    unittest.main()
