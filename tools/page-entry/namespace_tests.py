"""Supplied-byte parser controls; these do not execute or qualify the loader."""
import unittest
import namespace as ns


def supplied(tags=None, strings=b"\0liba.so\0libowner.so\0"):
    data = bytearray(1024)
    ns.EH.pack_into(data, 0, b"\x7fELF\x02\x01\x01" + b"\0" * 9,
                    3, 62, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    ns.PH.pack_into(data, 64, 1, 4, 0, 0, 0, 1024, 1024, 4096)
    tags = tags if tags is not None else [(5, 512), (10, len(strings)), (1, 1), (14, 9), (0, 0)]
    ns.PH.pack_into(data, 120, 2, 4, 256, 256, 0, 16 * len(tags), 16 * len(tags), 8)
    for i, row in enumerate(tags):
        ns.DY.pack_into(data, 256 + i * 16, *row)
    data[512:512 + len(strings)] = strings
    return data


class NamespaceParser(unittest.TestCase):
    def test_complete_names_and_order(self):
        row = ns.parse(supplied())
        self.assertEqual(row, {"elf_type": 3, "needed": ["liba.so"],
                               "soname": "libowner.so", "interpreter": None})

    def test_dynamic_extent_and_singletons(self):
        for tags in ([(5, 512), (10, 9), (1, 1)],
                     [(5, 512), (5, 512), (10, 9), (0, 0)],
                     [(5, 512), (0, 0)], [(5, 1020), (10, 9), (0, 0)]):
            with self.subTest(tags=tags), self.assertRaises(ValueError):
                ns.parse(supplied(tags))

    def test_search_policy_is_refused(self):
        for tag in (15, 29, 0x6FFFFEFC, 0x6FFFFEFB, 0x7FFFFFFF, 0x7FFFFFFD):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                ns.parse(supplied([(5, 512), (10, 9), (tag, 1), (0, 0)]))

    def test_names_duplicates_and_offsets_are_checked(self):
        for strings in (b"\0../bad\0", b"\0bad/name\0", b"\0bad name\0", b"\0unterminated"):
            with self.subTest(strings=strings), self.assertRaises(ValueError):
                ns.parse(supplied([(5, 512), (10, len(strings)), (1, 1), (0, 0)], strings))
        for tags in ([(5, 512), (10, 9), (1, 1), (1, 1), (0, 0)],
                     [(5, 512), (10, 9), (1, 9), (0, 0)]):
            with self.subTest(tags=tags), self.assertRaises(ValueError):
                ns.parse(supplied(tags))

    def test_initialized_file_extent_is_required(self):
        data = supplied()
        ns.PH.pack_into(data, 64, 1, 4, 0, 0, 0, 512, 1024, 4096)
        with self.assertRaises(ValueError):
            ns.parse(data)  # String table in BSS is not file-backed evidence.
        data = supplied()
        ns.PH.pack_into(data, 120, 2, 4, 1000, 1000, 0, 80, 80, 8)
        with self.assertRaises(ValueError):
            ns.parse(data)


if __name__ == "__main__":
    unittest.main()
