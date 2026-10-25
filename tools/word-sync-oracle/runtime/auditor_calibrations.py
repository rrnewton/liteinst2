"""Pure additive output-auditor vectors; never a native coverage substitute."""
import sys
if sys.flags.optimize:
    raise SystemExit("optimized Python is forbidden")
sys.dont_write_bytecode = True
from audit import calibration_prefix, listed, native_output, output
from guard import HERE, read


def main():
    inventory = read(HERE / "inventory.json")
    mode = inventory["native_modes"][0]
    native = native_output(mode)
    listing = listed(inventory)
    calibrations = calibration_prefix(inventory) + b"0.00s\n\n"
    accepted = [(mode["name"], native), ("calibration-list", listing), ("calibrations", calibrations)]
    for name, data in accepted:
        output(name, data, b"", inventory)
    lines = native.splitlines(keepends=True)
    reversed_lines = lines.copy()
    reversed_lines[0], reversed_lines[1] = reversed_lines[1], reversed_lines[0]
    negatives = [
        ("missing-native-case", mode["name"], b"".join(lines[1:]), b""),
        ("duplicate-native-case", mode["name"], lines[0] + native, b""),
        ("reordered-native-case", mode["name"], b"".join(reversed_lines), b""),
        ("wrong-native-terminal", mode["name"], native.replace(b"phases=96", b"phases=95"), b""),
        ("extra-native-line", mode["name"], native + b"PASS\n", b""),
        ("native-stderr", mode["name"], native, b"unexpected\n"),
        ("missing-list-name", "calibration-list", b"\n".join(listing.split(b"\n")[1:]), b""),
        ("renamed-list-name", "calibration-list", listing.replace(b"rejects_application_memory_corruption", b"renamed_case"), b""),
        ("missing-should-panic", "calibrations", calibrations.replace(b" - should panic", b"", 1), b""),
        ("unexpected-should-panic", "calibrations", calibrations.replace(b"keeps_default_memory_and_flags_exact ...", b"keeps_default_memory_and_flags_exact - should panic ...", 1), b""),
        ("ignored-calibration", "calibrations", calibrations.replace(b"0 ignored", b"1 ignored"), b""),
        ("filtered-calibration", "calibrations", calibrations.replace(b"0 filtered out", b"1 filtered out"), b""),
    ]
    assert len(accepted) == 3 and len(negatives) == len({row[0] for row in negatives}) == 12
    originals = dict(accepted)
    for label, name, data, stderr in negatives:
        assert data != originals[name] or stderr != b"", label
        try:
            output(name, data, stderr, inventory)
        except AssertionError:
            pass
        else:
            raise AssertionError("accepted required negative " + label)
    print("auditor-calibrations accepted=3 rejected=12", flush=True)


if __name__ == "__main__":
    main()
