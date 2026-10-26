#!/usr/bin/python3
"""Preserve actual linker inputs, then exec the pinned compiler driver once."""
import sys
if sys.flags.optimize:
    raise SystemExit("optimized Python is forbidden")
sys.dont_write_bytecode = True
import hashlib
import importlib.util
import json
import os
from pathlib import Path


def sha(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(512 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def main():
    assert sys.pycache_prefix is None
    frozen = Path(os.environ["UNWIND_SOURCE_FREEZE"])
    digest = os.environ["UNWIND_SOURCE_FREEZE_SHA256"]
    assert frozen.resolve(strict=True) == frozen
    assert sha(frozen / "freeze.json") == digest
    data = json.loads((frozen / "freeze.json").read_text())
    owner = Path(data["adapter"]) / "adapter.py"
    assert owner.is_file() and not owner.is_symlink() and owner.resolve(strict=True) == owner
    relative = str(owner.relative_to(Path(data["root"])))
    source = owner.read_bytes()
    assert hashlib.sha256(source).hexdigest() == data["source_files"][relative]
    name = "_unwind_linker_adapter"
    assert name not in sys.modules
    spec = importlib.util.spec_from_file_location(name, owner)
    assert spec is not None and spec.origin == str(owner)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        exec(compile(source, str(owner), "exec", dont_inherit=True, optimize=0), vars(module))
        assert module.verify(frozen, digest) == data
        shim = frozen / "build/linker-capture"
        assert Path(__file__).resolve(strict=True) == shim
        shim_binding = json.loads((frozen / "build/linker-shim.json").read_text())
        assert sha(shim) == shim_binding["sha256"]
        assert sha(sys.executable) == data["tools"]["helper_python"]["sha256"]
        args = sys.argv[1:]
        assert args.count("-o") == 1
        output = Path(args[args.index("-o") + 1])
        assert output in [frozen / "build" / n for n in ("consumer-main", "consumer-launcher", "consumer-calibrations")]
        assert not output.exists()
        archive = Path(str(output) + ".link-inputs")
        archive.mkdir()
        records = []
        for arg in args:
            if arg.startswith("-"):
                continue
            path = Path(arg)
            if not path.is_absolute():
                path = Path(data["root"]) / path
            if not path.is_file():
                continue
            h = sha(path)
            copied = archive / (str(len(records)) + "-" + path.name)
            with path.open("rb") as src, copied.open("xb") as dst:
                for block in iter(lambda: src.read(512 * 1024), b""):
                    dst.write(block)
            assert sha(path) == sha(copied) == h
            records.append(dict(path=str(path), resolved_path=str(path.resolve()), sha256=h,
                                archive=str(copied), archive_sha256=h))
        assert records and any(row["path"].endswith(".o") for row in records)
        assert module.verify(frozen, digest) == data
        record = dict(argv=[data["tools"]["gcc"]["path"]] + args, cwd=data["root"], files=records,
                      freeze_sha256=digest, compiler_sha256=data["tools"]["gcc"]["sha256"],
                      linker_stdout=str(output) + ".linker.stdout", execution_result_not_yet_observed=True)
        with Path(str(output) + ".link-inputs.json").open("x") as stream:
            stream.write(json.dumps(record, indent=2, sort_keys=True) + "\n")
        fd = os.open(record["linker_stdout"], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        if fd != 1:
            os.dup2(fd, 1)
            os.close(fd)
        environment = dict(data["environment"])
    finally:
        del sys.modules[name]
    os.execve(data["tools"]["gcc"]["path"], record["argv"], environment)


if __name__ == "__main__":
    main()
