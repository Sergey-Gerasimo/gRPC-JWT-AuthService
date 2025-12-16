#!/usr/bin/env python3
"""
Generate gRPC Python code from .proto files and fix imports to be package-relative.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys
from typing import Iterable


ROOT = pathlib.Path(__file__).resolve().parent.parent


def run_protoc(proto_files: Iterable[pathlib.Path], out_dir: pathlib.Path) -> None:
    cmd = [
        sys.executable,
        "-m",
        "grpc_tools.protoc",
        "-I",
        str(ROOT / "proto"),
        f"--python_out={out_dir}",
        f"--grpc_python_out={out_dir}",
        *map(str, proto_files),
    ]
    subprocess.run(cmd, check=True)


def fix_imports(out_dir: pathlib.Path, pkg: str) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "__init__.py").touch(exist_ok=True)

    pattern = re.compile(r"^import (\w+_pb2)( as \w+)?$", re.MULTILINE)

    for path in out_dir.glob("*_pb2*.py"):
        text = path.read_text()
        updated = pattern.sub(
            lambda m: f"from . import {m.group(1)}{m.group(2) or ''}", text
        )
        if updated != text:
            path.write_text(updated)
            print(f"fixed imports in {path.relative_to(ROOT)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--proto", default="proto/auth.proto", help="Path to .proto file"
    )
    parser.add_argument("--out", default="grpc_generated", help="Output directory")
    parser.add_argument(
        "--fix-imports-only",
        action="store_true",
        help="Only run import fix without regenerating proto code",
    )
    args = parser.parse_args()

    proto_path = (ROOT / args.proto).resolve()
    out_dir = (ROOT / args.out).resolve()

    if not args.fix_imports_only:
        run_protoc([proto_path], out_dir)

    fix_imports(out_dir, out_dir.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
