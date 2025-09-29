import os
import subprocess
import sys
import shutil
from pathlib import Path

def compile_with_zig(c_file: str, output_dir: str):
    # Ensure Zig is installed
    if not shutil.which("zig"):
        print("Error: Zig is not installed or not in PATH.")
        sys.exit(1)

    c_file = Path(c_file).resolve()
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    base_name = c_file.stem  # filename without extension

    targets = {
        "linux-x86_64": ("x86_64-linux-gnu", base_name),
        "windows-x86_64": ("x86_64-windows-gnu", base_name + ".exe"),
    }

    for name, (target, out_name) in targets.items():
        out_path = output_dir / out_name
        cmd = [
            "zig", "cc", "-target", target,
            str(c_file), "-o", str(out_path)
        ]
        print(f"[+] Compiling for {name}: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)
        print(f"    -> Built: {out_path}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Compile C source to Linux and Windows binaries using Zig.")
    parser.add_argument("c_file", help="Path to the C source file")
    parser.add_argument("-o", "--output", default="build", help="Output directory (default: build)")
    args = parser.parse_args()

    compile_with_zig(args.c_file, args.output)
