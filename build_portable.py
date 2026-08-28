"""LinkSight single-file portable build (for remote deployment tools).

Usage (Windows):
    python build_portable.py

Output:  dist/LinkSight-Portable.exe  (~50-60 MB, ONE file, no _internal)

The onedir build (build_exe.py) is faster at launch but ships as a folder
with _internal/.  This build bundles everything into a single exe that
extracts to a temp dir on each run — slower to start (5-15s) but the file
can be pushed to a client device by a remote-tool that only moves one file.
"""

import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent


def embed_version():
    sha = "unknown"
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, cwd=PROJECT_DIR,
            timeout=5,
        )
        if result.returncode == 0:
            sha = result.stdout.strip()
    except Exception:
        pass
    version_file = PROJECT_DIR / "linksight" / "version.py"
    version_file.write_text(
        f'# Auto-generated at build time by build_portable.py\n'
        f'__version_sha__ = "{sha}"\n'
        f'__build_time__ = "{datetime.now().isoformat()}"\n'
    )
    print(f"  Version SHA: {sha[:7]} ({sha})")
    return sha


def main():
    print("=" * 60)
    print("LinkSight - single-file portable build")
    print(f"  Platform: {sys.platform}")
    print(f"  Python:   {sys.version.split()[0]}")
    print("=" * 60)

    if sys.platform != "win32":
        print("ERROR: this script must run on Windows (PyInstaller can't cross-build).")
        sys.exit(1)

    spec = PROJECT_DIR / "linksight-onefile.spec"
    if not spec.exists():
        print(f"ERROR: {spec} not found")
        sys.exit(1)

    print("\n[1/3] Embedding version info...")
    embed_version()

    print("\n[2/3] Cleaning previous build...")
    build_dir = PROJECT_DIR / "build"
    if build_dir.exists():
        shutil.rmtree(build_dir)
        print(f"  Removed build/")
    # NOTE: dist/ is NOT cleaned here — a prior step (build_exe.py) may have
    # placed the folder build + zip there; we only add our single exe.

    print("\n[3/3] Running PyInstaller (onefile)...")
    cmd = [sys.executable, "-m", "PyInstaller", str(spec), "--noconfirm"]
    result = subprocess.run(cmd, cwd=PROJECT_DIR)

    if result.returncode != 0:
        print("\nBuild FAILED. See output above for errors.")
        sys.exit(1)

    exe_path = PROJECT_DIR / "dist" / "LinkSight-Portable.exe"
    if not exe_path.exists():
        print("\nERROR: expected LinkSight-Portable.exe but it wasn't produced.")
        sys.exit(1)

    size_mb = exe_path.stat().st_size / (1024 * 1024)
    print(f"\nDONE - {size_mb:.0f} MB single file")
    print(f"  {exe_path}")
    print("\nPush this ONE file to any Windows device. No _internal folder,")
    print("no install, no dependencies. Startup takes a few seconds longer.")


if __name__ == "__main__":
    main()

