"""Windows build helper — creates a portable app bundle with PyInstaller.

Usage (on Windows — x64 or ARM64):
    pip install -r requirements.txt
    python build_exe.py

Output:  dist/LinkSight/LinkSight.exe  (~60-80 MB, self-contained)
         No install needed — run directly from the folder.

Why onedir instead of onefile:
    A single EXE decompresses the bundle to a temp directory on every launch
    (5-15 s startup). onedir extracts once at build time and starts instantly.
    The folder is still portable — zip it and it runs anywhere.
"""

import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent


def embed_version():
    """Write current git SHA to version.py so it's bundled into the exe."""
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
        f'# Auto-generated at build time by build_exe.py\n'
        f'__version_sha__ = "{sha}"\n'
        f'__build_time__ = "{datetime.now().isoformat()}"\n'
    )
    print(f"  Version SHA: {sha[:7]} ({sha})")
    return sha


def main():
    print("=" * 60)
    print("LinkSight - Windows portable build")
    print(f"  Platform: {sys.platform}")
    print(f"  Python:   {sys.version.split()[0]}")
    print("=" * 60)

    spec = PROJECT_DIR / "linksight.spec"
    if not spec.exists():
        print(f"ERROR: {spec} not found")
        sys.exit(1)

    print("\n[1/3] Embedding version info...")
    embed_version()

    print("\n[2/3] Cleaning previous build...")
    for d in ["build", "dist"]:
        p = PROJECT_DIR / d
        if p.exists():
            shutil.rmtree(p)
            print(f"  Removed {d}/")

    print("\n[3/3] Running PyInstaller...")
    cmd = [sys.executable, "-m", "PyInstaller", str(spec)]
    result = subprocess.run(cmd, cwd=PROJECT_DIR)

    if result.returncode != 0:
        print("\nBuild FAILED. See output above for errors.")
        sys.exit(1)

    exe_dir = PROJECT_DIR / "dist" / "LinkSight"
    exe_path = exe_dir / "LinkSight.exe"
    size_mb = sum(f.stat().st_size for f in exe_dir.rglob('*') if f.is_file()) / (1024 * 1024) if exe_dir.exists() else 0
    print(f"\nDONE - {size_mb:.0f} MB folder")
    print(f"  {exe_path}")
    print("\nDistribute the entire 'LinkSight' folder, or zip it for sharing.")
    print("Startup is instant - no decompression on every launch.")


if __name__ == "__main__":
    main()

