"""macOS build helper — creates a portable .app bundle with PyInstaller.

Usage (on a Mac):
    pip install -r requirements.txt
    python build_mac.py

Output:  dist/NetProbe.app  (self-contained bundle)
         Zip it and it runs from anywhere — Downloads, USB stick, a folder
         on a shared drive. No install needed.

The honest truth about "portable" on macOS:
    There is no single-file executable the way Windows has .exe.  macOS apps
    ARE bundles — a folder with a .app extension that macOS treats as one
    unit.  PyInstaller's onedir mode produces exactly that.  Zip the .app and
    it's as portable as it gets on this platform.

Gatekeeper / signing:
    - Built on your own Mac (ad-hoc, unsigned):  it runs on YOUR machine
      without ceremony.  When you give it to someone else, macOS will block
      the first launch:  "cannot be opened because the developer cannot be
      verified."  The user right-clicks → Open → Open (once), then it runs.
      Acceptable for friends/family; bad for a real product.
    - Real distribution:  sign with a Developer ID + notarize with Apple
      (requires an Apple Developer account, $99/year).  Then it installs
      with no warnings.  This script does NOT do that — see the signing
      section at the bottom for how.
"""

import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent


def embed_version():
    """Write current git SHA to netprobe/version.py so it's bundled."""
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

    version_file = PROJECT_DIR / "netprobe" / "version.py"
    version_file.write_text(
        f'# Auto-generated at build time\n'
        f'__version_sha__ = "{sha}"\n'
        f'__build_time__ = "{datetime.now().isoformat()}"\n'
    )
    print(f"  Version SHA: {sha[:7]} ({sha})")
    return sha


def main():
    print("=" * 60)
    print("NetProbe - macOS portable build")
    print(f"  Platform: {sys.platform}")
    print(f"  Python:   {sys.version.split()[0]}")
    print("=" * 60)

    if sys.platform != "darwin":
        print("ERROR: this script must run on macOS (PyInstaller can't cross-build).")
        sys.exit(1)

    spec = PROJECT_DIR / "netprobe-mac.spec"
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

    app_dir = PROJECT_DIR / "dist" / "NetProbe.app"
    if not app_dir.exists():
        print("\nERROR: expected NetProbe.app but it wasn't produced.")
        sys.exit(1)

    size_mb = sum(f.stat().st_size for f in app_dir.rglob('*') if f.is_file()) / (1024 * 1024)
    zip_path = PROJECT_DIR / "dist" / "NetProbe-mac.zip"
    print(f"\nDONE - {size_mb:.0f} MB bundle")
    print(f"  {app_dir}")
    print("  Creating distributable zip...")
    shutil.make_archive(str(zip_path.with_suffix("")), "zip", PROJECT_DIR / "dist", "NetProbe.app")
    print(f"  {zip_path}")
    print("\nDistribute the zip. Recipient unzips and drags NetProbe.app to")
    print("Applications, or runs it from the unzipped folder.")


# ---------------------------------------------------------------------------
# Real distribution (future): signing + notarization
#
#   # 1. Sign the .app with your Developer ID Application certificate
#   codesign --force --deep --options runtime \
#     --sign "Developer ID Application: Your Name (TEAMID)" \
#     dist/NetProbe.app
#
#   # 2. Notarize with Apple
#   xcrun notarytool submit dist/NetProbe.app --keychain-profile "notary" --wait
#
#   # 3. Staple the ticket so offline machines trust it
#   xcrun stapler staple dist/NetProbe.app
#
#   # 4. Re-zip and distribute
#   Requires an Apple Developer account ($99/yr). Until then, ad-hoc builds
#   work for your own machines and for users willing to right-click → Open.
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()
