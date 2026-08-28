"""Global pytest configuration for LinkSight test suite."""

import ctypes
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

for _egl in [
    "/opt/data/home/egl/usr/lib/x86_64-linux-gnu/libEGL.so.1",
    "/usr/lib/x86_64-linux-gnu/libEGL.so.1",
]:
    if os.path.exists(_egl):
        try:
            ctypes.CDLL(_egl, mode=ctypes.RTLD_GLOBAL)
            break
        except Exception:
            pass
