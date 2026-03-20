#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dedrm.py — Standalone DeDRM entry point for agent and CLI use.

Usage:
    python3 dedrm.py remove_drm <input_file> -o <output_file>
    python3 dedrm.py remove_drm <input_file> --overwrite
    python3 dedrm.py remove_drm <input_file> --outputdir <dir>
    python3 dedrm.py help

This script is the single command an agent or user needs. It:
  1. Installs missing Python dependencies (lxml, pycryptodome).
  2. Builds DeDRM_plugin.zip from source if it is missing or stale.
  3. Delegates all arguments to the plugin's CLI unchanged.

The plugin zip is a local build cache — it is .gitignored and regenerated
automatically whenever source files change. Only the source in DeDRM_plugin/
is committed, keeping the repo fully auditable.

Exit codes:
    0  — success (DRM removed, output file written)
    1  — failure (decryption failed, unsupported format, missing key, etc.)
    2  — usage / argument error
"""

import os
import sys
import subprocess

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_HERE        = os.path.dirname(os.path.abspath(__file__))
_PLUGIN_DIR  = os.path.join(_HERE, 'DeDRM_plugin')
_PLUGIN_ZIP  = os.path.join(_HERE, 'DeDRM_plugin.zip')
_BUILD_SCRIPT = os.path.join(_HERE, 'build_plugin.py')
_REQ_FILE    = os.path.join(_HERE, 'requirements.txt')


# ---------------------------------------------------------------------------
# Step 1: dependency check
# ---------------------------------------------------------------------------

def _ensure_deps():
    """Install required packages if they are not importable."""
    needed = []
    try:
        import lxml  # noqa: F401
    except ImportError:
        needed.append('lxml')
    try:
        import Crypto  # noqa: F401
    except ImportError:
        needed.append('pycryptodome')

    if not needed:
        return

    print(f"DeDRM: installing missing dependencies: {', '.join(needed)}", file=sys.stderr)
    subprocess.check_call(
        [sys.executable, '-m', 'pip', 'install', '-r', _REQ_FILE],
        stdout=subprocess.DEVNULL,
    )


# ---------------------------------------------------------------------------
# Step 2: stale-zip detection and on-demand build
# ---------------------------------------------------------------------------

def _source_mtime():
    """Return the newest modification time of any .py source file in DeDRM_plugin/."""
    latest = 0.0
    for root, dirs, files in os.walk(_PLUGIN_DIR):
        dirs[:] = [d for d in dirs if d != '__pycache__']
        for name in files:
            if name.endswith('.py'):
                t = os.path.getmtime(os.path.join(root, name))
                if t > latest:
                    latest = t
    return latest


def _ensure_zip():
    """Build DeDRM_plugin.zip if it is absent or older than any source file."""
    needs_build = (
        not os.path.exists(_PLUGIN_ZIP)
        or os.path.getmtime(_PLUGIN_ZIP) < _source_mtime()
    )

    if needs_build:
        reason = "missing" if not os.path.exists(_PLUGIN_ZIP) else "source changed"
        print(f"DeDRM: building plugin zip ({reason}) ...", file=sys.stderr)
        subprocess.check_call([sys.executable, _BUILD_SCRIPT], stdout=subprocess.DEVNULL)


# ---------------------------------------------------------------------------
# Step 3: delegate to the plugin CLI
# ---------------------------------------------------------------------------

def main():
    _ensure_deps()
    _ensure_zip()

    result = subprocess.run(
        [sys.executable, _PLUGIN_ZIP] + sys.argv[1:],
        cwd=_HERE,
    )
    sys.exit(result.returncode)


if __name__ == '__main__':
    main()
