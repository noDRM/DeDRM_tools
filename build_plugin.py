#!/usr/bin/env python3
"""
Fast standalone build: creates DeDRM_plugin.zip directly in the repo root.
Usage: python3 build_plugin.py
Then:  python3 DeDRM_plugin.zip remove_drm <file> -o <output>
"""

import os, shutil, zipfile

SRC_DIR  = 'DeDRM_plugin'
OUT_ZIP  = 'DeDRM_plugin.zip'
TMP_DIR  = 'DeDRM_plugin_build_tmp'

def read_compat_code():
    with open(os.path.join(SRC_DIR, '__calibre_compat_code.py'), 'rb') as f:
        return f.read()

def patch(src_bytes, compat_code):
    out = []
    for line in src_bytes.splitlines(keepends=True):
        if line.strip().startswith(b'#@@CALIBRE_COMPAT_CODE@@'):
            out.append(compat_code)
        else:
            out.append(line)
    return b''.join(out)

def build():
    # Clean up
    shutil.rmtree(TMP_DIR, ignore_errors=True)
    shutil.copytree(SRC_DIR, TMP_DIR)

    compat_code = read_compat_code()

    # Patch all .py files
    for root, dirs, files in os.walk(TMP_DIR):
        # Skip __pycache__
        dirs[:] = [d for d in dirs if d != '__pycache__']
        for name in files:
            if name.endswith('.py'):
                path = os.path.join(root, name)
                with open(path, 'rb') as f:
                    data = f.read()
                patched = patch(data, compat_code)
                with open(path, 'wb') as f:
                    f.write(patched)

    # Create zip
    if os.path.exists(OUT_ZIP):
        os.remove(OUT_ZIP)
    with zipfile.ZipFile(OUT_ZIP, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(TMP_DIR):
            dirs[:] = [d for d in dirs if d != '__pycache__']
            for name in files:
                full = os.path.join(root, name)
                arcname = os.path.relpath(full, TMP_DIR)
                zf.write(full, arcname)

    shutil.rmtree(TMP_DIR, ignore_errors=True)
    print(f'Built: {OUT_ZIP}')

if __name__ == '__main__':
    build()
