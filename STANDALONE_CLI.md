# DeDRM Standalone CLI

Remove DRM from ebooks **without Calibre** using a single Python command.

Supports Adobe Digital Editions (ADEPT), Barnes & Noble PassHash, Kindle /
Mobipocket / KFX, eReader PDB, and standard password-encrypted PDFs.

---

## Quick Start

```bash
python3 dedrm.py remove_drm "My Book.epub" -o "My Book (DRM-free).epub"
```

That's it. On first run `dedrm.py` automatically:
1. Installs missing Python dependencies (`lxml`, `pycryptodome`)
2. Builds the plugin zip from source (cached locally, rebuilt if source changes)
3. Runs the CLI

Subsequent runs skip straight to step 3.

---

## Usage

```
python3 dedrm.py remove_drm <input> [options]

Options:
  -o / --output <file>      Write output to this file path
  --outputdir <dir>         Write output to this directory (keeps original filename)
  --overwrite               Replace the input file in-place (implies --force)
  -f / --force              Overwrite output file if it already exists
  --config <path>           Path to JSON key config (default: dedrm.json in cwd)

Examples:
  python3 dedrm.py remove_drm book.epub -o book_nodrm.epub
  python3 dedrm.py remove_drm book.epub --overwrite
  python3 dedrm.py remove_drm book.epub --outputdir ./clean/
  python3 dedrm.py remove_drm book.epub --config ~/.config/dedrm.json
```

> **Windows note:** shell glob expansion (`*.epub`) does not work in cmd.exe or
> PowerShell. Pass files individually or use a wrapper script.

**Exit codes:** `0` = success (DRM-free file written), `1` = failure (decryption
failed, file not found, no matching key).

**Output:** progress and status messages go to **stdout**; usage errors and
argument problems go to **stderr**.

---

## How Keys Are Found

The tool tries keys in this order for each book:

### 1. Stored keys (`dedrm.json`)

On every run, stored keys are tried first. Keys are read from a JSON file
(default: `dedrm.json` in the current working directory):

```json
{
  "adeptkeys":  { "my_ade_key": "<hex>" },
  "kindlekeys": { "my_kindle_key": "<hex>" },
  "bandnkeys":  { "my_nook_key": "<hex>" },
  "serials":    ["1234567890abcdef"],
  "pids":       []
}
```

Use `--config <path>` to specify a different location. This is useful for
keeping keys in a stable place (e.g. `~/.config/dedrm/keys.json`) so they
persist across working directory changes.

### 2. Auto-discovery (Windows and macOS only — fallback)

If stored keys fail or don't exist, the tool automatically extracts keys from
locally installed applications:

| App | Key type extracted | Platform |
|---|---|---|
| Adobe Digital Editions (ADE) | Adobe ADEPT key | Windows, macOS |
| Kindle for PC / Kindle for Mac | Kindle database key | Windows, macOS |
| NOOK Study | B&N PassHash key | Windows, macOS |
| NOOK (Microsoft Store) | B&N PassHash key | Windows only |

Successfully discovered keys are saved to `dedrm.json` automatically, so
subsequent runs use stored keys and don't need the app installed.

On Linux, auto-discovery is unavailable. Populate `dedrm.json` by exporting
keys from ADE or Kindle on a Windows/macOS machine and transferring the file.

---

## Supported Formats

| Format | DRM Type | Notes |
|---|---|---|
| `.epub` | Adobe ADEPT | Most library ebooks (OverDrive, etc.) |
| `.epub` | B&N PassHash | Barnes & Noble ebooks |
| `.epub` | LCP | **Not supported** — DMCA takedown |
| `.epub` | None | Passed through unchanged |
| `.pdf` | Adobe ADEPT (EBX) | ADE-protected PDFs |
| `.pdf` | Standard / password | Tries empty password then stored passphrases |
| `.pdf` | FileOpen | Not supported |
| `.mobi` `.azw` `.azw3` | Kindle | Requires Kindle for PC/Mac key |
| `.kfx` `.kfx-zip` | Kindle KFX | Same key as above |
| `.pdb` | eReader | Requires stored key in `dedrm.json` |

---

## Using as an Agent Skill

This repo is designed to be pulled and invoked by AI agents (e.g. Claude, OpenClaw,
or any tool-use agent) as a standalone skill — no Calibre, no manual setup, no GUI.

### Invocation

```bash
python3 dedrm.py remove_drm "<input_file>" -o "<output_file>"
```

Check the exit code: `0` = success, `1` = failure. Progress goes to stdout.

### Skill descriptor

```json
{
  "name": "dedrm",
  "description": "Remove DRM from ebooks (Adobe ADEPT, Kindle, B&N, eReader, PDF). Auto-discovers keys from ADE/Kindle installed on the same machine. Keys cached in dedrm.json after first successful decryption.",
  "requires": ["python3", "pip"],
  "invoke": "python3 dedrm.py remove_drm <input_file> -o <output_file>",
  "exit_codes": {
    "0": "success — DRM-free output written",
    "1": "failure — decryption failed, no matching key, or file not found"
  }
}
```

### Trust model

An agent can audit every line that will be executed before running anything:

```
1. clone repo
2. read dedrm.py          — ~115 lines: dep check, stale-zip detection, subprocess call
3. read build_plugin.py   — ~65 lines: copies source into zip, inlines compat shim
4. read DeDRM_plugin/*.py — ~48 Python modules, all DRM logic, fully readable source
5. decide to trust
6. python3 dedrm.py remove_drm book.epub -o book_nodrm.epub
   → installs deps if missing
   → builds DeDRM_plugin.zip from audited source if missing or stale
   → runs the zip
```

**No binary blobs committed. No network calls at runtime. No eval/exec of
downloaded code.** The zip is a local build cache — `.gitignored`, never
committed, always derived from the source the agent already read.

---

## Architecture and Design Decisions

### Why a plugin zip at all?

The DeDRM codebase was designed as a Calibre plugin. Each `.py` file contains a
`#@@CALIBRE_COMPAT_CODE@@` placeholder that `build_plugin.py` replaces with a shim
that:

- Adds the plugin directory to `sys.path`
- Installs a `_DeDRMFinder` import hook that maps `dedrm.X → X`, enabling the
  relative imports (`from .utilities import ...`) the modules use without a real
  Python package structure on disk

`python3 DeDRM_plugin.zip` is the correct execution model: the zip is a
self-contained Python application (Python's zipapp format), not a library.

### Why the zip is not committed to git

`DeDRM_plugin.zip` is a **build artifact** — a transformed copy of the source in
`DeDRM_plugin/`. Committing it would:

- Create an opaque blob that agents and reviewers cannot easily audit
- Risk the zip drifting out of sync with source
- Bloat git history with a binary that changes on every source edit

Instead, `dedrm.py` builds it on demand and caches it locally. Staleness is
detected by comparing the zip's mtime against the newest `.py` file in
`DeDRM_plugin/` — if any source is newer, the zip is rebuilt before the next run.

### Key storage and the missing-config case

Keys live in `dedrm.json` (or the path given to `--config`). If the file doesn't
exist, the tool prints a notice and continues with defaults — it will attempt
auto-discovery and create `dedrm.json` if new keys are found. The file is
`.gitignored` and must never be committed (it contains private keys tied to
personal accounts).

### Calibre plugin compatibility

None of these changes affect Calibre plugin behaviour:

- `__calibre_compat_code.py` standalone branch runs only when `"calibre"` is
  absent from `sys.modules`
- `prefs.py` import fix falls back gracefully inside Calibre
- `make_release.py` still produces a valid `DeDRM_plugin.zip` for Calibre users

### Linux / Wine

Key auto-discovery is Windows and macOS only (the modules call OS-specific APIs).
On Linux, populate `dedrm.json` manually. The Calibre plugin supports Wine-based
key extraction on Linux; the standalone CLI does not.

---

## Files Changed vs. Upstream

| File | Change |
|---|---|
| `DeDRM_plugin/standalone/remove_drm.py` | Full implementation (was a non-functional stub) |
| `DeDRM_plugin/standalone/__init__.py` | `execute_action` now propagates `perform_action` exit code via `sys.exit()` |
| `DeDRM_plugin/__calibre_compat_code.py` | Added `_DeDRMFinder` for standalone relative-import support |
| `DeDRM_plugin/prefs.py` | `from __init__` → `from __version__` (avoids import ambiguity in zip) |

New files (not upstream):

| File | Purpose |
|---|---|
| `dedrm.py` | Agent/CLI entry point — dep install, stale-zip rebuild, delegation |
| `build_plugin.py` | Zip builder — inlines compat shim, packages source into zipapp |
| `requirements.txt` | Explicit dependency list (`lxml>=4.6`, `pycryptodome>=3.9`) |
| `STANDALONE_CLI.md` | This document |
| `dedrm_revision_plan.md` | Developer design reference |
