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
2. Builds the plugin zip from source
3. Runs the CLI

On subsequent runs it goes straight to step 3 (or rebuilds the zip if source has changed).

---

## Usage

```
python3 dedrm.py remove_drm <input> [options]

Options:
  -o / --output <file>      Output file path
  --outputdir <dir>         Output directory (uses original filename)
  --overwrite               Replace input file in-place (implies --force)
  -f / --force              Overwrite output if it already exists
  --config <path>           Path to JSON key config (default: dedrm.json in cwd)

Examples:
  python3 dedrm.py remove_drm book.epub -o book_nodrm.epub
  python3 dedrm.py remove_drm book.epub --overwrite
  python3 dedrm.py remove_drm *.epub --outputdir ./clean/
  python3 dedrm.py remove_drm book.epub --config ~/.config/dedrm.json
```

Exit codes: `0` = success, `1` = failure (decryption failed / no key), `2` = bad arguments.

---

## How Keys Are Found

The tool finds decryption keys in two ways, tried in order:

### 1. Auto-discovery (Windows and macOS only)

On first use against an encrypted book, the tool automatically extracts keys
from locally installed applications:

| App | Key type extracted |
|---|---|
| Adobe Digital Editions (ADE) | Adobe ADEPT key (covers most library ebooks) |
| Kindle for PC / Kindle for Mac | Kindle database key |
| NOOK Study | B&N PassHash key |
| NOOK (Microsoft Store, Windows only) | B&N PassHash key |

Discovered keys are saved to `dedrm.json` in the current directory so
subsequent runs are instant and require no installed apps.

### 2. Stored keys (`dedrm.json`)

Keys are stored in a JSON file:

```json
{
  "adeptkeys":  { "my_ade_key": "<hex>" },
  "kindlekeys": { "my_kindle_key": "<hex>" },
  "bandnkeys":  { "my_nook_key": "<hex>" },
  "serials":    ["1234567890abcdef"],
  "pids":       []
}
```

Use `--config` to point to a key file in a non-default location. On Linux
(where app-based auto-discovery is unavailable), populate `dedrm.json` by
exporting keys from ADE or Kindle on a Windows/Mac machine and transferring
the file.

---

## Supported Formats

| Format | DRM Type | Notes |
|---|---|---|
| `.epub` | Adobe ADEPT | Most library ebooks (OverDrive, etc.) |
| `.epub` | B&N PassHash | Barnes & Noble ebooks |
| `.epub` | LCP | **Not supported** — DMCA takedown |
| `.epub` | None | Passed through unchanged |
| `.pdf` | Adobe ADEPT (EBX) | ADE-protected PDFs |
| `.pdf` | Standard / password | Tries empty password + stored passphrases |
| `.pdf` | FileOpen | Not supported |
| `.mobi` `.azw` `.azw3` | Kindle | Kindle for PC/Mac key required |
| `.kfx` `.kfx-zip` | Kindle KFX | Same key as above |
| `.pdb` | eReader | Stored key required |

---

## Using as an Agent Skill

This repo is designed to be pulled and invoked by AI agents (e.g. Claude, OpenClaw,
or any tool-use agent) as a standalone skill — no Calibre, no manual setup, no GUI.

### Skill invocation

```bash
# Setup (once per environment — installs deps, builds plugin zip from source)
python3 dedrm.py remove_drm --help

# Remove DRM
python3 dedrm.py remove_drm "<input_file>" -o "<output_file>"
```

Exit codes: `0` = success, `1` = failure. All progress goes to stderr; exit code is
the only thing the agent needs to check.

### Skill descriptor (for agent registries)

```json
{
  "name": "dedrm",
  "description": "Remove DRM from ebooks (Adobe ADEPT, Kindle, B&N, eReader, PDF). Auto-discovers keys from ADE/Kindle installed on the same machine. Keys cached in dedrm.json after first use.",
  "requires": ["python3", "pip"],
  "setup": "python3 dedrm.py --help",
  "invoke": "python3 dedrm.py remove_drm <input_file> -o <output_file>",
  "exit_codes": { "0": "success — DRM-free output written", "1": "failure — decryption failed or no key", "2": "usage error — bad arguments" }
}
```

### Agent trust chain

```
1. agent clones repo
2. agent reads dedrm.py     (~80 lines: dep install, stale check, subprocess call)
3. agent reads build_plugin.py  (~60 lines: zip assembly from source)
4. agent reads DeDRM_plugin/*.py  (all DRM logic, fully auditable Python)
5. agent decides to trust
6. agent calls: python3 dedrm.py remove_drm book.epub -o book_nodrm.epub
7. dedrm.py installs deps if missing → builds zip if missing/stale → runs zip
```

No binary blobs in the repo. No network calls at runtime. No eval/exec of
downloaded code. The zip is a **local build cache** derived from the source the
agent already audited — it is `.gitignored` and never committed.

---

## Architecture and Design Decisions

### Why a plugin zip?

The DeDRM codebase was originally designed as a Calibre plugin. Each `.py`
file contains a `#@@CALIBRE_COMPAT_CODE@@` placeholder that the build system
(`build_plugin.py`) replaces with a small shim that:

- Adds the plugin directory to `sys.path`
- Installs a `_DeDRMFinder` import hook that maps `dedrm.X → X`, enabling
  the relative imports (`from .utilities import ...`) that the modules use
  without requiring a real Python package structure

Running `python3 DeDRM_plugin.zip` is therefore the correct execution model:
the zip is a self-contained Python application, not a library.

### Why the zip is not committed to git

`DeDRM_plugin.zip` is a **build artifact** — a transformed copy of the source
files in `DeDRM_plugin/`. Committing it would:

- Create an opaque binary that agents and reviewers cannot audit
- Risk the zip drifting out of sync with source
- Bloat git history

Instead, `dedrm.py` builds the zip on demand and caches it locally. It also
detects staleness: if any source file in `DeDRM_plugin/` is newer than the
zip, the zip is rebuilt automatically before the next run.

### Transparency for AI agents

This repo is designed to be used as a **skill by AI agents** (e.g. autonomous
coding agents, claw-style tool-use agents). The trust model requires that
every line the agent executes is auditable before execution:

```
agent reads source → verifies intent → python3 dedrm.py → auto-build → run
```

The full execution surface is:
- `dedrm.py` — entry point, ~80 lines, only does: dep check, stale detection, subprocess call
- `build_plugin.py` — ~60 lines, copies and patches source files into zip
- `DeDRM_plugin/` — all DRM logic, ~15 Python modules, all readable source
- `requirements.txt` — two packages (`lxml`, `pycryptodome`), pinned floor versions

No binary blobs. No network calls at runtime. No eval or exec of downloaded code.

### Key storage

Keys are written to `dedrm.json` in the working directory on first successful
decryption. This file is `.gitignored` — it contains private cryptographic
keys tied to personal accounts and must never be committed.

Use `--config <path>` to store the key file in a stable location (e.g.
`~/.config/dedrm/keys.json`) so it persists across working directory changes.

### Calibre plugin compatibility

None of the changes made for standalone use break the Calibre plugin:

- `__calibre_compat_code.py` changes are in an `else:` branch that only
  activates when Calibre is not present
- `prefs.py` import fix falls back to the original `from __init__ import`
  if `__version__` is unavailable (which never happens in Calibre)
- `make_release.py` still produces a valid `DeDRM_plugin.zip` for Calibre

### Linux / Wine

Auto-discovery of ADE and Kindle keys is Windows and macOS only (the key
extraction modules call OS-specific APIs). On Linux, populate `dedrm.json`
manually. The Calibre plugin supports Wine-based key extraction on Linux;
the standalone CLI does not.

---

## Files Changed vs. Upstream

| File | Change |
|---|---|
| `standalone/remove_drm.py` | Full implementation (was a non-functional stub) |
| `__calibre_compat_code.py` | Added `_DeDRMFinder` for Python 3.12+ standalone use |
| `prefs.py` | `from __init__` → `from __version__` (avoids import ambiguity in zip) |

New files (not upstream):

| File | Purpose |
|---|---|
| `dedrm.py` | Agent/CLI entry point — dep check, stale-zip rebuild, delegation |
| `build_plugin.py` | Fast zip builder for development iteration |
| `requirements.txt` | Explicit Python dependency list for standalone use |
| `STANDALONE_CLI.md` | This document |
| `dedrm_revision_plan.md` | Implementation plan and design decisions (dev reference) |
