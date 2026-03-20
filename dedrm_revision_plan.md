# DeDRM Standalone CLI — Implementation Plan

> **Status: IMPLEMENTED** — See `STANDALONE_CLI.md` for the user-facing documentation.
> This file is the developer/design reference.

## Goal

Make the standalone CLI fully functional without requiring Calibre to be installed,
**and** make it usable as a skill by AI agents with a full transparency/audit model.

### Extended goal (added post-initial-plan)

The tool should be safe for an AI agent to pull and invoke without requiring the agent
to trust a pre-built binary. Design decisions to support this:

- **No committed build artifacts**: `DeDRM_plugin.zip` is `.gitignored`. Agents audit
  source, then the entry point builds the zip on demand from that audited source.
- **Single entry point**: `dedrm.py` (~80 lines) handles dep install, stale detection,
  and delegation. The agent only needs to know one command.
- **Stale detection**: `dedrm.py` compares the zip mtime against the newest source file
  mtime. If source is newer, the zip is rebuilt. Safe to call repeatedly.
- **Calibre plugin unchanged**: all changes are additive or in standalone-only branches.

Original goal (standalone CLI implementation):

Make the standalone CLI (`python3 DeDRM_plugin.zip remove_drm <file>`) fully functional
without requiring Calibre to be installed. All the DRM-removal logic already exists in
the individual format modules; only the "glue" in `standalone/remove_drm.py` is missing.

---

## The One File to Change

**`DeDRM_plugin/standalone/remove_drm.py`**

Minor threading change needed in `perform_action()` to pass `config_path` down to
`dedrm_single_file()`. No other files need editing.

---

## What Already Exists and Works

| Module | What it does |
|---|---|
| `ineptepub.py` | Adobe Adept / B&N PassHash ePub decryption |
| `ineptpdf.py` | Adobe Adept / Standard / B&N PDF decryption |
| `k4mobidedrm.py` | Kindle / Mobipocket / Topaz / KFX decryption |
| `kfxdedrm.py` | KFX decryption engine (called internally by k4mobidedrm) |
| `erdr2pml.py` | eReader PDB decryption |
| `lcpdedrm.py` | LCP stub (raises immediately — DMCA takedown) |
| `zipfix.py` | ZIP repair before ePub processing |
| `epubfontdecrypt.py` | Post-process: deobfuscate ePub fonts |
| `adobekey.py` | Auto-extract ADE keys (Win/Mac) |
| `kindlekey.py` | Auto-extract Kindle keys (Win/Mac) |
| `ignoblekeyNookStudy.py` | Auto-extract Nook Study keys (Win/Mac) |
| `ignoblekeyWindowsStore.py` | Auto-extract Nook Store keys (Win only) |
| `adobekey_get_passhash.py` | Auto-extract ADE PassHash keys (Win only) |
| `prefs.py` | Config / key storage (works without Calibre via `standalone/jsonconfig.py`) |
| `standalone/__init__.py` | CLI arg parsing, calls `perform_action` |
| `standalone/remove_drm.py` | **STUB — this is the only thing to implement** |

---

## Calibre Plugin vs Standalone: Key Differences

### What the Calibre plugin does that standalone must replace

| Calibre API | Standalone replacement |
|---|---|
| `self.temporary_file(".epub")` | `tempfile.mkstemp(suffix=".epub")` + `os.close(fd)` |
| `self.starttime` | Local `starttime = time.time()` |
| `self.alfdir` (Wine key extraction on Linux) | Skipped — stored keys in prefs still work on Linux |
| `self.postProcessEPUB()` | Inline: check `deobfuscate_fonts` pref, call `epubfontdecrypt.decryptFontsBook()` directly |
| `checkForDeACSMkeys()` in `config.py` | **Skipped** — Calibre-only bridge to the DeACSM Calibre plugin (see note below) |

### How the Calibre plugin routes files

The Calibre plugin's `run()` routes by **file extension** (`.epub`, `.pdf`, `.mobi`, etc.).
The standalone's `determine_file_type()` routes by **magic bytes** — smarter and extension-agnostic.

### Failure semantics

- **Calibre**: Returns the still-encrypted file path so Calibre can handle it gracefully.
- **Standalone**: Returns `False`, prints an error, and produces **no output file**.
  This is correct CLI behavior — a partial/silent failure would be confusing.

### DeACSM note

`checkForDeACSMkeys()` in `config.py` is 100% Calibre-specific:
- Imports `calibre_plugins.deacsm.libadobeAccount` (another Calibre plugin)
- Uses `calibre.ptempfile.TemporaryFile`

These imports are impossible outside Calibre. The key it produces is identical in format
to what `adobekey.py` already auto-discovers from a native ADE installation. For users
who use DeACSM instead of ADE (no native ADE installed), the workaround is to manually
export the key and add it to `dedrm.json`. A future task could add a probe for DeACSM's
on-disk activation data (stored in Calibre's config directory).

---

## Bugs Fixed vs Calibre Original

### PassHash loop bug (Calibre `__init__.py` line ~472)

In `ePubDecrypt`, after trying auto-discovered NOOK/PassHash keys, the original code has
`return inf.name` **inside** the for loop — so it returns the still-encrypted file after
the very first key attempt, regardless of whether it succeeded. Standalone fixes this:
only set `decrypted_file` on success, continue the loop on failure, return `None` after
exhausting all keys.

---

## Implementation: Functions to Add/Replace

### 1. Helper: `_make_temp_file(suffix) → str`

```python
def _make_temp_file(suffix):
    import tempfile
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    return path
```

Creates a named temp file that persists on disk. Returns the path string.

---

### 2. Helper: `_pdf_inept_decrypt(input_file, dedrmprefs, starttime) → str | None`

Models `DeDRM.PDFIneptDecrypt()`. Handles Adobe Adept EBX and B&N PDFs.

Logic:
1. Try `ineptpdf.adeptGetUserUUID()` to detect which account the book is for.
2. Try UUID-matched key from `dedrmprefs['adeptkeys']` first.
3. Try all stored adept keys.
4. Auto-discover via `adobekey.adeptkeys()` (Win/Mac only), try each new key, save successes.
5. Try B&N keys from `dedrmprefs['bandnkeys']`.
6. Return temp file path on success, `None` on failure.
7. Catch `ineptpdf.ADEPTNewVersionError` and return `None` immediately (unsupported DRM version).

---

### 3. Helper: `_pdf_standard_decrypt(input_file, dedrmprefs, starttime) → str | None`

Models `DeDRM.PDFStandardDecrypt()`. Handles password-protected PDFs.

Logic:
1. Build password list: `[""] + dedrmprefs['adobe_pdf_passphrases']`.
2. For each password: call `ineptpdf.decryptBook(bytearray(pw, "utf-8"), ...)`.
3. Catch `ineptpdf.ADEPTInvalidPasswordError` to distinguish wrong password from other errors.
4. Return temp file path on first success, `None` if all fail.

---

### 4. Main: Replace `dedrm_single_file(input_file, output_file, config_path)` stub

**Signature change:** adds `config_path` parameter (threaded from `perform_action` which
already has it via `standalone.config_file_path`).

The function returns `True` on success, `False` on failure. On failure, no output file
is written and the caller should exit non-zero.

**Imports needed at top of function:**
```python
import codecs, time, shutil, traceback, tempfile
```

**Flow:**

```
1. starttime = time.time()
2. ftype = determine_file_type(input_file)   # already implemented in file
3. dedrmprefs = prefs.DeDRM_Prefs(os.path.abspath(config_path))
4. Branch on ftype:
   - "MOBI" / "TPZ" / "KFX" / "KFX-ZIP"  → Kindle branch
   - "PDB"                                 → eReader branch
   - "PDF"                                 → PDF branch
   - "LCP" / "ADEPT" / "ADEPT-PassHash" / "ZIP"  → ePub branch
   - else                                  → print error, return False
5. If decrypted_file is None → print error, return False
6. Post-process ePub (font deobfuscation) if applicable
7. Copy decrypted_file → output_file via shutil.copy2()
8. Clean up temp files (but never delete input_file)
9. Return True
```

#### Kindle branch ("MOBI", "TPZ", "KFX", "KFX-ZIP")

```python
import k4mobidedrm
pids = list(dedrmprefs['pids'])
serials = list(dedrmprefs['serials'])
for v in dedrmprefs['androidkeys'].values():
    serials.extend(v)
kindleDatabases = list(dedrmprefs['kindlekeys'].items())

try:
    book = k4mobidedrm.GetDecryptedBook(input_file, kindleDatabases, [], serials, pids, starttime)
except Exception as e:
    # Auto-discover via kindlekey.kindlekeys() (Win/Mac only)
    # Try again with new keys, save successes to prefs
    # If still fails → return False

ext = book.getBookExtension()         # e.g. ".azw3"
decrypted_file = _make_temp_file(ext)
book.getFile(decrypted_file)
book.cleanup()
```

#### eReader branch ("PDB")

```python
import erdr2pml
for keyname, userkey in dedrmprefs['ereaderkeys'].items():
    tmp = _make_temp_file(".pmlz")
    result = erdr2pml.decryptBook(input_file, tmp, True, codecs.decode(userkey, 'hex'))
    if result == 0:
        decrypted_file = tmp
        break
    os.remove(tmp)
# If no key worked → decrypted_file remains None → return False
```

#### PDF branch ("PDF")

```python
import ineptpdf, lcpdedrm
if lcpdedrm.isLCPbook(input_file):
    # lcpdedrm.decryptLCPbook() raises immediately (DMCA). Catch and return False.
    decrypted_file = lcpdedrm.decryptLCPbook(input_file, dedrmprefs['lcp_passphrases'], None)
else:
    enc = ineptpdf.getPDFencryptionType(input_file)
    if enc is None:
        decrypted_file = input_file      # DRM-free: pass-through to copy
    elif enc == "EBX_HANDLER":
        decrypted_file = _pdf_inept_decrypt(input_file, dedrmprefs, starttime)
    elif enc in ("Standard", "Adobe.APS"):
        decrypted_file = _pdf_standard_decrypt(input_file, dedrmprefs, starttime)
    elif enc in ("FOPN_fLock", "FOPN_foweb"):
        print("FileOpen encryption is unsupported."); return False
    else:
        print(f"Unsupported PDF encryption: {enc}"); return False
```

#### ePub branch ("LCP", "ADEPT", "ADEPT-PassHash", "ZIP")

```python
import zipfix, ineptepub, lcpdedrm

# 1. Repair ZIP
tmp_fixed = _make_temp_file(".epub")
zipfix.fixZip(input_file, tmp_fixed).fix()

if ftype == "LCP":
    # lcpdedrm raises immediately (DMCA). Catch and return False.
    decrypted_file = lcpdedrm.decryptLCPbook(tmp_fixed, dedrmprefs['lcp_passphrases'], None)

elif ftype == "ADEPT-PassHash":
    # Try stored bandnkeys
    # Then auto-discover: ignoblekeyNookStudy.nookkeys() (Win/Mac)
    #                     ignoblekeyWindowsStore.dump_keys() (Win only)
    #                     adobekey_get_passhash.passhash_keys() (Win only)
    # BUG FIX: don't return inside the loop — try all keys before giving up
    # Save successful auto-discovered keys to prefs

elif ftype == "ADEPT":
    # Try ineptepub.adeptGetUserUUID() to get book UUID
    # Try UUID-matched key from adeptkeys first
    # Try all stored adeptkeys
    # Auto-discover via adobekey.adeptkeys() (Win/Mac), save successes to prefs

else:  # "ZIP" = DRM-free ePub
    decrypted_file = tmp_fixed   # pass through
```

#### Font post-processing (ePub only, after decryption succeeds)

```python
# Controlled by dedrmprefs['deobfuscate_fonts'] (default True)
if dedrmprefs['deobfuscate_fonts']:
    try:
        tmp_fonts = _make_temp_file(".epub")
        ret = epubfontdecrypt.decryptFontsBook(decrypted_file, tmp_fonts)
        if ret == 0:
            # Fonts were deobfuscated — use the new file
            if decrypted_file != input_file:
                os.remove(decrypted_file)
            decrypted_file = tmp_fonts
        else:
            # ret == 1: no fonts needed deobfuscation (no-op)
            # other: error during deobfuscation
            os.remove(tmp_fonts)
    except:
        pass  # font deobfuscation is best-effort
```

#### Final copy

```python
if decrypted_file and decrypted_file != output_file:
    os.makedirs(os.path.dirname(os.path.abspath(output_file)) or '.', exist_ok=True)
    shutil.copy2(decrypted_file, output_file)
    if decrypted_file != input_file:   # never delete the user's input
        os.remove(decrypted_file)
return True
```

---

## File Type Detection: `determine_file_type()` additions

The existing `determine_file_type()` handles most cases. One gap: **plain KFX files**
(not in a ZIP container). These start with `\xeaDRMION\xee` as their first 8 bytes.
Add before the ZIP check:

```python
elif fdata[:8] == b'\xeaDRMION\xee':
    return "KFX"
```

The Kindle branch handles both `"KFX"` and `"KFX-ZIP"` identically via `k4mobidedrm`.

---

## Key Decisions / Edge Cases

| Situation | Handling |
|---|---|
| `decrypted_file == input_file` (DRM-free PDF) | Copy to output but don't delete input |
| LCP books | `lcpdedrm.decryptLCPbook()` raises immediately (DMCA). Catch, print error, return False. |
| `ADEPTNewVersionError` | Return False immediately; this DRM version is unsupported |
| Linux key extraction | Skipped — Win/Mac only for auto-discovery. Stored keys in prefs still work on Linux. |
| Font deobfuscation | Best-effort only (catches all exceptions). Controlled by `deobfuscate_fonts` pref. `ret==0`: success; `ret==1`: no fonts to deobfuscate (no-op); other: error. |
| Watermark removal | Not implemented in standalone — `epubwatermark.py` requires the Calibre plugin object (`self`). |
| DeACSM keys | Not implemented — Calibre-only bridge. Workaround: export key manually and add to `dedrm.json`. |
| Config path | Passed explicitly as `config_path` parameter through `perform_action` → `dedrm_single_file`. |
| PassHash loop bug | **Fixed**: don't return inside the auto-discovered-key loop; try all keys before failing. |
| Plain KFX (non-ZIP) | Detected via `\xeaDRMION\xee` magic bytes → `"KFX"` type → same Kindle branch as `"KFX-ZIP"`. |

---

## Files Changed

| File | Change |
|---|---|
| `standalone/remove_drm.py` | Full implementation of `dedrm_single_file()` and helpers |

`perform_action()` in `remove_drm.py` already has access to `standalone.config_file_path`
and passes it down to `dedrm_single_file()`.

## Files NOT Changed

- `standalone/__init__.py` — CLI routing is already complete
- `standalone/passhash.py` — separate feature, separate task
- All format modules (`ineptepub.py`, `ineptpdf.py`, etc.) — already work standalone
- `prefs.py` — already works standalone via `standalone/jsonconfig.py`
- `__init__.py` (Calibre plugin) — untouched

---

## Testing Approach

After implementing, test each format type:

```bash
# Adobe ePub (primary test)
python3 DeDRM_plugin.zip remove_drm "path/to/book.epub" -o book_nodrm.epub

# Kindle
python3 DeDRM_plugin.zip remove_drm book.azw3 -o book_nodrm.azw3

# Adobe PDF
python3 DeDRM_plugin.zip remove_drm book.pdf -o book_nodrm.pdf

# eReader
python3 DeDRM_plugin.zip remove_drm book.pdb -o book_nodrm.pmlz

# DRM-free passthrough
python3 DeDRM_plugin.zip remove_drm drm_free.epub -o out.epub
```

Keys are auto-discovered from installed ADE (Win/Mac) or read from the JSON config
(default: `dedrm.json` in cwd). Use `--config` to specify an alternate config path.
