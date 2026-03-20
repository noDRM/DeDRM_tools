#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# CLI interface for the DeDRM plugin (useable without Calibre, too)
# DRM removal

from __future__ import absolute_import, print_function

# Copyright © 2021 NoDRM

#@@CALIBRE_COMPAT_CODE@@

import os, sys
import codecs, time, shutil, traceback, tempfile

from zipfile import ZipInfo, ZipFile, ZIP_STORED, ZIP_DEFLATED
from contextlib import closing

from standalone.__init__ import print_opt, print_std_usage

iswindows = sys.platform.startswith('win')
isosx = sys.platform.startswith('darwin')

try:
    from __version import PLUGIN_NAME, PLUGIN_VERSION
except ImportError:
    from __init__ import PLUGIN_NAME, PLUGIN_VERSION  # type: ignore

def print_removedrm_help():
    print(PLUGIN_NAME + " v" + PLUGIN_VERSION + " - Calibre DRM removal plugin by noDRM")
    print()
    print("remove_drm: Remove DRM from one or multiple files")
    print()
    print_std_usage("remove_drm", "<filename> ... [ -o <filename> ] [ -f ]")

    print()
    print("Options: ")
    print_opt(None, "outputdir", "Folder to export the file(s) to")
    print_opt("o", "output", "File name to export the file to")
    print_opt("f", "force", "Overwrite output file if it already exists")
    print_opt(None, "overwrite", "Replace DRMed file with DRM-free file (implies --force)")


def determine_file_type(file):
    # Returns a file type:
    # "PDF", "PDB", "MOBI", "TPZ", "KFX", "LCP", "ADEPT", "ADEPT-PassHash", "KFX-ZIP", "ZIP" or None

    f = open(file, "rb")
    fdata = f.read(100)
    f.close()

    if fdata.startswith(b"PK\x03\x04"):
        pass
        # Either LCP, Adobe, or Amazon — fall through to ZIP analysis below
    elif fdata.startswith(b"%PDF"):
        return "PDF"
    elif fdata[0x3c:0x3c+8] == b"PNRdPPrs" or fdata[0x3c:0x3c+8] == b"PDctPPrs":
        return "PDB"
    elif fdata[0x3c:0x3c+8] == b"BOOKMOBI" or fdata[0x3c:0x3c+8] == b"TEXtREAd":
        return "MOBI"
    elif fdata.startswith(b"TPZ"):
        return "TPZ"
    elif fdata[:8] == b'\xeaDRMION\xee':
        # Plain KFX file (not in a ZIP container)
        return "KFX"
    else:
        return None
        # Unknown file type


    # If it's a ZIP, determine the type.

    from lcpdedrm import isLCPbook
    if isLCPbook(file):
        return "LCP"

    from ineptepub import adeptBook, isPassHashBook
    if adeptBook(file):
        if isPassHashBook(file):
            return "ADEPT-PassHash"
        else:
            return "ADEPT"

    try:
        # Amazon / KFX-ZIP has a file that starts with b'\xeaDRMION\xee' in the ZIP.
        with closing(ZipFile(open(file, "rb"))) as book:
            for subfilename in book.namelist():
                with book.open(subfilename) as subfile:
                    data = subfile.read(8)
                    if data == b'\xeaDRMION\xee':
                        return "KFX-ZIP"
    except:
        pass

    return "ZIP"


def _make_temp_file(suffix):
    """Create a named temp file that persists on disk. Returns the path string."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    return path


def _pdf_inept_decrypt(input_file, dedrmprefs, starttime):
    """
    Try to decrypt an Adobe Adept / B&N EBX-encrypted PDF.
    Returns the path to the decrypted temp file on success, None on failure.
    """
    import ineptpdf


    book_uuid = None
    try:
        book_uuid = ineptpdf.adeptGetUserUUID(input_file)
    except:
        pass

    if book_uuid is not None:
        print("{0} v{1}: PDF is licensed for UUID {2}".format(PLUGIN_NAME, PLUGIN_VERSION, book_uuid))
        # Try UUID-matched key first
        for keyname, userkeyhex in dedrmprefs['adeptkeys'].items():
            if book_uuid.lower() not in keyname.lower():
                continue
            print("{0} v{1}: Trying UUID-matched key {2}".format(PLUGIN_NAME, PLUGIN_VERSION, keyname))
            tmp = _make_temp_file(".pdf")
            try:
                userkey = codecs.decode(userkeyhex, 'hex')
                result = ineptpdf.decryptBook(userkey, input_file, tmp)
                if result == 0:
                    print("{0} v{1}: Decrypted with key {2} after {3:.1f}s".format(PLUGIN_NAME, PLUGIN_VERSION, keyname, time.time()-starttime))
                    return tmp
            except ineptpdf.ADEPTNewVersionError:
                print("{0} v{1}: Unsupported (too new) Adobe DRM version.".format(PLUGIN_NAME, PLUGIN_VERSION))
                os.remove(tmp)
                return None
            except:
                traceback.print_exc()
            os.remove(tmp)

    # Try all stored adept keys
    for keyname, userkeyhex in dedrmprefs['adeptkeys'].items():
        print("{0} v{1}: Trying key {2}".format(PLUGIN_NAME, PLUGIN_VERSION, keyname))
        tmp = _make_temp_file(".pdf")
        try:
            userkey = codecs.decode(userkeyhex, 'hex')
            result = ineptpdf.decryptBook(userkey, input_file, tmp)
            if result == 0:
                print("{0} v{1}: Decrypted with key {2} after {3:.1f}s".format(PLUGIN_NAME, PLUGIN_VERSION, keyname, time.time()-starttime))
                return tmp
        except ineptpdf.ADEPTNewVersionError:
            print("{0} v{1}: Unsupported (too new) Adobe DRM version.".format(PLUGIN_NAME, PLUGIN_VERSION))
            os.remove(tmp)
            return None
        except:
            traceback.print_exc()
            result = 1
        os.remove(tmp)
        print("{0} v{1}: Failed with key {2} after {3:.1f}s".format(PLUGIN_NAME, PLUGIN_VERSION, keyname, time.time()-starttime))

    # Auto-discover new ADE keys (Win/Mac only)
    if iswindows or isosx:
        print("{0} v{1}: Looking for new ADE keys ...".format(PLUGIN_NAME, PLUGIN_VERSION))
        try:
            from adobekey import adeptkeys
            defaultkeys, defaultnames = adeptkeys()
            newkeys = []
            newnames = []
            for i, keyvalue in enumerate(defaultkeys):
                if codecs.encode(keyvalue, 'hex').decode('ascii') not in dedrmprefs['adeptkeys'].values():
                    newkeys.append(keyvalue)
                    newnames.append("default_ade_key_uuid_" + defaultnames[i])

            for i, userkey in enumerate(newkeys):
                print("{0} v{1}: Trying new discovered ADE key".format(PLUGIN_NAME, PLUGIN_VERSION))
                tmp = _make_temp_file(".pdf")
                try:
                    result = ineptpdf.decryptBook(userkey, input_file, tmp)
                    if result == 0:
                        print("{0} v{1}: Decrypted with new key after {2:.1f}s".format(PLUGIN_NAME, PLUGIN_VERSION, time.time()-starttime))
                        try:
                            dedrmprefs.addnamedvaluetoprefs('adeptkeys', newnames[i], codecs.encode(userkey, 'hex').decode('ascii'))
                            dedrmprefs.writeprefs()
                        except:
                            traceback.print_exc()
                        return tmp
                except:
                    traceback.print_exc()
                os.remove(tmp)
        except:
            traceback.print_exc()

    # Try B&N keys
    for keyname, userkey in dedrmprefs['bandnkeys'].items():
        print("{0} v{1}: Trying B&N key {2}".format(PLUGIN_NAME, PLUGIN_VERSION, keyname))
        tmp = _make_temp_file(".pdf")
        try:
            result = ineptpdf.decryptBook(userkey, input_file, tmp, False)
            if result == 0:
                print("{0} v{1}: Decrypted with B&N key {2} after {3:.1f}s".format(PLUGIN_NAME, PLUGIN_VERSION, keyname, time.time()-starttime))
                return tmp
        except ineptpdf.ADEPTNewVersionError:
            print("{0} v{1}: Unsupported (too new) Adobe DRM version.".format(PLUGIN_NAME, PLUGIN_VERSION))
            os.remove(tmp)
            return None
        except:
            traceback.print_exc()
        os.remove(tmp)

    print("{0} v{1}: Failed to decrypt PDF with any available key.".format(PLUGIN_NAME, PLUGIN_VERSION))
    return None


def _pdf_standard_decrypt(input_file, dedrmprefs, starttime):
    """
    Try to decrypt a Standard/password-encrypted PDF.
    Returns the path to the decrypted temp file on success, None on failure.
    """
    import ineptpdf


    for i, pw in enumerate([""] + list(dedrmprefs['adobe_pdf_passphrases'])):
        label = "empty password" if i == 0 else "password {}".format(i)
        print("{0} v{1}: Trying {2} ...".format(PLUGIN_NAME, PLUGIN_VERSION, label), end="")
        tmp = _make_temp_file(".pdf")
        try:
            result = ineptpdf.decryptBook(bytearray(pw, "utf-8"), input_file, tmp)
            print(" done")
            if result == 0:
                print("{0} v{1}: Decrypted with {2} after {3:.1f}s".format(PLUGIN_NAME, PLUGIN_VERSION, label, time.time()-starttime))
                return tmp
        except ineptpdf.ADEPTInvalidPasswordError:
            print(" invalid password")
        except:
            print(" exception")
            traceback.print_exc()
        os.remove(tmp)

    print("{0} v{1}: Failed to decrypt PDF — add the correct password to the config.".format(PLUGIN_NAME, PLUGIN_VERSION))
    return None


def dedrm_single_file(input_file, output_file, config_path):
    """
    Remove DRM from input_file and write the result to output_file.
    Returns True on success, False on failure (no output file written on failure).
    """


    starttime = time.time()
    print("{0} v{1}: Trying to decrypt {2}".format(PLUGIN_NAME, PLUGIN_VERSION, os.path.basename(input_file)))

    try:
        ftype = determine_file_type(input_file)
    except Exception as e:
        print("{0} v{1}: Can't determine file type: {2}".format(PLUGIN_NAME, PLUGIN_VERSION, e))
        return False

    if ftype is None:
        print("{0} v{1}: Unknown or unsupported file format.".format(PLUGIN_NAME, PLUGIN_VERSION))
        return False

    print("{0} v{1}: Detected file type: {2}".format(PLUGIN_NAME, PLUGIN_VERSION, ftype))

    import prefs
    dedrmprefs = prefs.DeDRM_Prefs(os.path.abspath(config_path))

    decrypted_file = None
    is_epub = False
    temp_files = []   # track all temp files for cleanup

    try:
        # ------------------------------------------------------------------ #
        # Kindle / Mobipocket / Topaz / KFX                                  #
        # ------------------------------------------------------------------ #
        if ftype in ("MOBI", "TPZ", "KFX", "KFX-ZIP"):
            import k4mobidedrm

            pids = list(dedrmprefs['pids'])
            serials = list(dedrmprefs['serials'])
            for android_serials in dedrmprefs['androidkeys'].values():
                serials.extend(android_serials)
            kindleDatabases = list(dedrmprefs['kindlekeys'].items())

            book = None
            try:
                book = k4mobidedrm.GetDecryptedBook(input_file, kindleDatabases, [], serials, pids, starttime)
            except Exception as e:
                print("{0} v{1}: Failed to decrypt with stored keys: {2}".format(PLUGIN_NAME, PLUGIN_VERSION, e))
                traceback.print_exc()

                # Auto-discover new Kindle keys (Win/Mac only)
                if iswindows or isosx:
                    print("{0} v{1}: Looking for new Kindle keys ...".format(PLUGIN_NAME, PLUGIN_VERSION))
                    try:
                        from kindlekey import kindlekeys
                        defaultkeys = kindlekeys()
                        newkeys = {}
                        for i, keyvalue in enumerate(defaultkeys):
                            if keyvalue not in dedrmprefs['kindlekeys'].values():
                                newkeys["key_{0:d}".format(i)] = keyvalue

                        if newkeys:
                            print("{0} v{1}: Found {2} new Kindle key(s), trying ...".format(PLUGIN_NAME, PLUGIN_VERSION, len(newkeys)))
                            book = k4mobidedrm.GetDecryptedBook(input_file, list(newkeys.items()), [], [], [], starttime)
                            # Save successful keys
                            for keyvalue in newkeys.values():
                                dedrmprefs.addnamedvaluetoprefs('kindlekeys', "kindle_key_{0:d}".format(int(time.time())), keyvalue)
                            dedrmprefs.writeprefs()
                    except Exception as e2:
                        print("{0} v{1}: Auto-discovery also failed: {2}".format(PLUGIN_NAME, PLUGIN_VERSION, e2))
                        traceback.print_exc()

            if book is None:
                print("{0} v{1}: Ultimately failed to decrypt Kindle book.".format(PLUGIN_NAME, PLUGIN_VERSION))
                return False

            ext = book.getBookExtension()
            decrypted_file = _make_temp_file(ext)
            temp_files.append(decrypted_file)
            book.getFile(decrypted_file)
            book.cleanup()

        # ------------------------------------------------------------------ #
        # eReader PDB                                                         #
        # ------------------------------------------------------------------ #
        elif ftype == "PDB":
            import erdr2pml

            for keyname, userkey in dedrmprefs['ereaderkeys'].items():
                print("{0} v{1}: Trying eReader key {2}".format(PLUGIN_NAME, PLUGIN_VERSION, keyname))
                tmp = _make_temp_file(".pmlz")
                temp_files.append(tmp)
                result = erdr2pml.decryptBook(input_file, tmp, True, codecs.decode(userkey, 'hex'))
                if result == 0:
                    print("{0} v{1}: Decrypted with key {2} after {3:.1f}s".format(PLUGIN_NAME, PLUGIN_VERSION, keyname, time.time()-starttime))
                    decrypted_file = tmp
                    break
                temp_files.remove(tmp)
                os.remove(tmp)

            if decrypted_file is None:
                print("{0} v{1}: Failed to decrypt eReader book — no matching key found.".format(PLUGIN_NAME, PLUGIN_VERSION))
                return False

        # ------------------------------------------------------------------ #
        # PDF                                                                 #
        # ------------------------------------------------------------------ #
        elif ftype == "PDF":
            import ineptpdf
            import lcpdedrm

            if lcpdedrm.isLCPbook(input_file):
                try:
                    decrypted_file = lcpdedrm.decryptLCPbook(input_file, dedrmprefs['lcp_passphrases'], None)
                    temp_files.append(decrypted_file)
                except Exception as e:
                    print("{0} v{1}: LCP decryption failed: {2}".format(PLUGIN_NAME, PLUGIN_VERSION, e))
                    return False
            else:
                enc = ineptpdf.getPDFencryptionType(input_file)
                if enc is None:
                    print("{0} v{1}: PDF is DRM-free, copying as-is.".format(PLUGIN_NAME, PLUGIN_VERSION))
                    decrypted_file = input_file   # signal: just copy, don't delete
                elif enc == "EBX_HANDLER":
                    print("{0} v{1}: PDF uses Adobe Adept (EBX) encryption.".format(PLUGIN_NAME, PLUGIN_VERSION))
                    decrypted_file = _pdf_inept_decrypt(input_file, dedrmprefs, starttime)
                    if decrypted_file:
                        temp_files.append(decrypted_file)
                elif enc in ("Standard", "Adobe.APS"):
                    print("{0} v{1}: PDF uses Standard/password encryption ({2}).".format(PLUGIN_NAME, PLUGIN_VERSION, enc))
                    decrypted_file = _pdf_standard_decrypt(input_file, dedrmprefs, starttime)
                    if decrypted_file:
                        temp_files.append(decrypted_file)
                elif enc in ("FOPN_fLock", "FOPN_foweb"):
                    print("{0} v{1}: FileOpen encryption '{2}' is unsupported.".format(PLUGIN_NAME, PLUGIN_VERSION, enc))
                    return False
                else:
                    print("{0} v{1}: Unsupported PDF encryption type: {2}".format(PLUGIN_NAME, PLUGIN_VERSION, enc))
                    return False

            if decrypted_file is None:
                return False

        # ------------------------------------------------------------------ #
        # ePub: LCP, Adobe Adept, B&N PassHash, or DRM-free                  #
        # ------------------------------------------------------------------ #
        elif ftype in ("LCP", "ADEPT", "ADEPT-PassHash", "ZIP"):
            import zipfix
            import ineptepub
            import lcpdedrm
            import epubfontdecrypt
            is_epub = True

            # Step 1: repair ZIP
            tmp_fixed = _make_temp_file(".epub")
            temp_files.append(tmp_fixed)
            try:
                print("{0} v{1}: Verifying zip archive integrity".format(PLUGIN_NAME, PLUGIN_VERSION))
                zipfix.fixZip(input_file, tmp_fixed).fix()
            except Exception as e:
                print("{0} v{1}: Error checking zip archive: {2}".format(PLUGIN_NAME, PLUGIN_VERSION, e))
                raise

            if ftype == "LCP":
                try:
                    decrypted_file = lcpdedrm.decryptLCPbook(tmp_fixed, dedrmprefs['lcp_passphrases'], None)
                    temp_files.append(decrypted_file)
                except Exception as e:
                    print("{0} v{1}: LCP decryption failed: {2}".format(PLUGIN_NAME, PLUGIN_VERSION, e))
                    return False

            elif ftype == "ADEPT-PassHash":
                print("{0} v{1}: Book is B&N PassHash-encrypted.".format(PLUGIN_NAME, PLUGIN_VERSION))

                def _try_passhash_key(userkey, keyname):
                    """Returns temp path on success, None on failure."""
                    tmp = _make_temp_file(".epub")
                    try:
                        result = ineptepub.decryptBook(userkey, tmp_fixed, tmp)
                        if result == 0:
                            print("{0} v{1}: Decrypted with key {2} after {3:.1f}s".format(
                                PLUGIN_NAME, PLUGIN_VERSION, keyname, time.time()-starttime))
                            return tmp
                    except:
                        traceback.print_exc()
                    os.remove(tmp)
                    return None

                # Try stored keys
                for keyname, userkey in dedrmprefs['bandnkeys'].items():
                    print("{0} v{1}: Trying B&N key {2}".format(PLUGIN_NAME, PLUGIN_VERSION, keyname))
                    result = _try_passhash_key(userkey, keyname)
                    if result:
                        decrypted_file = result
                        temp_files.append(decrypted_file)
                        break

                # Auto-discover new keys if stored keys didn't work
                if decrypted_file is None and (iswindows or isosx):
                    print("{0} v{1}: Looking for new B&N/PassHash keys ...".format(PLUGIN_NAME, PLUGIN_VERSION))
                    newkeys = []

                    try:
                        from ignoblekeyNookStudy import nookkeys
                        for kv in nookkeys():
                            if kv not in dedrmprefs['bandnkeys'].values() and kv not in newkeys:
                                newkeys.append(("nook_key_{0}".format(int(time.time())), kv))
                    except:
                        traceback.print_exc()

                    if iswindows:
                        try:
                            from ignoblekeyWindowsStore import dump_keys as dump_nook_keys
                            for kv in dump_nook_keys(False):
                                if kv not in dedrmprefs['bandnkeys'].values() and kv not in [k for _, k in newkeys]:
                                    newkeys.append(("nook_store_key_{0}".format(int(time.time())), kv))
                        except:
                            traceback.print_exc()

                        try:
                            from adobekey_get_passhash import passhash_keys, ADEPTError
                            try:
                                ph_keys, ph_names = passhash_keys()
                                for i, kv in enumerate(ph_keys):
                                    if kv not in dedrmprefs['bandnkeys'].values() and kv not in [k for _, k in newkeys]:
                                        newkeys.append(("ade_passhash_{0}".format(int(time.time())), kv))
                            except ADEPTError:
                                pass
                        except:
                            traceback.print_exc()

                    # BUG FIX: try ALL new keys before giving up (don't return inside loop)
                    for keyname, userkey in newkeys:
                        if not userkey:
                            continue
                        print("{0} v{1}: Trying new discovered key".format(PLUGIN_NAME, PLUGIN_VERSION))
                        result = _try_passhash_key(userkey, keyname)
                        if result:
                            decrypted_file = result
                            temp_files.append(decrypted_file)
                            try:
                                dedrmprefs.addnamedvaluetoprefs('bandnkeys', keyname, userkey)
                                dedrmprefs.writeprefs()
                            except:
                                traceback.print_exc()
                            break

                if decrypted_file is None:
                    print("{0} v{1}: Failed to decrypt B&N ePub — no matching key found.".format(PLUGIN_NAME, PLUGIN_VERSION))
                    return False

            elif ftype == "ADEPT":
                print("{0} v{1}: Book is Adobe Adept-encrypted.".format(PLUGIN_NAME, PLUGIN_VERSION))

                book_uuid = None
                try:
                    book_uuid = ineptepub.adeptGetUserUUID(tmp_fixed)
                except:
                    pass

                if book_uuid:
                    print("{0} v{1}: Book is licensed for UUID {2}".format(PLUGIN_NAME, PLUGIN_VERSION, book_uuid))

                def _try_adept_key(userkeyhex, keyname):
                    """Returns temp path on success, None on failure. Raises ADEPTNewVersionError."""
                    tmp = _make_temp_file(".epub")
                    try:
                        userkey = codecs.decode(userkeyhex, 'hex')
                        result = ineptepub.decryptBook(userkey, tmp_fixed, tmp)
                        if result == 0:
                            print("{0} v{1}: Decrypted with key {2} after {3:.1f}s".format(
                                PLUGIN_NAME, PLUGIN_VERSION, keyname, time.time()-starttime))
                            return tmp
                    except ineptepub.ADEPTNewVersionError:
                        os.remove(tmp)
                        raise
                    except:
                        traceback.print_exc()
                    os.remove(tmp)
                    return None

                try:
                    # Try UUID-matched key first
                    if book_uuid:
                        for keyname, userkeyhex in dedrmprefs['adeptkeys'].items():
                            if book_uuid.lower() not in keyname.lower():
                                continue
                            print("{0} v{1}: Trying UUID-matched key {2}".format(PLUGIN_NAME, PLUGIN_VERSION, keyname))
                            result = _try_adept_key(userkeyhex, keyname)
                            if result:
                                decrypted_file = result
                                temp_files.append(decrypted_file)
                                break

                    # Try all stored keys
                    if decrypted_file is None:
                        for keyname, userkeyhex in dedrmprefs['adeptkeys'].items():
                            print("{0} v{1}: Trying key {2}".format(PLUGIN_NAME, PLUGIN_VERSION, keyname))
                            result = _try_adept_key(userkeyhex, keyname)
                            if result:
                                decrypted_file = result
                                temp_files.append(decrypted_file)
                                break

                    # Auto-discover new ADE keys (Win/Mac only)
                    if decrypted_file is None and (iswindows or isosx):
                        print("{0} v{1}: Looking for new ADE keys ...".format(PLUGIN_NAME, PLUGIN_VERSION))
                        from adobekey import adeptkeys
                        defaultkeys, defaultnames = adeptkeys()
                        newkeys = []
                        newnames = []
                        for i, keyvalue in enumerate(defaultkeys):
                            if codecs.encode(keyvalue, 'hex').decode('ascii') not in dedrmprefs['adeptkeys'].values():
                                newkeys.append(keyvalue)
                                newnames.append("default_ade_key_uuid_" + defaultnames[i])

                        for i, userkey in enumerate(newkeys):
                            print("{0} v{1}: Trying new discovered ADE key".format(PLUGIN_NAME, PLUGIN_VERSION))
                            userkeyhex = codecs.encode(userkey, 'hex').decode('ascii')
                            tmp = _make_temp_file(".epub")
                            try:
                                result = ineptepub.decryptBook(userkey, tmp_fixed, tmp)
                                if result == 0:
                                    print("{0} v{1}: Decrypted with new key after {2:.1f}s".format(PLUGIN_NAME, PLUGIN_VERSION, time.time()-starttime))
                                    decrypted_file = tmp
                                    temp_files.append(decrypted_file)
                                    try:
                                        dedrmprefs.addnamedvaluetoprefs('adeptkeys', newnames[i], userkeyhex)
                                        dedrmprefs.writeprefs()
                                    except:
                                        traceback.print_exc()
                                    break
                            except ineptepub.ADEPTNewVersionError:
                                os.remove(tmp)
                                raise
                            except:
                                traceback.print_exc()
                            if decrypted_file is None:
                                os.remove(tmp)

                except ineptepub.ADEPTNewVersionError:
                    print("{0} v{1}: Unsupported (too new) Adobe DRM version.".format(PLUGIN_NAME, PLUGIN_VERSION))
                    return False

                if decrypted_file is None:
                    print("{0} v{1}: Ultimately failed to decrypt Adobe ePub.".format(PLUGIN_NAME, PLUGIN_VERSION))
                    print("{0} v{1}: Read the FAQs at noDRM's repository: https://github.com/noDRM/DeDRM_tools/blob/master/FAQs.md".format(PLUGIN_NAME, PLUGIN_VERSION))
                    return False

            else:  # "ZIP" = DRM-free ePub
                print("{0} v{1}: ePub appears to be DRM-free.".format(PLUGIN_NAME, PLUGIN_VERSION))
                decrypted_file = tmp_fixed

            # Font deobfuscation post-processing
            if dedrmprefs['deobfuscate_fonts']:
                import epubfontdecrypt
                try:
                    tmp_fonts = _make_temp_file(".epub")
                    ret = epubfontdecrypt.decryptFontsBook(decrypted_file, tmp_fonts)
                    if ret == 0:
                        # Fonts were deobfuscated — use the new file
                        if decrypted_file != input_file and decrypted_file in temp_files:
                            temp_files.remove(decrypted_file)
                            os.remove(decrypted_file)
                        decrypted_file = tmp_fonts
                        temp_files.append(decrypted_file)
                    else:
                        # ret == 1: no fonts to deobfuscate (no-op); other: error
                        os.remove(tmp_fonts)
                except:
                    pass  # font deobfuscation is best-effort

        else:
            print("{0} v{1}: Unsupported file type: {2}".format(PLUGIN_NAME, PLUGIN_VERSION, ftype))
            return False

        # ------------------------------------------------------------------ #
        # Copy result to output_file                                          #
        # ------------------------------------------------------------------ #
        if decrypted_file is None:
            print("{0} v{1}: Decryption failed — no output written.".format(PLUGIN_NAME, PLUGIN_VERSION))
            return False

        output_dir = os.path.dirname(os.path.abspath(output_file))
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        shutil.copy2(decrypted_file, output_file)
        print("{0} v{1}: Saved DRM-free file to {2}".format(PLUGIN_NAME, PLUGIN_VERSION, output_file))
        print("{0} v{1}: Finished after {2:.1f} seconds".format(PLUGIN_NAME, PLUGIN_VERSION, time.time()-starttime))
        return True

    finally:
        # Clean up all temp files, but never delete input_file
        for tmp in temp_files:
            try:
                if tmp != input_file and os.path.exists(tmp):
                    os.remove(tmp)
            except:
                pass


def perform_action(params, files):
    output = None
    outputdir = None
    force = False
    overwrite_original = False

    import standalone
    config_path = standalone.config_file_path

    if len(files) == 0:
        print_removedrm_help()
        return 0

    while len(params) > 0:
        p = params.pop(0)
        if p == "--output":
            output = params.pop(0)
        elif p == "--outputdir":
            outputdir = params.pop(0)
        elif p == "--force":
            force = True
        elif p == "--overwrite":
            overwrite_original = True
            force = True
        elif p == "--help":
            print_removedrm_help()
            return 0

    if overwrite_original and (output is not None or outputdir is not None):
        print("Can't use --overwrite together with --output or --outputdir.", file=sys.stderr)
        return 1

    if output is not None and os.path.isfile(output) and not force:
        print("Output file already exists. Use --force to overwrite.", file=sys.stderr)
        return 1

    if output is not None and len(files) > 1:
        print("Cannot set output file name if there's multiple input files.", file=sys.stderr)
        return 1

    if outputdir is not None and output is not None and os.path.isabs(output):
        print("--output parameter is absolute path despite --outputdir being set.", file=sys.stderr)
        print("Remove --outputdir, or give a relative path to --output.", file=sys.stderr)
        return 1

    any_failed = False

    for file in files:

        file = os.path.abspath(file)

        if not os.path.isfile(file):
            print("Skipping file " + file + " - not found.", file=sys.stderr)
            any_failed = True
            continue

        if overwrite_original:
            output_filename = file
        else:
            if output is not None:
                # Due to the check above, we DO only have one file here.
                if outputdir is not None and not os.path.isabs(output):
                    output_filename = os.path.join(outputdir, output)
                else:
                    output_filename = os.path.abspath(output)
            else:
                if outputdir is None:
                    outputdir = os.getcwd()
                output_filename = os.path.join(outputdir, os.path.basename(file))
                output_filename = os.path.abspath(output_filename)

                if output_filename == file:
                    # If we export to the import folder, add a suffix to the file name.
                    fn, f_ext = os.path.splitext(output_filename)
                    output_filename = fn + "_nodrm" + f_ext

        if os.path.isfile(output_filename) and not force:
            print("Skipping file " + file + " because output file already exists (use --force).", file=sys.stderr)
            any_failed = True
            continue

        success = dedrm_single_file(file, output_filename, config_path)
        if not success:
            any_failed = True

    return 1 if any_failed else 0


if __name__ == "__main__":
    print("This code is not intended to be executed directly!", file=sys.stderr)
