#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# lcpdedrm.py
# Copyright © 2021 NoDRM

# Released under the terms of the GNU General Public Licence, version 3
# <http://www.gnu.org/licenses/>


# Revision history:
#   1 - Initial release

"""
Decrypt Readium LCP encrypted ePub and PDF books.
"""

__license__ = 'GPL v3'
__version__ = "1"

import json
import hashlib
import base64
import zlib
import binascii
from zipfile import ZipInfo, ZipFile, ZIP_STORED, ZIP_DEFLATED
from contextlib import closing
from Crypto.Cipher import AES
from lxml import etree

# Wrap a stream so that output gets flushed immediately
# and also make sure that any unicode strings get
# encoded using "replace" before writing them.
class SafeUnbuffered:
    def __init__(self, stream):
        self.stream = stream
        self.encoding = stream.encoding
        if self.encoding == None:
            self.encoding = "utf-8"
    def write(self, data):
        if isinstance(data,str) or isinstance(data,unicode):
            # str for Python3, unicode for Python2
            data = data.encode(self.encoding,"replace")
        try:
            buffer = getattr(self.stream, 'buffer', self.stream)
            # self.stream.buffer for Python3, self.stream for Python2
            buffer.write(data)
            buffer.flush()
        except:
            # We can do nothing if a write fails
            raise
    def __getattr__(self, attr):
        return getattr(self.stream, attr)



class Decryptor(object):
    def __init__(self, bookkey, encryption):
        enc = lambda tag: '{%s}%s' % ('http://www.w3.org/2001/04/xmlenc#', tag)
        dsig = lambda tag: '{%s}%s' % ('http://www.w3.org/2000/09/xmldsig#', tag)
        self.book_key = bookkey
        
        self._encryption = etree.fromstring(encryption)
        # This loops through all entries in the "encryption.xml" file
        # to figure out which files need to be decrypted.
        # All encrypted file paths will be added to the "encrypted" list
        self._encrypted = encrypted = set()
        self._other = other = set()

        self._json_elements_to_remove = json_elements_to_remove = set()
        self._has_remaining_xml = False
        expr = './%s/%s/%s' % (enc('EncryptedData'), enc('CipherData'),
                               enc('CipherReference'))
        for elem in self._encryption.findall(expr):
            path = elem.get('URI', None)
            encryption_type_url = (elem.getparent().getparent().find("./%s" % (enc('EncryptionMethod'))).get('Algorithm', None))
            retrieval_method_url = None
            if (encryption_type_url == "http://www.w3.org/2001/04/xmlenc#aes256-cbc"):
                try: 
                    retrieval_method_url = (elem.getparent().getparent().find("./%s/%s" % (dsig('KeyInfo'), dsig('RetrievalMethod'))).get('Type', None))
                except:
                    pass

            if path is not None:
                if retrieval_method_url == "http://readium.org/2014/01/lcp#EncryptedContentKey":
                    path = path.encode('utf-8')
                    encrypted.add(path)
                    if (self.book_key is None):
                        self._has_remaining_xml = True
                    else:
                        json_elements_to_remove.add(elem.getparent().getparent())

                else: 
                    path = path.encode('utf-8')
                    other.add(path)
                    self._has_remaining_xml = True
                    # Other unsupported type.
        
        for elem in json_elements_to_remove:
            elem.getparent().remove(elem)

    def check_if_remaining(self):
        return self._has_remaining_xml

    def get_xml(self):
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" + etree.tostring(self._encryption, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("utf-8")

    def decompress(self, bytes):
        dc = zlib.decompressobj(-15)
        try:
            decompressed_bytes = dc.decompress(bytes)
            ex = dc.decompress(b'Z') + dc.flush()
            if ex:
                decompressed_bytes = decompressed_bytes + ex
        except:
            # possibly not compressed by zip - just return bytes
            return bytes, False
        return decompressed_bytes , True
    
    def decrypt(self, path, data):
        if path.encode('utf-8') in self._encrypted and self.book_key is not None:
            aes = AES.new(self.book_key, AES.MODE_CBC, data[:16])
            data = aes.decrypt(data[16:])
            
            # Fix padding
            if type(data[-1]) != int:
                place = ord(data[-1])
            else:
                place = data[-1]
            data = data[:-place]
            data, was_decomp = self.decompress(data)
            return data

        else: 
            # Not encrypted or obfuscated
            return data

class LCPError(Exception):
    pass

class LCPTransform: 

    @staticmethod
    def secret_transform_basic(input_hash):
        # basic profile doesn't have any transformation
        # Takes key input as hexdigest and outputs it as hexdigest
        return input_hash

    @staticmethod
    def secret_transform_profile10(input_hash): 
        # Takes an input sha256 hash as hexdigest and transforms that according to the profile-1.0 spec. 
        # This 64-byte master key is basically all that distinguishes the open source "open for everyone" version
        # from the so-called "open source" closed-source-version that's actually being used by book distributors.
        # 64 byte master key = 64 iterations

        # This function is what the documentation describes as "uk = userkey(h)", the "secret userkey transform"

        # 1. Take input
        # 2. Hash it
        # 3. Add one byte from the master key to the end of the hash
        # 4. Hash that result again
        # 5. Go back to 3. until you run out of bytes. 
        # 6. The result is the key.

        masterkey = "b3a07c4d42880e69398e05392405050efeea0664c0b638b7c986556fa9b58d77b31a40eb6a4fdba1e4537229d9f779daad1cc41ee968153cb71f27dc9696d40f"
        masterkey = bytearray.fromhex(masterkey)

        current_hash = bytearray.fromhex(input_hash)

        for byte in masterkey:
            current_hash.append(byte)
            current_hash = bytearray(hashlib.sha256(current_hash).digest())
        return binascii.hexlify(current_hash)

    @staticmethod
    def userpass_to_hash(passphrase, algorithm):
        # Check for the password algorithm. The Readium LCP standard only defines SHA256.
        # The hashing standard documents they link to define a couple other hash algorithms, too. 
        # I've never seen them actually used in an LCP-encrypted file, so I didn't bother to implement them. 

        if (algorithm == "http://www.w3.org/2001/04/xmlenc#sha256"):
            algo = "SHA256"
            user_password_hashed = hashlib.sha256(passphrase).hexdigest()
            # This seems to be the only algorithm that's actually defined in the Readium standard.
        else:
            print("LCP: Book is using unsupported user key algorithm: {0}".format(algorithm))
            return None, None

        return algo, user_password_hashed


# Check file to see if this is an LCP-protected file
def isLCPbook(inpath):
    try: 
        with closing(ZipFile(open(inpath, 'rb'))) as lcpbook:
            if ("META-INF/license.lcpl" not in lcpbook.namelist() or
                "META-INF/encryption.xml" not in lcpbook.namelist() or
                b"EncryptedContentKey" not in lcpbook.read("META-INF/encryption.xml")):
                return False

            license = json.loads(lcpbook.read('META-INF/license.lcpl'))

            if "id" in license and "encryption" in license and "profile" in license["encryption"]:
                return True

    except: 
        return False
    
    return False

# This function decrypts data with the given key
def dataDecryptLCP(b64data, hex_key):

    try: 
        iv = base64.decodebytes(b64data.encode('ascii'))[:16]
        cipher = base64.decodebytes(b64data.encode('ascii'))[16:]
    except AttributeError:
        iv = base64.decodestring(b64data.encode('ascii'))[:16]
        cipher = base64.decodestring(b64data.encode('ascii'))[16:]

    aes = AES.new(binascii.unhexlify(hex_key), AES.MODE_CBC, iv)
    temp = aes.decrypt(cipher)
    try: 
        padding = temp[-1]
        data_temp = temp[:-padding]
    except TypeError:
        padding = ord(temp[-1])
        data_temp = temp[:-padding]

    return data_temp


# This function just returns an info string about the license
# Optional.
def returnUserInfoStringForLicense(license, user_pass = None):
    if not "user" in license:
        return None

    user_name = None
    user_email = None

    if "email" in license["user"]:
        user_email = license["user"]["email"]
    if "name" in license["user"]:
        user_name = license["user"]["name"]

    # Sometimes these are encrypted
    if "encrypted" in license["user"] and "email" in license["user"]["encrypted"]:
        if user_pass is None:
            user_email = None
        else:
            # Decrypt
            try: 
                user_email_temp = dataDecryptLCP(user_email, user_pass)
                user_email = str(user_email_temp.decode("utf-8"))
            except:
                pass
            
    
    if "encrypted" in license["user"] and "name" in license["user"]["encrypted"]:
        if user_pass is None:
            user_name = None
        else:
            # Decrypt
            try: 
                user_name_temp = dataDecryptLCP(user_name, user_pass)
                user_name = str(user_name_temp.decode("utf-8"))
            except:
                pass

    if (user_name is None and user_email is None):
        return None

    print_str = ""

    if ("id" in license["user"]):
        print_str += "ID=" + license["user"]["id"] + ", "
    
    if (user_email is not None):
        print_str += "Email=" + user_email + ", "

    if (user_name is not None):
        print_str += "Name=" + user_name + ", "

    # Remove last comma
    print_str = print_str[:-2]
    return print_str


# Takes a file and a list of passphrases
def decryptLCPbook(inpath, passphrases, parent_object):

    if not isLCPbook(inpath):
        raise LCPError("This is not an LCP-encrypted book")

    file = ZipFile(open(inpath, 'rb'))

    license = json.loads(file.read('META-INF/license.lcpl'))
    print("LCP: Found LCP-encrypted book {0}".format(license["id"]))
    
    user_info_string1 = returnUserInfoStringForLicense(license, None)
    if (user_info_string1 is not None):
        print("LCP: Account information: " + user_info_string1)

    # Check algorithm:
    if license["encryption"]["profile"] == "http://readium.org/lcp/basic-profile":
        print("LCP: Book is using lcp/basic-profile encryption.")
        transform_algo = LCPTransform.secret_transform_basic
    elif license["encryption"]["profile"] == "http://readium.org/lcp/profile-1.0":
        print("LCP: Book is using lcp/profile-1.0 encryption")
        transform_algo = LCPTransform.secret_transform_profile10
    else: 
        file.close()
        raise LCPError("Book is using an unknown LCP encryption standard: {0}".format(license["encryption"]["profile"]))

    if (
        "algorithm" in license["encryption"]["content_key"] and 
        license["encryption"]["content_key"]["algorithm"] != "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
        ):
        file.close()
        raise LCPError("Book is using an unknown LCP encryption algorithm: {0}".format(license["encryption"]["content_key"]["algorithm"]))

    key_check = license["encryption"]["user_key"]["key_check"]
    encrypted_content_key = license["encryption"]["content_key"]["encrypted_value"]

    # Prepare a list of encryption keys to test:
    password_hashes = []
    
    # Some providers hard-code the passphrase in the LCPL file. That doesn't happen often,
    # but when it does, these files can be decrypted without knowing any passphrase.

    if "value" in license["encryption"]["user_key"]:
        try: 
            password_hashes.append(binascii.hexlify(base64.decodebytes(license["encryption"]["user_key"]["value"].encode())).decode("ascii"))
        except AttributeError:
            # Python 2
            password_hashes.append(binascii.hexlify(base64.decodestring(license["encryption"]["user_key"]["value"].encode())).decode("ascii"))
    if "hex_value" in license["encryption"]["user_key"]:
        password_hashes.append(binascii.hexlify(bytearray.fromhex(license["encryption"]["user_key"]["hex_value"])).decode("ascii"))

    # Hash all the passwords provided by the user:
    for possible_passphrase in passphrases:
        algo = "http://www.w3.org/2001/04/xmlenc#sha256"
        if "algorithm" in license["encryption"]["user_key"]:
            algo = license["encryption"]["user_key"]["algorithm"]

        algo, tmp_pw = LCPTransform.userpass_to_hash(possible_passphrase.encode('utf-8'), algo)
        if tmp_pw is not None: 
            password_hashes.append(tmp_pw)

    # For all the password hashes, check if one of them decrypts the book:
    correct_password_hash = None

    for possible_hash in password_hashes:
        transformed_hash = transform_algo(possible_hash)
        try: 
            decrypted = None
            decrypted = dataDecryptLCP(key_check, transformed_hash)
        except:
            pass

        if (decrypted is not None and decrypted.decode("ascii", errors="ignore") == license["id"]):
            # Found correct password hash, hooray!
            correct_password_hash = transformed_hash
            break


    # Print an error message if none of the passwords worked
    if (correct_password_hash is None):
        print("LCP: None of the passphrases could decrypt the book ...")
        print("LCP: Enter the correct passphrase in the DeDRM plugin settings, then try again.")
        
        # Print password hint, if available
        if ("text_hint" in license["encryption"]["user_key"] and license["encryption"]["user_key"]["text_hint"] != ""):
            print("LCP: The book distributor has given you the following passphrase hint: \"{0}\"".format(license["encryption"]["user_key"]["text_hint"]))
        
        # Print password reset instructions, if available
        for link in license["links"]:
            if ("rel" in link and link["rel"] == "hint"):
                print("LCP: You can visit the following webpage to reset your LCP passphrase: {0}".format(link["href"]))
                break

        
        file.close()
        raise LCPError("No correct passphrase found")

    print("LCP: Found correct passphrase, decrypting book ...")
    user_info_string2 = returnUserInfoStringForLicense(license, correct_password_hash)
    if (user_info_string2 is not None):
        if (user_info_string1 != user_info_string2):
            print("LCP: Account information: " + user_info_string2)


    # Take the key we found and decrypt the content key:
    decrypted_content_key = dataDecryptLCP(encrypted_content_key, correct_password_hash)

    if decrypted_content_key is None:
        raise LCPError("Decrypted content key is None")

    # Begin decrypting

    encryption = file.read('META-INF/encryption.xml')
    decryptor = Decryptor(decrypted_content_key, encryption)
    kwds = dict(compression=ZIP_DEFLATED, allowZip64=False)

    mimetype = file.read("mimetype").decode("latin-1")

    if mimetype == "application/pdf":
        # Check how many PDF files there are. 
        # Usually, an LCP-protected PDF/ZIP is only supposed to contain one 
        # PDF file, but if there are multiple, return a ZIP that contains them all.

        pdf_files = []
        for filename in file.namelist():
            if filename.endswith(".pdf"):
                pdf_files.append(filename)

        if len(pdf_files) == 0:
            file.close()
            raise LCPError("Error: Book is an LCP-protected PDF, but doesn't contain any PDF files ...")
        
        elif len(pdf_files) == 1:
            # One PDF file found - extract and return that.
            pdfdata = file.read(pdf_files[0])
            outputname = parent_object.temporary_file(".pdf").name
            print("LCP: Successfully decrypted, exporting to {0}".format(outputname))

            with open(outputname, 'wb') as f:
                f.write(decryptor.decrypt(pdf_files[0], pdfdata))
            
            file.close()
            return outputname
                
        else:
            # Multiple PDFs found
            outputname = parent_object.temporary_file(".zip").name
            with closing(ZipFile(open(outputname, 'wb'), 'w', **kwds)) as outfile:
                for path in pdf_files:
                    data = file.read(path)
                    outfile.writestr(path, decryptor.decrypt(path, data))

            print("LCP: Successfully decrypted a multi-PDF ZIP file, exporting to {0}".format(outputname))
            file.close()
            return outputname

    else:
        # Not a PDF -> EPUB

        if mimetype == "application/epub+zip":
            outputname = parent_object.temporary_file(".epub").name
        else:
            outputname = parent_object.temporary_file(".zip").name

        with closing(ZipFile(open(outputname, 'wb'), 'w', **kwds)) as outfile:

            # mimetype must be 1st file. Remove from list and manually add at the beginning
            namelist = file.namelist()
            namelist.remove("mimetype")
            namelist.remove("META-INF/license.lcpl")

            for path in (["mimetype"] + namelist):
                data = file.read(path)
                zi = ZipInfo(path)

                if path == "META-INF/encryption.xml":
                    # Check if that's still needed
                    if (decryptor.check_if_remaining()):
                        data = decryptor.get_xml()
                        print("LCP: Adding encryption.xml for the remaining files.")
                    else:
                        continue
                
                try:
                    oldzi = file.getinfo(path)
                    if path == "mimetype":
                        zi.compress_type = ZIP_STORED
                    else:
                        zi.compress_type = ZIP_DEFLATED
                    zi.date_time = oldzi.date_time
                    zi.comment = oldzi.comment
                    zi.extra = oldzi.extra
                    zi.internal_attr = oldzi.internal_attr
                    zi.external_attr = oldzi.external_attr
                    zi.create_system = oldzi.create_system
                    if any(ord(c) >= 128 for c in path) or any(ord(c) >= 128 for c in zi.comment):
                        # If the file name or the comment contains any non-ASCII char, set the UTF8-flag
                        zi.flag_bits |= 0x800
                except:
                    pass

                if path == "META-INF/encryption.xml":
                    outfile.writestr(zi, data)
                else:
                    outfile.writestr(zi, decryptor.decrypt(path, data))
        
        print("LCP: Successfully decrypted, exporting to {0}".format(outputname))
        file.close()
        return outputname
                    
