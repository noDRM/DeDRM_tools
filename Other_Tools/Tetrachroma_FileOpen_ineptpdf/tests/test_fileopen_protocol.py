import importlib.machinery
import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / 'ineptpdf_fileopen.pyw'
LOADER = importlib.machinery.SourceFileLoader('ineptpdf_fileopen', str(SCRIPT))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
fileopen = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(fileopen)


class FileOpenProtocolTests(unittest.TestCase):
    def test_parse_pairs_preserves_base64_plus_and_first_value(self):
        parsed = fileopen.parse_fileopen_pairs('Nascd=ab+c==&RetVal=1&RetVal=2\r\n')
        self.assertEqual('ab+c==', parsed['Nascd'])
        self.assertEqual('1', parsed['RetVal'])

    def test_normalize_info_converts_bytes_and_aliases(self):
        parsed = fileopen.normalize_fileopen_info(
            b'PURL=https://example.test;DPRM=/permission;VERS=2;PRID=user/name')
        self.assertEqual('https://example.test', parsed['PURL'])
        self.assertEqual('/permission', parsed['DPRM'])
        self.assertEqual('2', parsed['EncrVer'])
        self.assertEqual('user%2Fname', parsed['USR'])
        self.assertNotIn('VERS', parsed)

    def test_nascv1_round_trip(self):
        envelope = fileopen.encode_fileopen_envelope(
            'RetVal=1&Code=0011223344', nasca=4097, nasct=123456)
        self.assertEqual(
            {'RetVal': '1', 'Code': '0011223344'},
            fileopen.decode_fileopen_response(envelope))

    def test_nascv2_url_escaped_round_trip(self):
        envelope = fileopen.encode_fileopen_envelope(
            'RetVal=2&Reason=Allowed', nasca=4353, nasct=654321)
        envelope = envelope.replace('Nascv=1', 'Nascv=2', 1)
        self.assertEqual(
            {'RetVal': '2', 'Reason': 'Allowed'},
            fileopen.decode_fileopen_response(envelope))

    def test_document_key_accepts_hex_and_raw_bytes(self):
        self.assertEqual(
            bytes.fromhex('0011223344'),
            fileopen.decode_fileopen_document_key('0011223344', 5))
        raw = bytes(range(16))
        self.assertEqual(raw, fileopen.decode_fileopen_document_key(raw, 16))

    def test_document_key_rejects_wrong_length(self):
        with self.assertRaises(fileopen.ADEPTError):
            fileopen.decode_fileopen_document_key('0011', 16)

    def test_genkey_v2_accepts_binary_document_keys(self):
        document = fileopen.PDFDocument.__new__(fileopen.PDFDocument)
        document.decrypt_key = b'ABCDE'
        binary_result = document.genkey_v2(12, 0)
        document.decrypt_key = 'ABCDE'
        text_result = document.genkey_v2(12, 0)

        self.assertEqual(binary_result, text_result)
        self.assertEqual(10, len(binary_result))

    def test_query_order_is_stable(self):
        query = fileopen.build_fileopen_query(
            'DocPerm', ('Build', 'Machine', 'Missing'),
            {'Machine': 'ABC', 'Build': '1016'})
        self.assertEqual('Request=DocPerm&Build=1016&Machine=ABC', query)

    def test_modern_document_url_matches_windows_client(self):
        encoded = fileopen.fileopen_document_url(
            r'C:\Users\Happy Hacker\Downloads\protected.pdf')
        self.assertEqual(
            'file%3A%2F%2F%2FC%7C%2FUsers%2FHappy%20Hacker%2FDownloads%2Fprotected.pdf',
            encoded)

    def test_modern_stamps_are_integer_and_increase(self):
        previous = str(int(fileopen.time.time()) + 1000)
        first = fileopen.next_fileopen_stamp(previous)
        second = fileopen.next_fileopen_stamp(first)
        self.assertEqual(str(int(previous) + 1), first)
        self.assertEqual(str(int(previous) + 2), second)

    def test_modern_query_order_matches_current_client(self):
        fields = {key: key for key in fileopen.FILEOPEN_MODERN_SETTING_FIELDS}
        query = fileopen.build_fileopen_query(
            'Setting', fileopen.FILEOPEN_MODERN_SETTING_FIELDS, fields)
        self.assertLess(query.index('&PageCount='), query.index('&AdobePermanentId='))
        self.assertLess(query.index('&HostAppFeatures='), query.index('&Build='))
        self.assertLess(query.index('&RejectedDlls='), query.index('&OSName='))

    def test_redaction_hashes_sensitive_values(self):
        redacted = fileopen.redact_fileopen_fields(
            {'Build': '1016', 'Machine': 'secret-machine'})
        self.assertEqual('1016', redacted['Build'])
        self.assertRegex(redacted['Machine'], r'^<redacted:[0-9a-f]{12}>$')
        self.assertNotIn('secret-machine', redacted['Machine'])

    def test_redaction_covers_modern_client_identifiers(self):
        redacted = fileopen.redact_fileopen_fields({
            'AdobePermanentId': 'permanent',
            'AdobeInstanceId': 'instance',
            'DocPathUrl': 'file:///C:/Users/person/document.pdf',
            'DocuId': 'document',
            'Ident3Id': 'identity',
            'markstamp': 'machine / public-ip / timestamp',
            'PhysHostname': 'workstation',
            'SaUser': 'person',
        })
        for value in redacted.values():
            self.assertRegex(value, r'^<redacted:[0-9a-f]{12}>$')


if __name__ == '__main__':
    unittest.main()
