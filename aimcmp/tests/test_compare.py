"""Regression checks against the independently verified idlemon fixture.

Run from the aimcmp project root: python -m unittest discover -s tests -v
"""
from pathlib import Path
import json
import tempfile
import unittest
import pefile
from aimcmp.pe import Image
from aimcmp.binja import pe_snapshot
from aimcmp.compare import compare
from aimcmp.cli import write_report

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / '../targets/builds/idlemon/idlemon.dll'
ORIGINAL = ROOT / '../originals/AIM/idlemon.dll'


def comparison(left, right):
    a, b = Image(left), Image(right)
    return compare(a, b, pe_snapshot(a), pe_snapshot(b))


class ComparisonTests(unittest.TestCase):
    def test_independent_exact_code_fixture(self):
        result = comparison(ORIGINAL, FIXTURE)
        self.assertEqual(result['summary']['exact_functions'], 8)
        self.assertEqual(result['summary']['analyzed_original_bytes'], 407)
        self.assertTrue(result['summary']['code_sections_exact'])
        self.assertFalse(result['summary']['file_exact'])

    def test_rebasing_preserves_symbol_identity_but_not_raw_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            changed = Path(d) / 'rebased.dll'
            p = pefile.PE(data=FIXTURE.read_bytes())
            data = bytearray(FIXTURE.read_bytes())
            delta = 0x10000000
            for block in p.DIRECTORY_ENTRY_BASERELOC:
                for item in block.entries:
                    if item.type == 3:
                        offset = p.get_offset_from_rva(item.rva)
                        value = int.from_bytes(data[offset:offset+4], 'little')
                        data[offset:offset+4] = (value+delta).to_bytes(4, 'little')
            offset = p.OPTIONAL_HEADER.get_field_absolute_offset('ImageBase')
            data[offset:offset+4] = (p.OPTIONAL_HEADER.ImageBase+delta).to_bytes(4, 'little')
            changed.write_bytes(data)
            result = comparison(FIXTURE, changed)
            self.assertEqual(result['summary']['normalized_functions'], 8)
            self.assertLess(result['summary']['exact_functions'], 8)
            self.assertFalse(result['summary']['code_sections_exact'])

    def test_wrong_import_target_cannot_be_hidden_by_address_masking(self):
        with tempfile.TemporaryDirectory() as d:
            changed = Path(d) / 'wrong-import.dll'
            p = pefile.PE(str(FIXTURE))
            offset = p.get_offset_from_rva(0x1002)
            data = bytearray(FIXTURE.read_bytes())
            # First function calls GetProcAddress instead of GetTickCount.
            data[offset:offset+4] = (p.OPTIONAL_HEADER.ImageBase + 0x2004).to_bytes(4, 'little')
            changed.write_bytes(data)
            result = comparison(FIXTURE, changed)
            first = result['functions'][0]
            self.assertEqual(first['status'], 'different')
            self.assertFalse(first['normalized_match'])
            self.assertEqual(result['summary']['exact_functions'], 7)
            self.assertFalse(result['summary']['file_match_except_timestamps'])

    def test_metadata_only_change_does_not_claim_whole_file_match(self):
        with tempfile.TemporaryDirectory() as d:
            changed = Path(d) / 'timestamp.dll'
            p = pefile.PE(str(FIXTURE)); p.FILE_HEADER.TimeDateStamp += 1; p.write(str(changed))
            result = comparison(FIXTURE, changed)
            self.assertTrue(result['summary']['code_sections_exact'])
            self.assertFalse(result['summary']['file_exact'])
            self.assertIn('timestamp', result['metadata_diff'])

    def test_unmatched_functions_count_against_coverage(self):
        a, b = Image(FIXTURE), Image(FIXTURE)
        left, right = pe_snapshot(a), pe_snapshot(b)
        right['functions'] = right['functions'][1:]
        result = compare(a, b, left, right)
        self.assertEqual(result['summary']['missing_functions'], 1)
        self.assertLess(result['summary']['normalized_coverage_percent'], 100)

    def test_html_data_is_not_executable_markup(self):
        with tempfile.TemporaryDirectory() as d:
            result = comparison(FIXTURE, FIXTURE)
            result['notes'].append('</script><script>alert(1)</script>')
            output = Path(d) / 'report.html'
            write_report(result, None, output)
            html = output.read_text()
            self.assertNotIn('</script><script>alert(1)</script>', html)
            self.assertIn('\\u003c/script\\u003e', html)

    def test_launcher_fixtures_match_entire_files_except_coff_timestamp(self):
        for name in ('SendFile', 'ShareFile'):
            with self.subTest(name=name):
                original = ROOT / f'../originals/AIM/{name}.exe'
                rebuilt = ROOT / f'../targets/builds/{name}/{name}.exe'
                result = comparison(original, rebuilt)
                self.assertTrue(result['summary']['code_sections_exact'])
                self.assertEqual(result['summary']['exact_functions'], 1)
                a, b = bytearray(original.read_bytes()), bytearray(rebuilt.read_bytes())
                p = pefile.PE(data=a)
                offset = p.FILE_HEADER.get_field_absolute_offset('TimeDateStamp')
                a[offset:offset+4] = b'\0'*4
                b[offset:offset+4] = b'\0'*4
                self.assertEqual(a, b)

    def test_idlemon_complete_layout_except_coff_and_export_timestamps(self):
        result = comparison(ORIGINAL, FIXTURE)
        self.assertTrue(result['summary']['file_match_except_timestamps'])
        self.assertFalse(result['summary']['file_exact'])
        a, b = bytearray(ORIGINAL.read_bytes()), bytearray(FIXTURE.read_bytes())
        original_pe, rebuilt_pe = pefile.PE(data=a), pefile.PE(data=b)
        self.assertEqual(len(a), 4608)
        self.assertEqual(len(b), 4608)
        offsets = [original_pe.FILE_HEADER.get_field_absolute_offset('TimeDateStamp'),
                   original_pe.DIRECTORY_ENTRY_EXPORT.struct.get_field_absolute_offset('TimeDateStamp')]
        rebuilt_offsets = [rebuilt_pe.FILE_HEADER.get_field_absolute_offset('TimeDateStamp'),
                           rebuilt_pe.DIRECTORY_ENTRY_EXPORT.struct.get_field_absolute_offset('TimeDateStamp')]
        self.assertEqual(offsets, rebuilt_offsets)
        for offset in offsets:
            a[offset:offset+4] = b'\0'*4
            b[offset:offset+4] = b'\0'*4
        self.assertEqual(a, b)


if __name__ == '__main__':
    unittest.main()
