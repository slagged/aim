"""Object equivalence must ignore spelling without concealing changed targets."""
import struct
import unittest
import hashlib
import tempfile
from pathlib import Path
import pefile
from aimcmp.coff import section_signature, relocate_section, compare_contributions


def fixture(label=b'local', external=False, addend=b'\0\0\0\0'):
    header = struct.pack('<HHIIIHH', 0x14c, 1, 123, 74, 1, 0, 0)
    section = struct.pack('<8sIIIIIIHHI', b'.text', 0, 0, 4, 60, 64, 0, 1, 0, 0x60000020)
    fix = struct.pack('<IIH', 0, 0, 6)
    symbol = struct.pack('<8sIhHBB', label.ljust(8, b'\0'), 0, 0 if external else 1, 0, 2, 0)
    return header + section + addend + fix + symbol + struct.pack('<I', 4)


class CoffTests(unittest.TestCase):
    def test_full_contribution_comparison_rejects_wrong_target_extent_and_hash(self):
        original = Path(__file__).resolve().parents[2] / 'originals/AIM/idlemon.dll'
        image = pefile.PE(str(original))
        rva = image.OPTIONAL_HEADER.AddressOfEntryPoint
        address = image.OPTIONAL_HEADER.ImageBase + rva
        word = int.from_bytes(image.get_data(rva, 4), 'little')
        image.close()
        item = {'id': 'test', 'object': 'test.obj', 'address': hex(address),
                'size': 4, 'bindings': {'api': hex(word)}}
        manifest = {'schema': 1, 'original_sha256': hashlib.sha256(original.read_bytes()).hexdigest(),
                    'functions': [item]}
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'test.obj').write_bytes(fixture(b'api', True))
            self.assertTrue(compare_contributions(original, directory, manifest)['exact'])
            item['bindings']['api'] = hex(word + 1)
            self.assertFalse(compare_contributions(original, directory, manifest)['exact'])
            item['bindings']['api'] = hex(word)
            item['section'] = '.missing'
            with self.assertRaisesRegex(ValueError, 'exactly one'):
                compare_contributions(original, directory, manifest)
            item['section'] = '.text'
            Path(directory, 'test.obj').write_bytes(fixture())
            item['internal_bindings'] = [{'section': 1, 'offset': 0, 'address': hex(word)}]
            self.assertTrue(compare_contributions(original, directory, manifest)['exact'])
            item['internal_bindings'][0]['offset'] = 1
            with self.assertRaisesRegex(ValueError, 'Unbound'):
                compare_contributions(original, directory, manifest)
            item['internal_bindings'][0]['offset'] = 0
            item['size'] = 5
            self.assertFalse(compare_contributions(original, directory, manifest)['exact'])
            manifest['original_sha256'] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'identify'):
                compare_contributions(original, directory, manifest)

    def test_relative_binding_retains_addend_and_wrong_target_changes_bytes(self):
        section = {'bytes': 'e803000000', 'relocations': [
            {'offset': 1, 'type': 0x14, 'target': ['external', '_callee', 0, 0]}]}
        expected = bytes.fromhex('e8fe0f0000')
        self.assertEqual(relocate_section(section, 0x1000, {'_callee': 0x2000}), expected)
        self.assertNotEqual(relocate_section(section, 0x1000, {'_callee': 0x2001}), expected)
        with self.assertRaisesRegex(ValueError, 'Unbound'):
            relocate_section(section, 0x1000, {})

    def test_absolute_internal_binding_preserves_instruction_bytes(self):
        section = {'bytes': 'a104000000c3', 'relocations': [
            {'offset': 1, 'type': 6, 'target': ['internal', 2, 8]}]}
        self.assertEqual(relocate_section(section, 0x1000, {('internal', 2, 8): 0x5000}),
                         bytes.fromhex('a104500000c3'))

    def test_bad_fixups_are_rejected(self):
        fix = {'offset': 1, 'type': 6, 'target': ['external', '_api', 0, 0]}
        for fixes, message in [([{**fix, 'offset': 2}], 'beyond'),
                               ([fix, fix], 'Overlapping'),
                               ([{**fix, 'type': 7}], 'Unsupported')]:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                relocate_section({'bytes': 'e800000000', 'relocations': fixes}, 0x1000, {'_api': 1})

    def test_local_spelling_and_timestamp_do_not_change_contributions(self):
        left = fixture(b'local1')
        right = bytearray(fixture(b'local2'))
        struct.pack_into('<I', right, 4, 999)
        self.assertEqual(section_signature(left), section_signature(right))

    def test_different_external_target_is_significant(self):
        self.assertNotEqual(section_signature(fixture(b'api1', True)),
                            section_signature(fixture(b'api2', True)))

    def test_different_addend_is_significant(self):
        self.assertNotEqual(section_signature(fixture()), section_signature(fixture(addend=b'\1\0\0\0')))

    def test_truncation_and_wrong_machine_are_rejected(self):
        with self.assertRaises(ValueError):
            section_signature(fixture()[:-4])
        raw = bytearray(fixture())
        struct.pack_into('<H', raw, 0, 0x8664)
        with self.assertRaises(ValueError):
            section_signature(raw)
