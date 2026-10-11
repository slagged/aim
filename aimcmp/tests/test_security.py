import unittest
import tempfile
import json
import hashlib
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from aimcmp.security import cookie_observations
from aimcmp.object_analysis import analyze_export


class SecurityTests(unittest.TestCase):
    def test_export_pipeline_parses_load_config_in_fast_load_mode(self):
        original = Path(__file__).resolve().parents[2] / 'originals/AIM/aim.exe'
        raw = original.read_bytes()
        # A minimal, independently checked original checker block is sufficient
        # to exercise directory parsing without depending on the full BN cache.
        address = 0x403961
        function = {'address': address, 'name': 'checker', 'type': 'void()',
                    'blocks': [{'start': address, 'end': address + 6,
                                'bytes': '3b0d24604000', 'edges': []}],
                    'assembly': [], 'calls': []}
        metadata = {'sha256': hashlib.sha256(raw).hexdigest(), 'image_base': 0x400000,
                    'imports': [], 'exports': []}
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'pe.json').write_text(json.dumps(metadata))
            Path(directory, 'functions.jsonl').write_text(json.dumps(function) + '\n')
            result = analyze_export(directory, original)['security_cookie']
        self.assertEqual(result['cookie_address'], 0x406024)
        self.assertEqual(result['check_helpers'], [address])

    def test_cookie_presence_alone_is_not_instrumentation(self):
        decoder = Cs(CS_ARCH_X86, CS_MODE_32)
        decoder.detail = True
        functions = [{'address': 0x1000, 'blocks': [{'start': 0x1000, 'bytes': 'a100300000c3'}]}]
        result = cookie_observations(decoder, functions, 0x3000)
        self.assertFalse(result['functions'][0]['loads_and_checks_cookie'])
        self.assertEqual(result['check_helpers'], [])

    def test_cookie_load_and_direct_check_are_recorded(self):
        decoder = Cs(CS_ARCH_X86, CS_MODE_32)
        decoder.detail = True
        functions = [
            {'address': 0x1000, 'blocks': [{'start': 0x1000, 'bytes': 'a100300000e8f60f0000c3'}]},
            {'address': 0x2000, 'blocks': [{'start': 0x2000, 'bytes': '3b0d003000007501c3c3'}]}]
        result = cookie_observations(decoder, functions, 0x3000)
        self.assertEqual(result['check_helpers'], [0x2000])
        self.assertTrue(result['functions'][0]['loads_and_checks_cookie'])
        self.assertEqual(cookie_observations(decoder, functions, 0x4000)['functions'], [])
