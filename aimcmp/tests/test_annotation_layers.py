"""Keep declaration hypotheses out of verified-only analysis."""
import copy
import unittest
import tempfile
import json
from pathlib import Path
from unittest.mock import patch
from aimcmp.pe import Image
from aimcmp.mappings import annotations, load, validate
from aimcmp.binja import snapshot
from aimcmp.annotation_study import study


ROOT = Path(__file__).resolve().parents[2]


class AnnotationLayerTests(unittest.TestCase):
    def setUp(self):
        self.ledger = load(ROOT / 'targets/mappings/aim-contracts.json')
        self.image = Image(ROOT / 'originals/AIM/aim.exe')

    def test_verified_pass_excludes_layout_and_unprobed_signatures(self):
        known = annotations(self.ledger, self.image, 'original', 'verified')
        declarations = '\n'.join(d for layer in known['type_layers'] for d in layer['types'])
        self.assertIn('typedef struct AIM_TBstr', declarations)
        self.assertNotIn('multibyte', declarations)
        left = next(r for r in known['records'] if 'TBstr::Left' in r['name'] or '?Left@' in r['name'])
        self.assertIn('AIM_TBstr *result', left['type'])
        self.assertFalse(any('?Assign@' in r['name'] for r in known['records']))
        all_layers = annotations(self.ledger, self.image, 'original', 'all')
        self.assertIn('multibyte', all_layers['type_layers'][1]['types'][0])
        self.assertTrue(next(r for r in all_layers['records'] if '?Assign@' in r['name'])['type'])

    def test_matched_body_does_not_promote_legacy_signature(self):
        ledger = copy.deepcopy(self.ledger)
        row = {'id': 'matched-helper', 'kind': 'function', 'original': '0x401c6b',
               'name': 'file_time_before', 'type': 'bool helper(void *, void *)',
               'confidence': 'verified', 'evidence': ['Exact body; no independent prototype evidence.']}
        ledger['records'].append(row)
        known = annotations(ledger, self.image, 'original', 'verified')
        helper = next(r for r in known['records'] if r['id'] == row['id'])
        self.assertNotIn('type', helper)
        self.assertEqual(helper['confidence'], 'verified')

    def test_verified_contract_requires_specific_verification(self):
        self.ledger['records'][0].pop('type_verification')
        with self.assertRaisesRegex(ValueError, 'byte-match or probe'):
            validate(self.ledger)

    def test_import_address_must_match_symbol_not_just_image_section(self):
        self.ledger['records'][0]['original'], self.ledger['records'][1]['original'] = (
            self.ledger['records'][1]['original'], self.ledger['records'][0]['original'])
        with self.assertRaisesRegex(ValueError, 'Import identity'):
            annotations(self.ledger, self.image, 'original')

    def test_pinned_annotations_reject_other_binary_before_rpc(self):
        with patch('aimcmp.binja.rpyc.connect') as connect:
            with self.assertRaisesRegex(ValueError, 'pinned original'):
                snapshot(self.image.path, '.unused-cache', annotations={'original_sha256': '0'*64})
            connect.assert_not_called()

    def test_failed_connection_marks_run_failed_instead_of_leaving_old_report_authoritative(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'report.json').write_text('{"old": true}')
            with patch('aimcmp.annotation_study.rpyc.connect', side_effect=RuntimeError('offline')):
                with self.assertRaisesRegex(RuntimeError, 'offline'):
                    study(self.image.path, ROOT / 'targets/mappings/aim-contracts.json', path, [0x402846])
            self.assertEqual(json.loads((path / 'status.json').read_text())['status'], 'failed')


if __name__ == '__main__':
    unittest.main()
