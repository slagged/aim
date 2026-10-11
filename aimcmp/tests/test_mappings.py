"""Persistent identities must survive layout changes without guessing addresses."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, Mock
import copy
import tempfile
import unittest
from aimcmp.pe import Image, sha256
from aimcmp.binja import pe_snapshot, snapshot
from aimcmp.compare import compare
from aimcmp.iteration import compact_report
from aimcmp.mappings import create, validate, save, load, resolve, annotations
from aimcmp.mapping_cli import execute

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = ROOT/'../originals/AIM/idlemon.dll'
REBUILT = ROOT/'../targets/builds/idlemon/idlemon.dll'
MAP = ROOT/'../targets/builds/idlemon/idlemon.map'


def fixture():
    left, right = Image(ORIGINAL), Image(REBUILT, MAP)
    ledger = create(ORIGINAL)
    ledger['records'] = [{'id':'stable-timer', 'kind':'function', 'original':'0x1c001000',
        'name':'Timer', 'type':'unsigned long Timer(void)', 'confidence':'supported',
        'evidence':['Observed GetTickCount subtraction'], 'rebuilt':{'symbol':'IdleTimeSinceLastInput'}}]
    return ledger, left, right


class MappingTests(unittest.TestCase):
    def test_annotation_cache_is_separate_and_changes_with_content(self):
        bv = SimpleNamespace(functions=[], file=SimpleNamespace(close=Mock()))
        bn = SimpleNamespace(core_version=lambda:'fixture', load=Mock(return_value=bv))
        conn = SimpleNamespace(root=SimpleNamespace(import_module=lambda name:bn), close=Mock())
        with tempfile.TemporaryDirectory() as directory:
            with patch('aimcmp.binja.rpyc.connect', return_value=conn), patch('aimcmp.mappings.apply', return_value=[]):
                plain = snapshot(ORIGINAL, directory)
                data = {'types':[], 'records':[]}
                annotated = snapshot(ORIGINAL, directory, annotations=data)
                cached = snapshot(ORIGINAL, directory, annotations=data)
                changed = snapshot(ORIGINAL, directory, annotations={'types':['typedef int MY_INT;'], 'records':[]})
                self.assertFalse(plain['cached'])
                self.assertFalse(annotated['cached'])
                self.assertTrue(cached['cached'])
                self.assertFalse(changed['cached'])
                self.assertEqual(bn.load.call_count, 3)
                self.assertEqual(bv.file.close.call_count, 3)

    def test_annotation_failure_closes_owned_view_and_leaves_no_cache(self):
        bv = SimpleNamespace(functions=[], file=SimpleNamespace(close=Mock()))
        bn = SimpleNamespace(core_version=lambda:'fixture', load=Mock(return_value=bv))
        conn = SimpleNamespace(root=SimpleNamespace(import_module=lambda name:bn), close=Mock())
        with tempfile.TemporaryDirectory() as directory:
            with patch('aimcmp.binja.rpyc.connect', return_value=conn), patch('aimcmp.mappings.apply', side_effect=ValueError('invalid type')):
                with self.assertRaisesRegex(ValueError, 'invalid type'):
                    snapshot(ORIGINAL, directory, annotations={'types':[], 'records':[]})
            bv.file.close.assert_called_once()
            conn.close.assert_called_once()
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_symbol_resolves_after_rebuilt_function_moves(self):
        ledger, left, right = fixture()
        right.symbols[0x1c001170] = right.symbols.pop(0x1c001000)
        right.exports.pop(0x1c001000)
        resolved = resolve(ledger, left, right, pe_snapshot(left), None)
        self.assertEqual(resolved['functions'][0]['rebuilt'], 0x1c001170)
        self.assertEqual(resolved['functions'][0]['id'], 'stable-timer')

    def test_global_reference_uses_stable_id_and_keeps_evidence(self):
        ledger, left, right = fixture()
        ledger['records'].append({'id':'stable-input', 'kind':'global', 'original':'0x1c003014',
            'name':'last_input', 'type':'unsigned long', 'confidence':'verified',
            'evidence':['Whole-file layout and MAP'], 'rebuilt':{'symbol':'last_input'}})
        report = compare(left, right, pe_snapshot(left), pe_snapshot(right), ledger)
        refs = [ref['identity'] for f in report['functions'] for row in f['diff']
                if row['original'] for ref in row['original']['references']]
        self.assertIn('symbol:mapping:stable-input', refs)
        self.assertEqual(report['mapping']['records'][1]['evidence'], ['Whole-file layout and MAP'])

    def test_rename_does_not_invent_a_function_change(self):
        ledger, left, right = fixture()
        before = compare(left, right, pe_snapshot(left), pe_snapshot(right), ledger)
        ledger['records'][0]['name'] = 'BetterTimerName'
        after = compare(left, right, pe_snapshot(left), pe_snapshot(right), ledger)
        brief = compact_report(after, before)
        self.assertEqual(brief['delta']['changed_functions'], [])
        self.assertTrue(brief['delta']['annotations_changed'])
        self.assertEqual(after['functions'][0]['mapping_id'], 'stable-timer')

    def test_legacy_to_ledger_does_not_invent_a_function_change(self):
        ledger, left, right = fixture()
        before = compare(left, right, pe_snapshot(left), pe_snapshot(right))
        after = compare(left, right, pe_snapshot(left), pe_snapshot(right), ledger)
        self.assertEqual(compact_report(after, before)['delta']['changed_functions'], [])

    def test_stale_pinned_address_fails_even_if_timestamp_only(self):
        ledger, left, right = fixture()
        ledger['records'][0]['rebuilt'] = {'address':'0x1c001000', 'sha256':'0'*64}
        with self.assertRaisesRegex(ValueError, 'Stale rebuilt address'):
            resolve(ledger, left, right, pe_snapshot(left), pe_snapshot(right))

    def test_wrong_original_fails(self):
        ledger, left, right = fixture()
        ledger['original']['sha256'] = '0'*64
        with self.assertRaisesRegex(ValueError, 'different original'):
            annotations(ledger, left, 'original')

    def test_ambiguous_symbol_fails(self):
        ledger, left, right = fixture()
        right.symbols[0x1c001200] = dict(right.symbols[0x1c001000])
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            resolve(ledger, left, right, pe_snapshot(left), pe_snapshot(right))

    def test_duplicate_rebuilt_addresses_fail(self):
        ledger, left, right = fixture()
        row = copy.deepcopy(ledger['records'][0])
        row.update(id='another', original='0x1c00100f')
        ledger['records'].append(row)
        with self.assertRaisesRegex(ValueError, 'one-to-one'):
            resolve(ledger, left, right, pe_snapshot(left), pe_snapshot(right))

    def test_pending_record_preserves_original_annotations(self):
        ledger, left, right = fixture()
        ledger['records'][0]['rebuilt'] = None
        self.assertEqual(len(annotations(ledger, left, 'original')['records']), 1)
        self.assertEqual(annotations(ledger, right, 'rebuilt')['records'], [])
        self.assertEqual(resolve(ledger, left, right, pe_snapshot(left), pe_snapshot(right))['functions'], [])

    def test_cli_update_preserves_id_type_evidence_and_selector(self):
        ledger, left, right = fixture()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'mapping.json'
            save(path, ledger)
            args = SimpleNamespace(ledger=str(path), mapping_command='set', id='stable-timer',
                kind=None, original=None, name='BetterTimerName', type=None, confidence=None,
                evidence=['Another observation'], rebuilt_symbol=None, rebuilt_address=None,
                unpaired=False, rebuilt_binary=None)
            with patch('builtins.print'):
                execute(args)
            row = load(path)['records'][0]
            self.assertEqual(row['id'], 'stable-timer')
            self.assertEqual(row['type'], ledger['records'][0]['type'])
            self.assertEqual(len(row['evidence']), 2)
            self.assertEqual(row['rebuilt'], ledger['records'][0]['rebuilt'])

    def test_legacy_mapping_still_pairs(self):
        ledger, left, right = fixture()
        report = compare(left, right, pe_snapshot(left), pe_snapshot(right),
                         {'functions':[{'name':'Legacy', 'original':'0x1c001000', 'rebuilt':'0x1c001000'}]})
        self.assertEqual(report['functions'][0]['name'], 'Legacy')
        self.assertEqual(report['summary']['exact_functions'], 8)
