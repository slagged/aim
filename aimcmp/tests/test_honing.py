"""Adversarial checks for allocation diagnostics and evidence deduplication."""
import json
import tempfile
import unittest
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from aimcmp.honing_analysis import decode, classify, liveness, late_loads, zero_uses
from aimcmp.honing_ledger import identity, record, plateau, token_hash


def code(raw, base=0x1000):
    dis = Cs(CS_ARCH_X86, CS_MODE_32)
    rows = [{'address': i.address, 'offset': i.address-base, 'size': i.size,
             'bytes': i.bytes.hex(), 'assembly': i.mnemonic+' '+i.op_str, 'references': []}
            for i in dis.disasm(bytes.fromhex(raw), base)]
    return decode(rows)


class HoningAnalysisTests(unittest.TestCase):
    def test_slot_canonicalization_cannot_hide_new_partial_overlap(self):
        a = code('8b45fc8b5df8c3')
        b = code('8b45fc8b5dfac3')
        report = classify(a, b)
        self.assertTrue(report['canonical_equal'])
        self.assertEqual(report['classification'], 'stack-overlap-difference')
    def test_zero_register_survives_call_only_for_preserved_register(self):
        a = code('31db31c9e8000000005351c3')
        uses = zero_uses(a)['known_zero_register_uses']
        push = next(r for r in uses if r['assembly'] == 'push ebx')
        self.assertEqual(push['registers'], ['ebx'])
        self.assertFalse(any(r['assembly'] == 'push ecx' for r in uses))
    def test_preserved_register_permutation_with_identical_saves(self):
        # push esi; push edi; mov esi,1; mov edi,2; add esi,edi; pop edi; pop esi; ret
        a = code('5657be01000000bf0200000001fe5f5ec3')
        b = code('5657bf01000000be0200000001f75f5ec3')
        report = classify(a, b)
        self.assertEqual(report['classification'], 'allocation-permutation')
        self.assertTrue(report['canonical_equal'])

    def test_abi_result_register_cannot_be_renamed(self):
        self.assertFalse(classify(code('b801000000c3'), code('b901000000c3'))['canonical_equal'])

    def test_branch_shift_is_derived_but_changed_target_is_not_erased(self):
        a = code('eb0190c3')
        b = code('eb0090c3', 0x2000)
        for stream in (a, b):
            stream[0][1]['references'] = [{'offset': 1, 'identity': 'local:target'}]
        self.assertEqual(classify(a, b)['classification'], 'control-flow-difference')

    def test_call_kills_volatile_values_but_preserved_value_remains_live(self):
        a = code('bb01000000b902000000e80000000001d989c8c3')
        report = liveness(a, [])
        call = report['calls'][0]
        self.assertIn('ebx', call['live_across'])
        self.assertNotIn('ecx', call['live_across'])
        self.assertEqual(call['reaching_definitions']['ebx'], ['0x1000'])

    def test_partial_write_does_not_erase_prior_full_register_definition(self):
        a = code('bb01000000b302e80000000089d8c3')
        report = liveness(a, [])
        defs = report['calls'][0]['reaching_definitions']['ebx']
        self.assertIn('0x1000', defs)
        self.assertIn('partial@0x1005', defs)

    def test_stack_write_after_call_has_visible_unknown_memory_side_effect(self):
        a = code('c7450801000000e8000000008b7508e8000000008b4508c3')
        calls = liveness(a, [])['calls']
        self.assertTrue(any('may-clobber@' in d for d in calls[1]['reaching_definitions']['frame:+8/4']))

    def test_late_load_pairs_memory_not_merely_register_names(self):
        a = code('e8000000008b7508e80000000089f0c3')
        b = code('8b5d08e800000000e80000000089d8c3', 0x2000)
        report = classify(a, b)
        flags = late_loads(a, b, report['alignment'], liveness(b, []))
        self.assertTrue(flags)
        self.assertEqual(flags[0]['storage'], 'frame:+8/4')


class HoningLedgerTests(unittest.TestCase):
    inventory = {'status': 'captured', 'tools': [{'name': 'cl.exe', 'sha256': '1'*64}]}

    def test_token_hash_preserves_strings_and_token_boundaries(self):
        self.assertEqual(token_hash('#line 1 "one"\nint x=1; // hey'), token_hash('# 42 "two"\nint/*hey*/x = 1;'))
        self.assertNotEqual(token_hash('a/**/b'), token_hash('ab'))
        self.assertNotEqual(token_hash('"http://a"'), token_hash('"http://b"'))
        self.assertNotEqual(token_hash('#pragma pack(1)\nint x;'), token_hash('#pragma pack(4)\nint x;'))
        self.assertNotEqual(token_hash('1e-3'), token_hash('1e - 3'))
        self.assertEqual(token_hash('int x;\n/*\n#include <a>\n*/'), token_hash('int x;'))
        with self.assertRaisesRegex(ValueError, 'compiler-preprocessed'):
            token_hash('#include <a>\nint x;')

    def test_cosmetic_duplicates_keep_failure_and_changed_flags_are_new(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'ledger.json'
            first = identity('fn', '0'*64, '/O1', self.inventory, 'int x=1;')
            second = identity('fn', '0'*64, '/O1', self.inventory, 'int x = 1; /*new*/')
            record(path, first, 'Test placement', 'initialization-placement', 'build-failed')
            self.assertTrue(record(path, second, 'Again', 'initialization-placement', 'untested')['duplicate'])
            self.assertNotEqual(first['key'], identity('fn', '0'*64, '/O2', self.inventory, 'int x=1;')['key'])
            data = json.loads(path.read_text())
            self.assertIsNone(data['attempts'][0]['assessment'])
            with self.assertRaisesRegex(ValueError, 'without recorded attempts'):
                plateau(path, 'fn', '0'*64, 'No improvement', 'allocation', ['declaration-order'])
            with self.assertRaisesRegex(ValueError, 'Stopping requires'):
                plateau(path, 'fn', '0'*64, '', 'allocation', ['initialization-placement'])
            plateau(path, 'fn', '0'*64, 'Only build errors so far', 'untested', ['initialization-placement'])


if __name__ == '__main__':
    unittest.main()
