"""Exceptional cleanup is a graph with verified state transitions."""
import struct
import unittest
from aimcmp.eh import decode_unwind_info
from aimcmp.eh import propagate_states, state_step
from aimcmp.eh import initial_state_from_prologue
from capstone import Cs, CS_ARCH_X86, CS_MODE_32


class EhTests(unittest.TestCase):
    def fixture(self, transitions):
        header = struct.pack('<IiIIIII', 0x19930520, len(transitions), 28, 0, 0, 0, 0)
        data = header + b''.join(struct.pack('<iI', prior, action) for prior, action in transitions)
        return lambda address, length: data[address:address + length]

    def test_nested_objects_unwind_in_reverse_order(self):
        row = decode_unwind_info(self.fixture([(-1, 0x1000), (0, 0x2000)]), 0)
        self.assertEqual([(s['state'], s['previous_state'], s['action']) for s in row['states']],
                         [(0, -1, 0x1000), (1, 0, 0x2000)])

    def test_invalid_cycle_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'cyclic'):
            decode_unwind_info(self.fixture([(0, 0x1000)]), 0)

    def test_truncated_or_wrong_format_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Truncated'):
            decode_unwind_info(lambda address, size: b'', 0)
        with self.assertRaisesRegex(ValueError, 'magic'):
            decode_unwind_info(lambda address, size: b'\0' * size, 0)

    def decoder(self):
        decoder = Cs(CS_ARCH_X86, CS_MODE_32)
        decoder.detail = True
        return decoder

    def test_partial_state_store_preserves_upper_bytes(self):
        instruction = next(self.decoder().disasm(bytes.fromhex('c645fc01'), 0x1000))
        _, states, _ = state_step(instruction, {}, {-1})
        self.assertEqual(states, {-255})

    def test_only_verified_prologue_initializes_state(self):
        code = bytes.fromhex('6aff5064a100000000508b44240c64892500000000896c240c8d6c240c50c3')
        self.assertEqual(initial_state_from_prologue(list(self.decoder().disasm(code, 0x1000))), -1)
        unfamiliar = code[:1] + b'\0' + code[2:]
        self.assertIsNone(initial_state_from_prologue(list(self.decoder().disasm(unfamiliar, 0x1000))))

    def test_register_constant_state_store(self):
        instructions = list(self.decoder().disasm(bytes.fromhex('31ff897dfc'), 0x1000))
        constants, states, _ = state_step(instructions[0], {}, {-1})
        _, states, _ = state_step(instructions[1], constants, states)
        self.assertEqual(states, {0})

    def test_cross_boundary_store_invalidates_state(self):
        instruction = next(self.decoder().disasm(bytes.fromhex('c745fb00000000'), 0x1000))
        _, states, _ = state_step(instruction, {}, {0})
        self.assertEqual(states, {None})

    def test_branch_join_retains_both_lifetime_states(self):
        def block(start, raw, targets=()):
            return {'start': start, 'end': start + len(bytes.fromhex(raw)), 'bytes': raw,
                    'edges': [{'target': target} for target in targets]}
        function = {'address': 0x1000, 'blocks': [
            block(0x1000, 'e800000000', (0x1010, 0x1020)),
            block(0x1010, 'c745fc00000000', (0x1030,)),
            block(0x1020, 'c745fc01000000', (0x1030,)),
            block(0x1030, 'e800000000c745fcffffffffc3')]}
        owner = {'prologue_call': 0x1000, 'initial_state': -1,
                 'info': {'states': [{'previous_state': -1, 'action': 0x2000},
                                     {'previous_state': 0, 'action': 0x3000}]}}
        result = propagate_states(self.decoder(), function, owner)
        self.assertTrue(result['converged'])
        self.assertEqual(result['calls'][-1]['states'], [0, 1])
        self.assertEqual([x['action'] for x in result['calls'][-1]['possible_cleanup'][1]['chain']],
                         [0x3000, 0x2000])
        self.assertEqual(result['exits'][0]['states'], [-1])
