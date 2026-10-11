"""Cleanup-state identity must survive stack-slot reuse and ambiguous paths."""
import unittest
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from aimcmp.lifetimes import correlate_lifetimes


class LifetimeTests(unittest.TestCase):
    def fixture(self):
        decoder = Cs(CS_ARCH_X86, CS_MODE_32)
        decoder.detail = True
        code = 'e800000000c645fc00c645fcffe800000000e800000000c645fc01c645fcffe800000000c3'
        instructions = list(decoder.disasm(bytes.fromhex(code), 0x1000))
        calls = [i.address for i in instructions if i.mnemonic == 'call']
        stores = [i.address for i in instructions if i.mnemonic == 'mov']
        constructor, destructor = 'library!??0Object', 'library!??1Object'
        setups = [{'rva': a - 0x1000, 'name': constructor if n in (0, 2) else destructor,
                   'receiver_expression': {'frame_register': 'ebp', 'displacement': -16},
                   'pushes_since_previous_call': []} for n, a in enumerate(calls)]
        entries = [{'state': s, 'previous_state': -1, 'action': 0x2000,
                    'action_instructions': [{'bytes': '8d4df0'}, {'bytes': 'ff2500300000'}]}
                   for s in (0, 1)]
        owner = {'info': {'states': entries}, 'state_flow': {
            'writes': [{'address': a, 'input_states': [before], 'result_states': [after]}
                       for a, before, after in zip(stores, (-1, 0, -1, 1), (0, -1, 1, -1))],
            'calls': [{'address': a, 'states': [-1], 'possible_cleanup': []} for a in calls]}}
        function = {'address': 0x1000, 'blocks': [{'start': 0x1000, 'bytes': code}]}
        return decoder, function, {'call_setups': setups}, owner, 0x1000, {0x3000: destructor}

    def test_reused_storage_has_distinct_cleanup_epochs(self):
        result = correlate_lifetimes(*self.fixture())['epochs']
        self.assertEqual([e['frame_offset'] for e in result], [-16, -16])
        self.assertNotEqual(result[0]['id'], result[1]['id'])
        self.assertTrue(all(len(e['construction_sites']) == len(e['normal_destruction_sites']) == 1
                            for e in result))
        self.assertNotEqual(result[0]['construction_sites'][0]['call'],
                            result[1]['construction_sites'][0]['call'])

    def test_ambiguous_state_and_wrong_receiver_do_not_bind(self):
        args = self.fixture()
        args[3]['state_flow']['writes'][0]['input_states'] = [-1, 1]
        args[2]['call_setups'][-1]['receiver_expression']['displacement'] = -20
        result = correlate_lifetimes(*args)['epochs']
        self.assertEqual(result[0]['construction_sites'], [])
        self.assertEqual(result[1]['normal_destruction_sites'], [])

    def test_hidden_result_remains_an_abi_candidate(self):
        args = self.fixture()
        setup = args[2]['call_setups'][0]
        setup['name'] = 'library!value_return'
        setup['receiver_expression'] = None
        setup['pushes_since_previous_call'] = [{'expression': {'frame_register': 'ebp', 'displacement': -16}}]
        result = correlate_lifetimes(*args)['epochs']
        self.assertEqual(result[0]['construction_sites'][0]['kind'], 'result-storage-candidate')

    def test_unknown_cleanup_target_is_not_an_object_claim(self):
        args = self.fixture()
        args[-1].clear()
        self.assertEqual(correlate_lifetimes(*args)['epochs'], [])

    def test_different_class_constructor_does_not_bind_to_destructor(self):
        args = self.fixture()
        args[2]['call_setups'][0]['name'] = 'library!??0Other'
        self.assertEqual(correlate_lifetimes(*args)['epochs'][0]['construction_sites'], [])
