"""Adversarial ABI fixtures: provenance must not survive unsupported paths."""
import unittest
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from aimcmp.object_analysis import analyze_function, analyze_export, transfer, parameter_count


def block(address, raw, targets=()):
    return {'start': address, 'end': address + len(bytes.fromhex(raw)),
            'bytes': raw, 'edges': [{'target': t, 'type': 'UnconditionalBranch'} for t in targets]}


def analyze(blocks, imports=None, thunks=None):
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    function = {'address': 0x1000, 'name': 'fixture', 'type': 'unknown', 'blocks': blocks}
    return analyze_function(function, decoder, 0x1000, {}, imports or {}, thunks or {})


class ObjectAnalysisTests(unittest.TestCase):
    def test_push_width_is_architectural_even_if_decoder_reports_encoded_width(self):
        fake = SimpleNamespace(mnemonic='push', prefix=[0, 0, 0, 0],
                               operands=[SimpleNamespace(type=2, size=1, imm=1)],
                               regs_access=lambda: ([], []))
        self.assertEqual(transfer(fake, {'esp': ('entry_stack', 0)})['esp'], ('entry_stack', -4))
        fake.prefix[2] = 0x66
        self.assertEqual(transfer(fake, {'esp': ('entry_stack', 0)})['esp'], ('entry_stack', -2))

    def test_small_and_operand_size_prefixed_pushes_preserve_argument_offsets(self):
        decoder = Cs(CS_ARCH_X86, CS_MODE_32)
        decoder.detail = True
        state = {'esp': ('entry_stack', 0)}
        for instruction in decoder.disasm(bytes.fromhex('6a01666a01586658'), 0x1000):
            state = transfer(instruction, state)
        self.assertEqual(state['esp'], ('entry_stack', 0))
        result = analyze([block(0x1000, '6a018b4424088b4004c3')])
        self.assertEqual(result['receiver_accesses'][0]['origin'], 'entry_stack_slot@0x4')

    def test_unsigned_imm32_and_signed_imm8_have_same_pointer_effect(self):
        for code in ('89c881c0fcffffff8b00c3', '89c883c0fc8b00c3',
                     '89c881e8040000008b00c3'):
            with self.subTest(code=code):
                self.assertEqual(analyze([block(0x1000, code)])['receiver_accesses'][0]['offset'], -4)

    def test_pop_esp_and_unknown_callee_do_not_invent_stack_origins(self):
        for code in ('5c8b04248b00c3', 'e8000000008b4424048b00c3'):
            with self.subTest(code=code):
                self.assertEqual(analyze([block(0x1000, code)])['receiver_accesses'], [])

    def test_getprocaddress_thunk_return_is_dynamic_lookup(self):
        result = analyze([block(0x1000, 'e8fb0f000089c7ffd7c3')],
                         {0x4000: 'kernel32!GetProcAddress'}, {0x2000: 0x4000})
        self.assertEqual(result['calls'][-1]['classification'], 'dynamic_lookup')
        self.assertEqual(result['calls'][-1]['target_origin'][0], 'lookup_result@0x1000')

    def test_parameter_names_and_nested_callback_commas_do_not_change_count(self):
        self.assertEqual(parameter_count({'type': 'int32_t __stdcall(char* path, int mode)'}), 2)
        self.assertEqual(parameter_count({'type': 'int __stdcall(void (*callback)(int, int), void* context)'}), 2)
        self.assertEqual(parameter_count({'type': 'int __stdcall()', 'parameter_count': 3}), 3)
        self.assertIsNone(parameter_count({'type': 'int __stdcall(int value, ...)'}))

    def test_renamed_stdcall_parameters_do_not_create_false_diagnostic(self):
        decoder = Cs(CS_ARCH_X86, CS_MODE_32)
        decoder.detail = True
        function = {'address': 0x1000, 'name': 'callback', 'type': 'int __stdcall(int value)',
                    'blocks': [block(0x1000, 'c20400')]}
        self.assertEqual(analyze_function(function, decoder, 0x1000, {}, {}, {})['diagnostics'], [])

    def test_setup_receiver_and_push_cross_a_block_boundary(self):
        imports = {0x4000: 'Xprt.dll!?Append@TBstr@XPRT@@QAEAAV12@PBD@Z'}
        result = analyze([block(0x1010, 'ff1500400000c3'),
                          block(0x1000, '8d4de06a01', (0x1010,))], imports)
        setup = result['call_setups'][0]
        self.assertEqual(setup['receiver_expression']['displacement'], -32)
        self.assertEqual(setup['pushes_since_previous_call'][0]['rva'], 3)
        self.assertTrue(setup['setup_context']['first_call_in_block'])
        self.assertTrue(setup['setup_context']['pushes_complete'])

    def test_setup_join_disagreement_marks_pushes_incomplete(self):
        imports = {0x4000: 'Xprt.dll!?Append@TBstr@XPRT@@QAEAAV12@PBD@Z'}
        result = analyze([block(0x1000, '8d4de0', (0x1010, 0x1020)),
                          block(0x1010, '6a01', (0x1030,)),
                          block(0x1020, '6a02', (0x1030,)),
                          block(0x1030, 'ff1500400000c3')], imports)
        setup = result['call_setups'][0]
        self.assertEqual(setup['receiver_expression']['displacement'], -32)
        self.assertEqual(setup['pushes_since_previous_call'], [])
        self.assertFalse(setup['setup_context']['pushes_complete'])

    def test_returned_storage_candidate_survives_a_block_boundary(self):
        imports = {0x4000: 'Xprt.dll!?Left@TBstr@XPRT@@QBE?AV12@H@Z',
                   0x4004: 'Xprt.dll!?Assign@TBstr@XPRT@@QAEAAV12@ABV12@@Z'}
        result = analyze([block(0x1000, '6a028d45e0508d4dd0ff1500400000', (0x1020,)),
                          block(0x1020, '508d4dd0ff1504400000c3')], imports)
        temporary = result['call_setups'][1]['pushes_since_previous_call'][0]['expression']
        self.assertEqual(temporary['returned_storage_candidate']['displacement'], -32)

    def test_conflicting_receiver_setups_are_not_merged(self):
        imports = {0x4000: 'Xprt.dll!?GetString@TBstr@XPRT@@QBEPBGXZ'}
        result = analyze([block(0x1000, '85c0', (0x1010, 0x1020)),
                          block(0x1010, '8d4de0', (0x1030,)),
                          block(0x1020, '8d4dd0', (0x1030,)),
                          block(0x1030, 'ff1500400000c3')], imports)
        self.assertIsNone(result['call_setups'][0]['receiver_expression'])

    def test_setup_loop_converges_and_truncation_is_explicit(self):
        imports = {0x4000: 'Xprt.dll!?Append@TBstr@XPRT@@QAEAAV12@PBD@Z'}
        result = analyze([block(0x1000, '8d4de0', (0x1010,)),
                          block(0x1010, '6a01', (0x1010, 0x1020)),
                          block(0x1020, 'ff1500400000c3')], imports)
        self.assertTrue(result['call_setups'][0]['setup_context']['converged'])
        self.assertFalse(result['call_setups'][0]['setup_context']['pushes_complete'])

    def test_wrong_reference_hash_is_rejected_before_analysis(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'pe.json').write_text(json.dumps({'sha256': '0' * 64}))
            (root / 'original.exe').write_bytes(b'unrelated reference')
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                analyze_export(root, root / 'original.exe')

    def test_nonvolatile_copy_survives_call_but_ecx_does_not(self):
        result = analyze([block(0x1000, '89cee8000000008b46048b4108c3')])
        self.assertEqual([(r['origin'], r['offset']) for r in result['receiver_accesses']],
                         [('entry_ecx', 4)])

    def test_conflicting_predecessors_destroy_receiver_origin(self):
        result = analyze([block(0x1000, '85c0', (0x1010, 0x1020)),
                          block(0x1010, '89ce', (0x1030,)),
                          block(0x1020, '31f6', (0x1030,)),
                          block(0x1030, '8b4604c3')])
        self.assertEqual(result['receiver_accesses'], [])

    def test_agreeing_predecessors_preserve_receiver_origin(self):
        result = analyze([block(0x1000, '85c0', (0x1010, 0x1020)),
                          block(0x1010, '89ce', (0x1030,)),
                          block(0x1020, '89ce', (0x1030,)),
                          block(0x1030, '8b4604c3')])
        self.assertEqual(result['receiver_accesses'][0]['offset'], 4)

    def test_partial_register_write_invalidates_full_pointer(self):
        self.assertEqual(analyze([block(0x1000, 'b1008b4104c3')])['receiver_accesses'], [])

    def test_frame_argument_origin_and_actual_return_cleanup(self):
        result = analyze([block(0x1000, '5589e58b75088b8604050000c9c20c00')])
        self.assertEqual(result['receiver_accesses'][0]['origin'], 'entry_stack_slot@0x4')
        self.assertEqual(result['receiver_accesses'][0]['offset'], 0x504)
        self.assertEqual(result['returns'][0]['stack_pop'], 12)

    def test_incomplete_decompiler_signature_is_flagged(self):
        decoder = Cs(CS_ARCH_X86, CS_MODE_32)
        decoder.detail = True
        function = {'address': 0x1000, 'name': 'callback',
                    'type': 'int32_t __stdcall(int32_t arg1)',
                    'blocks': [block(0x1000, 'c20c00')]}
        result = analyze_function(function, decoder, 0x1000, {}, {}, {})
        self.assertIn('pops 12 bytes', result['diagnostics'][0])

    def test_adjustment_changes_effective_member_offset(self):
        result = analyze([block(0x1000, '8d71048b4604c3')])
        memory = [r for r in result['receiver_accesses'] if r['operation'] == 'memory']
        self.assertEqual(memory[0]['offset'], 8)

    def test_import_loaded_into_register_is_not_a_virtual_call(self):
        result = analyze([block(0x1000, '8b1d00400000ffd3c3')], {0x4000: 'dll!function'})
        self.assertEqual(result['calls'][0]['classification'], 'import_register')
        self.assertEqual(result['calls'][0]['name'], 'dll!function')

    def test_imported_pointer_variable_is_distinct_from_imported_function(self):
        result = analyze([block(0x1000, '8b1d00400000ff13c3')], {0x4000: 'dll!pointer'})
        self.assertEqual(result['calls'][0]['classification'], 'imported_pointer_call')

    def test_dynamic_lookup_result_survives_in_nonvolatile_register(self):
        result = analyze([block(0x1000, 'ff150040000089c7ff1504400000ffd7c3')],
                         {0x4000: 'kernel32!GetProcAddress', 0x4004: 'other!function'})
        self.assertEqual(result['calls'][-1]['classification'], 'dynamic_lookup')

    def test_hidden_result_setup_records_frame_address_as_candidate(self):
        imports = {0x4000: 'Xprt.dll!?Left@TBstr@XPRT@@QBE?AV12@H@Z',
                   0x4004: 'Xprt.dll!?Assign@TBstr@XPRT@@QAEAAV12@ABV12@@Z'}
        result = analyze([block(0x1000, '6a028d45e0508d4dd0ff1500400000508d4dd0ff1504400000c3')], imports)
        left, assign = result['call_setups']
        self.assertEqual(left['receiver_expression']['displacement'], -48)
        self.assertEqual(left['pushes_since_previous_call'][-1]['expression']['displacement'], -32)
        temporary = assign['pushes_since_previous_call'][0]['expression']
        self.assertEqual(temporary['returned_storage_candidate']['displacement'], -32)

    def test_setup_expressions_do_not_cross_unknown_calls(self):
        imports = {0x4000: 'Xprt.dll!?GetString@TBstr@XPRT@@QBEPBGXZ'}
        result = analyze([block(0x1000, '8d4de0e800000000ff1500400000c3')], imports)
        self.assertIsNone(result['call_setups'][0]['receiver_expression'])

    def test_field_value_passed_to_release_api_retains_load_provenance(self):
        result = analyze([block(0x1000, '89ce8b0650ff1500400000c3')], {0x4000: 'oleaut32!SysFreeString'})
        push = result['calls'][0]['recent_field_pushes'][0]
        self.assertIn('|entry_ecx|0', push['source']['loaded_value_origin'])

    def test_direct_field_push_is_separate_from_pointee_layout(self):
        result = analyze([block(0x1000, '89ceff7604ff1500400000c3')], {0x4000: 'xprt!free'})
        self.assertEqual(result['calls'][0]['recent_field_pushes'][0]['source']['offset'], 4)

    def test_unreachable_block_has_no_receiver_provenance(self):
        result = analyze([block(0x1000, 'c3'), block(0x1010, '8b4104c3')])
        self.assertEqual(result['receiver_accesses'], [])

    def test_pointer_changing_loop_does_not_invent_stable_offset(self):
        result = analyze([block(0x1000, '89ce', (0x1010,)),
                          block(0x1010, '83c6048b06', (0x1010, 0x1020)),
                          block(0x1020, 'c3')])
        self.assertTrue(result['origin_analysis_converged'])
        self.assertEqual(result['receiver_accesses'], [])


if __name__ == '__main__':
    unittest.main()
