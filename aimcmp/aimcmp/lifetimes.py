"""Correlate cleanup states with local construction and destruction evidence."""
from capstone.x86 import X86_OP_REG, X86_OP_MEM


def correlate_lifetimes(decoder, function, observed, owner, base, imports):
    """Keep reused frame slots separate by unwind state, without guessing types.

    Correlations require a single known state transition and an adjacent call
    in the same basic block. A pushed result buffer is only a producer candidate:
    its ABI must be validated separately. Loops may repeat a static lifetime site.
    """
    calls = {c['address']: c for c in owner['state_flow']['calls']}
    setups = {base + c['rva']: c for c in observed['call_setups']}
    writes = owner['state_flow']['writes']
    blocks = [list(decoder.disasm(bytes.fromhex(b['bytes']), b['start']))
              for b in function['blocks']]

    def frame(expression):
        if expression and expression.get('frame_register') == 'ebp':
            return expression['displacement']
        return None

    def adjacent_call(address, direction):
        for instructions in blocks:
            for index, ins in enumerate(instructions):
                if ins.address != address:
                    continue
                nearby = instructions[:index][::-1] if direction < 0 else instructions[index + 1:]
                for candidate in nearby:
                    if candidate.mnemonic == 'call':
                        return setups.get(candidate.address)
        return None

    rows = []
    for entry in owner['info']['states']:
        action = entry.get('action_instructions', [])
        raw = b''.join(bytes.fromhex(i['bytes']) for i in action)
        instructions = list(decoder.disasm(raw, entry['action']))
        # Accept only the observed two-instruction destructor thunk shape.
        if len(instructions) != 2:
            continue
        load, jump = instructions
        if load.mnemonic != 'lea' or jump.mnemonic != 'jmp':
            continue
        if len(load.operands) != 2 or load.operands[0].type != X86_OP_REG:
            continue
        receiver = load.operands[1]
        target = jump.operands[0]
        if (load.reg_name(load.operands[0].reg) != 'ecx' or receiver.type != X86_OP_MEM
                or load.reg_name(receiver.mem.base) != 'ebp' or receiver.mem.index
                or target.type != X86_OP_MEM or target.mem.base or target.mem.index):
            continue
        destructor = imports.get(target.mem.disp & 0xffffffff)
        if not destructor or '!??1' not in destructor:
            continue
        offset = receiver.mem.disp
        state, previous = entry['state'], entry['previous_state']
        starts, ends = [], []
        for write in writes:
            if write.get('input_states') == [previous] and write['result_states'] == [state]:
                setup = adjacent_call(write['address'], -1)
                if not setup:
                    continue
                creation = None
                same_class = (setup['name'].split('@@', 1)[0].replace('!??0', '!??1')
                              == destructor.split('@@', 1)[0])
                if ('!??0' in setup['name'] and same_class
                        and frame(setup['receiver_expression']) == offset):
                    creation = 'constructor'
                elif '!??0' not in setup['name'] and setup['pushes_since_previous_call'] and frame(
                        setup['pushes_since_previous_call'][-1]['expression']) == offset:
                    creation = 'result-storage-candidate'
                if creation:
                    starts.append({'call': base + setup['rva'], 'name': setup['name'],
                                   'kind': creation, 'activation': write,
                                   'states_before_call': calls[base + setup['rva']]['states']})
            if write.get('input_states') == [state] and write['result_states'] == [previous]:
                setup = adjacent_call(write['address'], 1)
                if (setup and setup['name'] == destructor
                        and frame(setup['receiver_expression']) == offset):
                    ends.append({'call': base + setup['rva'], 'deactivation': write})
        protected = [c['address'] for c in calls.values() if any(
            any(s['state'] == state for s in possible['chain']) for possible in c['possible_cleanup'])]
        rows.append({'id': f'{function["address"]:x}.state.{state}', 'state': state,
                     'previous_state': previous, 'frame_offset': offset,
                     'destructor': destructor, 'unwind_action': entry['action'],
                     'construction_sites': starts, 'normal_destruction_sites': ends,
                     'possibly_protected_calls': protected})
    return {'epochs': rows, 'limitations': [
        'State identity distinguishes cleanup obligations, not source declarations or loop iterations.',
        'Only same-block adjacent calls and exact EBP destructor thunks are correlated.',
        'Result-storage candidates require separate return-ABI validation.',
        'Missing correlations are unknown; no inheritance or complete object size is inferred.']}
