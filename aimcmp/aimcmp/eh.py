"""Decode the observed VC7.1 x86 FuncInfo/unwind-map format.

    Exception metadata provides cleanup edges that normal CFGs omit. This
    decoder records those edges; it does not infer C++ base relationships.
"""
import struct
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG


def initial_state_from_prologue(instructions):
    """Recognize the byte-verified stock helper; unfamiliar variants stay unknown."""
    stock = bytes.fromhex('6aff5064a100000000508b44240c64892500000000896c240c8d6c240c50c3')
    return -1 if b''.join(i.bytes for i in instructions) == stock else None


def decode_unwind_info(read, address):
    def words(address, format):
        size = struct.calcsize(format)
        raw = read(address, size)
        if len(raw) != size:
            raise ValueError('Truncated exception metadata')
        return struct.unpack(format, raw), raw.hex()

    values, raw = words(address, '<IiIIIII')
    magic, count, table, tries, try_table, ip_count, ip_table = values
    if magic != 0x19930520:
        raise ValueError('Unsupported FuncInfo magic')
    if count < 0 or count > 4096 or (count and not table):
        raise ValueError('Invalid unwind-map extent')
    states = []
    for index in range(count):
        (previous, action), data = words(table + index * 8, '<iI')
        if previous < -1 or previous >= index:
            raise ValueError('Invalid/cyclic unwind transition')
        states.append({'state': index, 'previous_state': previous,
                       'action': action, 'address': table + index * 8, 'bytes': data})
    return {'address': address, 'bytes': raw, 'magic': magic, 'states': states,
            'try_block_count': tries, 'try_block_table': try_table,
            'ip_map_count': ip_count, 'ip_map_table': ip_table,
            'limitations': ['Try/catch and IP-state tables are recorded but not decoded.']}


def discover_cleanup(decoder, functions, metadata, read):
    """Recognize handlers by an actual jump to the imported CxxFrameHandler."""
    imports = {entry['iat_address']: group['dll'] + '!' + (entry['name'] or '')
               for group in metadata['imports'] for entry in group['entries']}
    cxx_slots = {slot for slot, name in imports.items() if name.endswith('!__CxxFrameHandler')}
    thunks = set()
    for row in functions:
        code = list(decoder.disasm(read(row['address'], 6), row['address']))
        if code and code[0].mnemonic == 'jmp' and code[0].operands[0].type == X86_OP_MEM:
            operand = code[0].operands[0].mem
            if not operand.base and not operand.index and (operand.disp & 0xffffffff) in cxx_slots:
                thunks.add(row['address'])
    handlers = {}
    for row in functions:
        code = list(decoder.disasm(read(row['address'], 10), row['address']))
        if (len(code) == 2 and code[0].mnemonic == 'mov'
                and code[0].operands[0].type == X86_OP_REG
                and code[0].reg_name(code[0].operands[0].reg) == 'eax'
                and code[0].operands[1].type == X86_OP_IMM
                and code[1].mnemonic == 'jmp' and code[1].operands[0].type == X86_OP_IMM
                and code[1].operands[0].imm in thunks):
            info = decode_unwind_info(read, code[0].operands[1].imm)
            info['handler'] = row['address']
            for state in info['states']:
                action = state['action']
                if not action:
                    continue
                instructions = []
                for item in decoder.disasm(read(action, 32), action):
                    instructions.append({'address': item.address, 'bytes': item.bytes.hex(),
                                         'instruction': item.mnemonic + ' ' + item.op_str})
                    if item.mnemonic in ('jmp', 'ret', 'retf'):
                        break
                state['action_instructions'] = instructions
            handlers[row['address']] = info
    owners = []
    for row in functions:
        code = list(decoder.disasm(read(row['address'], 10), row['address']))
        if (len(code) == 2 and code[0].mnemonic == 'mov'
                and code[0].operands[0].type == X86_OP_REG
                and code[0].reg_name(code[0].operands[0].reg) == 'eax'
                and code[0].operands[1].type == X86_OP_IMM and code[1].mnemonic == 'call'):
            handler = code[0].operands[1].imm
            if handler in handlers:
                initial = None
                proof = []
                if code[1].operands[0].type == X86_OP_IMM:
                    for item in decoder.disasm(read(code[1].operands[0].imm, 64), code[1].operands[0].imm):
                        proof.append(item)
                        if item.mnemonic == 'ret':
                            break
                    initial = initial_state_from_prologue(proof)
                owners.append({'function': row['address'], 'handler': handler,
                               'prologue_bytes': b''.join(item.bytes for item in code).hex(),
                               'prologue_call': code[1].address, 'initial_state': initial,
                               'initialization_evidence': [{'address': i.address, 'bytes': i.bytes.hex(),
                                                           'instruction': i.mnemonic + ' ' + i.op_str} for i in proof],
                               'info': handlers[handler]})
    return owners


def signed(value):
    value &= 0xffffffff
    return value - 0x100000000 if value & 0x80000000 else value


def state_step(instruction, constants, states):
    """Transfer constants and direct writes to the observed EBP-4 state word."""
    from .x86 import canonical_register
    ops = instruction.operands
    replacement = None
    value = None
    if len(ops) >= 2:
        if ops[1].type == X86_OP_IMM:
            value = ops[1].imm
        elif ops[1].type == X86_OP_REG:
            value = constants.get(instruction.reg_name(ops[1].reg))
    if ops and ops[0].type == X86_OP_REG and ops[0].size == 4:
        if instruction.mnemonic == 'mov':
            replacement = value
        elif instruction.mnemonic == 'xor' and len(ops) == 2 and ops[1].type == X86_OP_REG and ops[0].reg == ops[1].reg:
            replacement = 0
        elif instruction.mnemonic == 'and' and value == 0:
            replacement = 0
    result_states = set(states)
    write = None
    if ops and ops[0].type == X86_OP_MEM and ops[0].access & 2:
        memory = ops[0].mem
        if (instruction.reg_name(memory.base) == 'ebp' and not memory.index and not memory.segment
                and memory.disp < 0 and memory.disp + ops[0].size > -4):
            width, shift = ops[0].size * 8, (memory.disp + 4) * 8
            contained = -4 <= memory.disp and memory.disp + ops[0].size <= 0
            mask = ((1 << width) - 1) << shift if contained else 0
            result_states = set()
            for state in states:
                if not contained:
                    result_states.add(None)
                elif instruction.mnemonic == 'mov' and value is not None:
                    if width == 32:
                        result_states.add(signed(value))
                    elif state is not None:
                        result_states.add(signed((state & ~mask) | ((value << shift) & mask)))
                    else:
                        result_states.add(None)
                elif instruction.mnemonic == 'and' and value == 0 and width == 32:
                    result_states.add(0)
                elif instruction.mnemonic == 'or' and value is not None and value & 0xffffffff == 0xffffffff and width == 32:
                    result_states.add(-1)
                else:
                    result_states.add(None)
            write = {'address': instruction.address, 'bytes': instruction.bytes.hex(),
                     'instruction': instruction.mnemonic + ' ' + instruction.op_str}
    result_constants = dict(constants)
    for register in instruction.regs_access()[1]:
        result_constants.pop(canonical_register(instruction.reg_name(register)), None)
    if replacement is not None:
        result_constants[instruction.reg_name(ops[0].reg)] = signed(replacement)
    if instruction.mnemonic == 'call':
        for register in ('eax', 'ecx', 'edx'):
            result_constants.pop(register, None)
    return result_constants, result_states, write


def propagate_states(decoder, function, owner):
    """May-state analysis over the normal CFG, with possible unwind chains at calls."""
    blocks = {b['start']: b for b in function['blocks']}
    instructions = {a: list(decoder.disasm(bytes.fromhex(b['bytes']), a)) for a, b in blocks.items()}
    predecessors = {a: [] for a in blocks}
    for address, block in blocks.items():
        for edge in block['edges']:
            if edge['target'] in blocks:
                predecessors[edge['target']].append(address)
    incoming, outgoing = {}, {}
    converged = False
    for _ in range(max(32, len(blocks) * 8)):
        changed = False
        for address in sorted(blocks):
            facts = [outgoing[p] for p in predecessors[address] if p in outgoing]
            if address == function['address']:
                facts.append(({}, {None}))
            if not facts:
                continue
            constants = {k: v for k, v in facts[0][0].items() if all(f[0].get(k) == v for f in facts[1:])}
            states = set.union(*(f[1] for f in facts))
            incoming[address] = (constants, states)
            for instruction in instructions[address]:
                constants, states, _ = state_step(instruction, constants, states)
                if instruction.address == owner['prologue_call']:
                    states = {owner['initial_state']}
            fact = (constants, states)
            if outgoing.get(address) != fact:
                outgoing[address] = fact
                changed = True
        if not changed:
            converged = True
            break
    def ordered(states):
        return sorted(states, key=lambda n: (n is None, n or 0))
    def chain(state):
        result = []
        table = owner['info']['states']
        while state is not None and state >= 0 and state < len(table):
            entry = table[state]
            result.append({'state': state, 'action': entry['action']})
            state = entry['previous_state']
        return result
    calls, writes, exits, diagnostics = [], [], [], []
    for address in sorted(blocks):
        if address not in incoming or not converged:
            continue
        constants, states = incoming[address]
        for instruction in instructions[address]:
            if instruction.mnemonic == 'call':
                calls.append({'address': instruction.address, 'states': ordered(states),
                              'possible_cleanup': [{'state': s, 'chain': chain(s)} for s in ordered(states)]})
            before = ordered(states)
            constants, states, write = state_step(instruction, constants, states)
            if instruction.address == owner['prologue_call']:
                states = {owner['initial_state']}
            if write:
                writes.append({**write, 'input_states': before, 'result_states': ordered(states)})
            if instruction.mnemonic in ('ret', 'retf'):
                exits.append({'address': instruction.address, 'states': ordered(states)})
        if instructions[address] and not blocks[address]['edges'] and instructions[address][-1].mnemonic == 'jmp':
            exits.append({'address': instructions[address][-1].address, 'states': ordered(states), 'kind': 'tail-jump'})
    if not converged:
        diagnostics.append('State analysis did not converge; no path facts emitted')
    for write in writes:
        if any(s is not None and (s < -1 or s >= len(owner['info']['states'])) for s in write['result_states']):
            diagnostics.append(f'Invalid state after write at {write["address"]:#x}')
    return {'converged': converged, 'calls': calls, 'writes': writes, 'exits': exits,
            'diagnostics': diagnostics,
            'limitations': ['May-states over BN CFG; branch predicates are not solved.',
                           'Direct EBP-4 stores only; aliases and full catch semantics are not modeled.',
                           'Possible cleanup does not assert that a call throws.']}
