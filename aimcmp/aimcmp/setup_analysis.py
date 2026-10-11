"""Must-analysis of frame expressions and argument-setup evidence across a CFG."""
from copy import deepcopy
from capstone.x86 import X86_OP_REG, X86_OP_MEM, X86_OP_IMM
from .x86 import canonical_register, signed32


def empty(complete=True):
    return {'expressions': {}, 'pushes': [], 'window': [],
            'pushes_complete': complete, 'window_complete': complete}


def common_suffix(sequences):
    result = []
    for values in zip(*(reversed(s) for s in sequences)):
        if not all(v == values[0] for v in values[1:]):
            break
        result.insert(0, values[0])
    return result


def merge(states):
    result = empty()
    result['expressions'] = {k: v for k, v in states[0]['expressions'].items()
                             if all(s['expressions'].get(k) == v for s in states[1:])}
    for key in ('pushes', 'window'):
        result[key] = common_suffix([s[key] for s in states])
        result[key + '_complete'] = all(s[key + '_complete'] and s[key] == result[key] for s in states)
    return result


def step(instruction, before, calls, image_base):
    state = deepcopy(before)
    expressions = state['expressions']
    operands = instruction.operands
    if instruction.mnemonic == 'call':
        name = calls[instruction.address]['name'] or ''
        for register in ('eax', 'ecx', 'edx'):
            expressions.pop(register, None)
        # Only the separately probed TBstr Left ABI gets a result candidate.
        if '?Left@TBstr@XPRT@@QBE?AV12@H@Z' in name and state['pushes']:
            expressions['eax'] = {'returned_storage_candidate': state['pushes'][-1]['expression'],
                                  'producer_rva': instruction.address - image_base}
        state.update(pushes=[], window=[], pushes_complete=True, window_complete=True)
        return state
    replacement = None
    if operands and operands[0].type == X86_OP_REG and operands[0].size == 4:
        if instruction.mnemonic == 'lea' and operands[1].type == X86_OP_MEM:
            memory = operands[1].mem
            if not memory.index and not memory.segment:
                base = instruction.reg_name(memory.base)
                if base in ('ebp', 'esp'):
                    replacement = {'frame_register': base, 'displacement': memory.disp,
                                   'definition_rva': instruction.address - image_base}
        elif instruction.mnemonic == 'mov' and operands[1].type == X86_OP_REG and operands[1].size == 4:
            replacement = expressions.get(instruction.reg_name(operands[1].reg))
        elif instruction.mnemonic in ('add', 'sub') and operands[1].type == X86_OP_IMM:
            expression = expressions.get(instruction.reg_name(operands[0].reg))
            if expression and 'frame_register' in expression:
                delta = signed32(operands[1].imm) * (1 if instruction.mnemonic == 'add' else -1)
                replacement = {**expression, 'displacement': signed32(expression['displacement'] + delta)}
    if instruction.mnemonic == 'push':
        operand = operands[0]
        expression = expressions.get(instruction.reg_name(operand.reg)) if operand.type == X86_OP_REG else None
        state['pushes'].append({'rva': instruction.address - image_base,
                               'operand': instruction.op_str, 'expression': expression})
        if len(state['pushes']) > 16:
            state['pushes'] = state['pushes'][-16:]
            state['pushes_complete'] = False
    for register in instruction.regs_access()[1]:
        expressions.pop(canonical_register(instruction.reg_name(register)), None)
    if replacement is not None:
        expressions[instruction.reg_name(operands[0].reg)] = replacement
    state['window'].append({'rva': instruction.address - image_base, 'bytes': instruction.bytes.hex(),
                            'instruction': instruction.mnemonic + ' ' + instruction.op_str})
    if len(state['window']) > 10:
        state['window'] = state['window'][-10:]
        state['window_complete'] = False
    return state


def analyze_setups(decoded, blocks, entry, calls, image_base):
    """Retain agreed frame expressions and common setup suffixes across blocks.

    A frame expression is relative to EBP/ESP at its defining instruction, not
    a normalized object identity. Completeness flags distinguish disagreement
    and truncation from an empty setup. Pushes can include saved registers.
    """
    calls = {c['rva'] + image_base: c for c in calls}
    predecessors = {a: [] for a in blocks}
    for address, block in blocks.items():
        for edge in block['edges']:
            if edge['target'] in blocks:
                predecessors[edge['target']].append(address)
    incoming, outgoing = {}, {}
    converged = False
    for _ in range(max(32, len(blocks) * 16)):
        changed = False
        for address in sorted(blocks):
            facts = [outgoing[p] for p in predecessors[address] if p in outgoing]
            if address == entry:
                facts.append(empty())
            if not facts:
                continue
            state = merge(facts)
            incoming[address] = state
            for instruction in decoded[address]:
                state = step(instruction, state, calls, image_base)
            if outgoing.get(address) != state:
                outgoing[address] = state
                changed = True
        if not changed:
            converged = True
            break
    rows = []
    for address in sorted(blocks):
        known = converged and address in incoming
        state = incoming[address] if known else empty(False)
        first_call = True
        for instruction in decoded[address]:
            if instruction.mnemonic == 'call':
                call = calls[instruction.address]
                if 'TBstr@XPRT@@' in (call['name'] or ''):
                    rows.append({'rva': call['rva'], 'name': call['name'],
                        'receiver_expression': state['expressions'].get('ecx') if known else None,
                        'pushes_since_previous_call': deepcopy(state['pushes']) if known else [],
                        'setup_window': deepcopy(state['window']) if known else [],
                        'setup_context': {'analysis': 'cfg-must', 'converged': converged,
                            'reachable': address in incoming, 'block_rva': address - image_base,
                            'first_call_in_block': first_call,
                            'pushes_complete': known and state['pushes_complete'],
                            'window_complete': known and state['window_complete']}})
                first_call = False
            state = step(instruction, state, calls, image_base)
    return rows
