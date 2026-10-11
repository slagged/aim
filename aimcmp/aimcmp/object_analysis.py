"""Evidence-only x86 object-boundary analysis of an exported BN corpus.

Register provenance is a must-analysis: paths retain an origin only when all
known predecessors agree. Calls kill volatile registers. Memory aliases and
callee side effects are deliberately not inferred as class relationships.
Run with python -m aimcmp.object_analysis, or the aimcmp objects subcommand.
"""
if __name__ == '__main__' and not __package__:
    raise SystemExit('Run this analyzer with python -m aimcmp.object_analysis from the aimcmp directory.')

import argparse
import hashlib
import json
import re
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
import pefile
from .x86 import canonical_register, signed32, stack_operand_width


def transfer(instruction, state, imports=None, thunks=None):
    """Preserve exact copies and constant pointer adjustments; kill other writes."""
    result = dict(state)
    operands = instruction.operands
    replacement = None
    if operands and operands[0].type == X86_OP_REG and operands[0].size == 4:
        if instruction.mnemonic == 'mov' and operands[1].type == X86_OP_REG:
            if operands[1].size == 4:
                replacement = state.get(instruction.reg_name(operands[1].reg))
        elif instruction.mnemonic == 'mov' and operands[1].type == X86_OP_MEM:
            memory = operands[1].mem
            origin = state.get(instruction.reg_name(memory.base))
            absolute = memory.disp & 0xffffffff
            if (not memory.base and not memory.index and not memory.segment
                    and operands[1].size == 4 and absolute in (imports or {})):
                replacement = (f'import_slot@{absolute:#x}', 0)
            if origin and origin[0] == 'entry_stack' and not memory.index and not memory.segment:
                offset = origin[1] + memory.disp
                if operands[1].size == 4 and offset >= 4 and offset % 4 == 0:
                    replacement = (f'entry_stack_slot@{offset:#x}', 0)
            elif (origin and not memory.index and not memory.segment
                  and origin[0] != 'entry_stack' and not origin[0].startswith(('import_slot@', 'lookup_result@'))):
                replacement = (f'field_load@{instruction.address:#x}|{origin[0]}|{origin[1] + memory.disp}', 0)
        elif instruction.mnemonic == 'lea' and operands[1].type == X86_OP_MEM:
            memory = operands[1].mem
            origin = state.get(instruction.reg_name(memory.base))
            if origin and not memory.index and not memory.segment:
                replacement = (origin[0], origin[1] + memory.disp)
        elif instruction.mnemonic in ('add', 'sub') and operands[1].type == X86_OP_IMM:
            origin = state.get(instruction.reg_name(operands[0].reg))
            if origin:
                delta = signed32(operands[1].imm) * (1 if instruction.mnemonic == 'add' else -1)
                replacement = (origin[0], signed32(origin[1] + delta))
    for register in instruction.regs_access()[1]:
        result.pop(canonical_register(instruction.reg_name(register)), None)
    if replacement is not None:
        result[instruction.reg_name(operands[0].reg)] = replacement
    if instruction.mnemonic in ('push', 'pop') and 'esp' in state:
        origin = state['esp']
        width = stack_operand_width(instruction)
        if (instruction.mnemonic == 'pop' and operands[0].type == X86_OP_REG
                and canonical_register(instruction.reg_name(operands[0].reg)) == 'esp'):
            result.pop('esp', None)
        else:
            result['esp'] = (origin[0], origin[1] + width *
                             (1 if instruction.mnemonic == 'pop' else -1))
    if instruction.mnemonic == 'call':
        # A call's net stack effect depends on callee cleanup. Without an ABI
        # proof, retaining ESP would invent subsequent entry-stack identities.
        for register in ('eax', 'ecx', 'edx', 'esp'):
            result.pop(register, None)
        operand = operands[0]
        slot = None
        if operand.type == X86_OP_IMM:
            slot = (thunks or {}).get(operand.imm & 0xffffffff)
        elif (operand.type == X86_OP_MEM and not operand.mem.base and not operand.mem.index
              and not operand.mem.segment):
            slot = operand.mem.disp & 0xffffffff
        elif operand.type == X86_OP_REG:
            origin = state.get(instruction.reg_name(operand.reg))
            if origin and origin[0].startswith('import_slot@') and origin[1] == 0:
                slot = int(origin[0].split('@')[1], 0)
        if (imports or {}).get(slot, '').endswith('!GetProcAddress'):
            result['eax'] = (f'lookup_result@{instruction.address:#x}', 0)
    return result


def join(states):
    if not states:
        return {}
    return {key: value for key, value in states[0].items()
            if all(state.get(key) == value for state in states[1:])}


def parameter_count(function):
    """Prefer structured type metadata; conservatively parse older cached types.

    This counts parameters, not stack bytes. Hidden results and wide parameters
    still require separate ABI checks. Parameter names have no significance.
    """
    count = function.get('parameter_count')
    if isinstance(count, int) and not isinstance(count, bool) and count >= 0:
        return count
    text = function['type']
    matches = list(re.finditer(r'\b__stdcall\s*(?:[A-Za-z_]\w*\s*)?\(', text))
    if len(matches) != 1:
        return None
    start = matches[0].end()
    depth, angles, brackets = 0, 0, 0
    commas = 0
    for index in range(start, len(text)):
        char = text[index]
        if char == ')' and depth == 0:
            content = text[start:index].strip()
            if angles or brackets or '...' in content:
                return None
            return 0 if content in ('', 'void') else commas + 1
        if char == '(':
            depth += 1
        elif char == ')':
            depth -= 1
        elif char == '<':
            angles += 1
        elif char == '>':
            angles -= 1
        elif char == '[':
            brackets += 1
        elif char == ']':
            brackets -= 1
        elif char == ',' and not (depth or angles or brackets):
            commas += 1
        if min(depth, angles, brackets) < 0:
            return None
    return None



def analyze_function(function, decoder, image_base, names, imports, thunks):
    from .setup_analysis import analyze_setups
    blocks = {row['start']: row for row in function['blocks']}
    decoded = {}
    predecessors = {address: [] for address in blocks}
    for address, block in blocks.items():
        raw = bytes.fromhex(block['bytes'])
        instructions = list(decoder.disasm(raw, address))
        if sum(item.size for item in instructions) != len(raw):
            raise ValueError(f'Incomplete instruction decoding at {address:#x}')
        decoded[address] = instructions
        for edge in block['edges']:
            if edge['target'] in blocks:
                predecessors[edge['target']].append(address)
    entry = function['address']
    incoming, outgoing = {}, {}
    converged = False
    # Unvisited predecessors are temporarily bottom. Iterate to agreement before
    # emitting observations; unreachable blocks never acquire entry provenance.
    for _ in range(max(32, len(blocks) * 8)):
        changed = False
        for address in sorted(blocks):
            states = [outgoing[p] for p in predecessors[address] if p in outgoing]
            if address == entry:
                states.append({'ecx': ('entry_ecx', 0), 'esp': ('entry_stack', 0)})
            if not states:
                continue
            state = join(states)
            incoming[address] = state
            for instruction in decoded[address]:
                state = transfer(instruction, state, imports, thunks)
            if outgoing.get(address) != state:
                outgoing[address] = state
                changed = True
        if not changed:
            converged = True
            break

    accesses, calls, returns = [], [], []
    for address in sorted(blocks):
        state = incoming.get(address, {}) if converged else {}
        recent_field_pushes = []
        for instruction in decoded[address]:
            evidence = {'rva': instruction.address - image_base,
                        'bytes': instruction.bytes.hex(),
                        'instruction': instruction.mnemonic + ' ' + instruction.op_str}
            for index, operand in enumerate(instruction.operands):
                if operand.type != X86_OP_MEM:
                    continue
                memory = operand.mem
                origin = state.get(instruction.reg_name(memory.base))
                if (origin and origin[0] != 'entry_stack'
                        and not origin[0].startswith('import_slot@')
                        and not origin[0].startswith('lookup_result@')
                        and not memory.index and not memory.segment):
                    accesses.append({**evidence, 'operand': index,
                                     'origin': origin[0], 'offset': origin[1] + memory.disp,
                                     'width': operand.size,
                                     'operation': 'address' if instruction.mnemonic == 'lea'
                                     else 'memory', 'access_flags': operand.access})
            if instruction.mnemonic == 'call':
                operand = instruction.operands[0]
                target, classification = None, 'unresolved_indirect'
                if operand.type == X86_OP_IMM:
                    target = operand.imm
                    classification = 'direct'
                elif operand.type == X86_OP_MEM:
                    memory = operand.mem
                    if not memory.base and not memory.index and not memory.segment:
                        target = memory.disp & 0xffffffff
                        classification = 'import_slot' if target in imports else 'static_indirect'
                    elif not memory.index and not memory.segment and memory.disp == 0:
                        origin = state.get(instruction.reg_name(memory.base))
                        if origin and origin[0].startswith('import_slot@') and origin[1] == 0:
                            target = int(origin[0].split('@')[1], 0)
                            classification = 'imported_pointer_call'
                elif operand.type == X86_OP_REG:
                    origin = state.get(instruction.reg_name(operand.reg))
                    if origin and origin[0].startswith('import_slot@') and origin[1] == 0:
                        target = int(origin[0].split('@')[1], 0)
                        classification = 'import_register'
                    elif origin and origin[0].startswith('lookup_result@') and origin[1] == 0:
                        classification = 'dynamic_lookup'
                resolved = thunks.get(target, target)
                target_origin = None
                if operand.type == X86_OP_REG:
                    target_origin = state.get(instruction.reg_name(operand.reg))
                elif operand.type == X86_OP_MEM:
                    target_origin = state.get(instruction.reg_name(operand.mem.base))
                calls.append({**evidence, 'classification': classification,
                              'target': target, 'name': imports.get(resolved, names.get(target)),
                              'target_origin': list(target_origin) if target_origin else None,
                              'recent_field_pushes': list(recent_field_pushes),
                              'ecx_origin': list(state['ecx']) if 'ecx' in state else None})
                recent_field_pushes = []
            if instruction.mnemonic == 'push':
                operand = instruction.operands[0]
                source = None
                if operand.type == X86_OP_MEM:
                    memory = operand.mem
                    origin = state.get(instruction.reg_name(memory.base))
                    if origin and not memory.index and not memory.segment and origin[0] != 'entry_stack':
                        source = {'receiver_origin': origin[0], 'offset': origin[1] + memory.disp,
                                  'width': operand.size}
                elif operand.type == X86_OP_REG:
                    origin = state.get(instruction.reg_name(operand.reg))
                    if origin and origin[0].startswith('field_load@'):
                        source = {'loaded_value_origin': origin[0], 'adjustment': origin[1]}
                if source:
                    recent_field_pushes.append({**evidence, 'source': source})
            if instruction.mnemonic in ('ret', 'retf'):
                returns.append({**evidence, 'stack_pop': instruction.operands[0].imm
                                if instruction.operands else 0})
            state = transfer(instruction, state, imports, thunks)
    diagnostics = []
    if not converged:
        diagnostics.append('Register-origin analysis did not converge; origins suppressed')
    stack_pops = sorted(set(row['stack_pop'] for row in returns))
    if len(stack_pops) > 1:
        diagnostics.append('Return sites disagree on stack cleanup; inspect function boundaries')
    if '__stdcall' in function['type'] and len(stack_pops) == 1 and stack_pops[0]:
        count = parameter_count(function)
        if count is not None and count * 4 != stack_pops[0]:
            diagnostics.append(f'BN lists {count} parameters but machine code '
                               f'pops {stack_pops[0]} bytes; inspect omitted/hidden/wide arguments')
    return {'address': entry, 'rva': entry - image_base,
            'name': names.get(entry, function['name']), 'bn_type': function['type'],
            'parameter_count': parameter_count(function),
            'receiver_accesses': accesses, 'calls': calls, 'returns': returns,
            'call_setups': analyze_setups(decoded, blocks, entry, calls, image_base),
            'diagnostics': diagnostics, 'origin_analysis_converged': converged}


def analyze_export(directory, original):
    directory, original = Path(directory), Path(original)
    metadata = json.loads((directory / 'pe.json').read_text(encoding='utf-8'))
    raw = original.read_bytes()
    if hashlib.sha256(raw).hexdigest() != metadata['sha256']:
        raise ValueError('Original SHA-256 does not match the export')
    functions = [json.loads(line) for line in
                 (directory / 'functions.jsonl').read_text(encoding='utf-8').splitlines()]
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    imports = {item['iat_address']: group['dll'] + '!' +
               (item['name'] or '#' + str(item['ordinal']))
               for group in metadata['imports'] for item in group['entries']}
    names = {item['address']: item['name'] for item in metadata['exports']
             if item['address'] is not None and item['name']}
    base = metadata['image_base']
    image = pefile.PE(data=raw, fast_load=True)
    cleanup = []
    try:
        if image.FILE_HEADER.Machine != 0x14c:
            raise ValueError('Object-boundary analysis requires an x86 PE')
        for function in functions:
            for block in function['blocks']:
                expected = bytes.fromhex(block['bytes'])
                if block['end'] - block['start'] != len(expected):
                    raise ValueError(f'Exported block extent differs at {block["start"]:#x}')
                if image.get_data(block['start'] - base, len(expected)) != expected:
                    raise ValueError(f'Exported block bytes differ at {block["start"]:#x}')
        from .eh import discover_cleanup, propagate_states
        cleanup = discover_cleanup(decoder, functions, metadata,
                                   lambda address, size: image.get_data(address - base, size))
        by_address = {f['address']: f for f in functions}
        for owner in cleanup:
            owner['state_flow'] = propagate_states(decoder, by_address[owner['function']], owner)
        from .security import cookie_observations
        image.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG']])
        config = getattr(image, 'DIRECTORY_ENTRY_LOAD_CONFIG', None)
        cookie = getattr(config.struct, 'SecurityCookie', None) if config else None
        security = cookie_observations(decoder, functions, cookie)
    finally:
        image.close()
    thunks = {}
    for function in functions:
        if len(function['blocks']) != 1:
            continue
        block = function['blocks'][0]
        instructions = list(decoder.disasm(bytes.fromhex(block['bytes']), block['start']))
        if len(instructions) == 1 and instructions[0].mnemonic == 'jmp':
            operand = instructions[0].operands[0]
            if operand.type == X86_OP_MEM and not operand.mem.base and not operand.mem.index:
                target = operand.mem.disp & 0xffffffff
                if target in imports:
                    thunks[function['address']] = target
    rows = [analyze_function(f, decoder, base, names, imports, thunks) for f in functions]
    from .lifetimes import correlate_lifetimes
    observed = {row['address']: row for row in rows}
    for owner in cleanup:
        owner['lifetimes'] = correlate_lifetimes(decoder, by_address[owner['function']],
                                                observed[owner['function']], owner, base, imports)
    return {'schema': 1, 'kind': 'aimcmp.object-observations',
            'analysis': {'algorithm': 'x86-register-must-analysis-v2',
                         'analyzer_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                         'module_hashes': {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                                           for name in ('object_analysis.py', 'eh.py', 'lifetimes.py', 'security.py', 'x86.py', 'setup_analysis.py')}},
            'binary': original.name, 'sha256': metadata['sha256'], 'image_base': base,
            'exception_cleanup': cleanup,
            'security_cookie': security,
            'limitations': ['Entry ECX is a register origin, not proof of this or a class.',
                            'Only exact register copies/constant adjustments are tracked.',
                            'Incoming stack-slot values are origins, not verified pointer arguments.',
                            'No memory alias, ownership or inheritance inference.',
                            'Calls assume the Windows x86 volatile-register contract.',
                            'Unknown callee stack cleanup invalidates ESP provenance.',
                            'Setup expressions use frame registers at their defining instructions; they are not normalized object identities.',
                            'Setup joins retain agreed expressions and common push/window suffixes; completeness flags record loss and truncation.',
                            'Function boundaries and CFG edges remain BN analysis inputs.'],
            'cleanup_limits': ['Only EAX-handler prologues and the observed 0x19930520 format are recognized.',
                               'Manual registration, alias writes, solved branch predicates and catch semantics remain unresolved.'],
            'functions': rows}


def markdown(report):
    lines = ['# Object-boundary observations: ' + report['binary'], '',
             'Reference SHA-256: `' + report['sha256'] + '`', '',
             'These are machine-code observations, not recovered class declarations.', '']
    for function in report['functions']:
        calls = [c for c in function['calls'] if c['classification'] in ('unresolved_indirect', 'dynamic_lookup')
                 or (c['name'] and 'TBstr@' in c['name'])]
        if not function['receiver_accesses'] and not calls and not function['diagnostics']:
            continue
        lines += [f'## {function["address"]:#x} {function["name"]}', '',
                  f'BN type: `{function["bn_type"]}`',
                  'Observed return cleanup: ' + ', '.join(str(r['stack_pop'])
                  for r in function['returns']) + ' bytes.', '']
        offsets = sorted(set((r['offset'], r['width']) for r in function['receiver_accesses']
                             if r['operation'] == 'memory'))
        if offsets:
            lines += ['Register-origin-derived memory accesses (offset, width): `' + str(offsets) + '`', '']
        for call in calls:
            lines.append(f'- RVA {call["rva"]:#x}: `{call["instruction"]}`; '
                         f'{call["name"] or call["classification"]}; ECX origin '
                         f'`{call["ecx_origin"]}`')
        lines.append('')
        lines += ['- ABI review: ' + message for message in function['diagnostics']]
        lines.append('')
        for setup in function['call_setups']:
            lines.append(f'- TBstr setup RVA {setup["rva"]:#x}: receiver '
                         f'`{setup["receiver_expression"]}`; recent pushes '
                         f'`{setup["pushes_since_previous_call"]}`; context '
                         f'`{setup["setup_context"]}`')
        lines.append('')
    lines += ['## Limits', ''] + ['- ' + line for line in report['limitations']]
    lines += ['', '## Security-cookie observations', '']
    cookie = report['security_cookie']['cookie_address']
    if cookie:
        lines.append(f'Load-config cookie address: {cookie:#x}.')
        for row in report['security_cookie']['functions']:
            if row['loads_and_checks_cookie']:
                lines.append(f'- Function {row["function"]:#x}: cookie load and direct check call observed.')
    else:
        lines.append('No load-config cookie address available.')
    lines += ['', '## Exception cleanup metadata', '']
    for owner in report['exception_cleanup']:
        lines += [f'- Function {owner["function"]:#x}: FuncInfo {owner["info"]["address"]:#x}; '
                  f'{len(owner["info"]["states"])} unwind states.']
        for state in owner['info']['states']:
            lines.append(f'  - State {state["state"]} -> {state["previous_state"]}: '
                         f'action {state["action"]:#x}; `' + '; '.join(
                         item['instruction'] for item in state.get('action_instructions', [])) + '`')
        for exit in owner['state_flow']['exits']:
            lines.append(f'  - Exit {exit["address"]:#x}: possible EH states `{exit["states"]}`')
        lines += ['  - Review: ' + d for d in owner['state_flow']['diagnostics']]
        for epoch in owner['lifetimes']['epochs']:
            starts = ', '.join(f'{s["call"]:#x} ({s["kind"]})' for s in epoch['construction_sites']) or 'unknown'
            ends = ', '.join(f'{s["call"]:#x}' for s in epoch['normal_destruction_sites']) or 'unknown'
            lines.append(f'  - Cleanup epoch {epoch["state"]}: EBP{epoch["frame_offset"]:+#x}; '
                         f'construction {starts}; normal destruction {ends}.')
    return '\n'.join(lines) + '\n'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('export', type=Path)
    parser.add_argument('original', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    report = analyze_export(args.export, args.original)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / 'observations.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    (args.output / 'report.md').write_text(markdown(report), encoding='utf-8')
    print(json.dumps({'binary': report['binary'], 'functions': len(report['functions']),
                      'receiver_accesses': sum(len(f['receiver_accesses']) for f in report['functions']),
                      'unresolved_indirect_calls': sum(c['classification'] == 'unresolved_indirect'
                      for f in report['functions'] for c in f['calls'])}))


if __name__ == '__main__':
    main()
