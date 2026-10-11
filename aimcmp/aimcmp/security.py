"""Locate direct x86 stack-cookie accesses and matching check-helper calls."""
from capstone.x86 import X86_OP_REG, X86_OP_MEM, X86_OP_IMM


def cookie_observations(decoder, functions, cookie):
    if not cookie:
        return {'cookie_address': None, 'check_helpers': [], 'functions': []}
    decoded = {f['address']: sorted((i for b in f['blocks'] for i in
               decoder.disasm(bytes.fromhex(b['bytes']), b['start'])), key=lambda i: i.address)
               for f in functions}

    def cookie_operand(operand):
        return (operand.type == X86_OP_MEM and not operand.mem.base and not operand.mem.index
                and operand.mem.disp & 0xffffffff == cookie)

    helpers = []
    for address, instructions in decoded.items():
        if not instructions:
            continue
        first = instructions[0]
        ops = first.operands
        if (first.mnemonic == 'cmp' and len(ops) == 2 and ops[0].type == X86_OP_REG
                and first.reg_name(ops[0].reg) == 'ecx' and cookie_operand(ops[1])):
            helpers.append(address)
    rows = []
    for address, instructions in decoded.items():
        accesses = [i for i in instructions if any(cookie_operand(o) for o in i.operands)]
        checks = [i for i in instructions if i.mnemonic == 'call' and i.operands[0].type == X86_OP_IMM
                  and i.operands[0].imm in helpers]
        if not accesses and not checks:
            continue
        def evidence(ins):
            return {'address': ins.address, 'bytes': ins.bytes.hex(),
                    'instruction': ins.mnemonic + ' ' + ins.op_str}
        rows.append({'function': address, 'cookie_accesses': [evidence(i) for i in accesses],
                     'check_calls': [evidence(i) for i in checks],
                     'loads_and_checks_cookie': bool(checks) and any(i.mnemonic == 'mov'
                         and cookie_operand(i.operands[-1]) for i in accesses)})
    return {'cookie_address': cookie, 'check_helpers': helpers, 'functions': rows,
            'limitations': ['Direct absolute cookie references and direct calls only.',
                           'Check-helper candidates begin with CMP ECX, [cookie]; no full helper semantics inferred.',
                           'A load-config cookie alone does not establish application instrumentation.']}
