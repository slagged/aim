"""Allocation diagnostics, instruction alignment, and conservative call liveness.

Canonical equality is a screening result. Fixed ABI registers, reference identities,
operand widths and aligned branch destinations remain significant.
"""
from difflib import SequenceMatcher
from collections import defaultdict
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_REG, X86_OP_MEM, X86_OP_IMM
from .x86 import canonical_register

PRESERVED = {'ebx', 'esi', 'edi', 'ebp'}
ALLOCATABLE = {'ebx', 'esi', 'edi'}


def decode(rows):
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    result = []
    for row in rows:
        decoded = list(decoder.disasm(bytes.fromhex(row['bytes']), row['address']))
        if len(decoded) != 1 or decoded[0].size != row['size']:
            raise ValueError('Honing requires completely decoded instructions')
        result.append((decoded[0], row))
    return result


def preservation_scaffold(code):
    """Exclude only matched entry saves and return restores of preserved registers.

    These instructions still appear in alignment and the full report. Their real
    register identities and reverse restore order are checked before excluding.
    """
    saves = []
    for i, (ins, _) in enumerate(code):
        if ins.mnemonic == 'call' or ins.mnemonic.startswith('j'):
            break
        if ins.mnemonic == 'push' and len(ins.operands) == 1 and ins.operands[0].type == X86_OP_REG:
            reg = ins.reg_name(ins.operands[0].reg)
            if reg in ALLOCATABLE:
                saves.append((i, reg))
    restores = []
    for i in range(len(code)-1, max(-1, len(code)-14), -1):
        ins = code[i][0]
        if ins.mnemonic == 'pop' and ins.operands[0].type == X86_OP_REG:
            reg = ins.reg_name(ins.operands[0].reg)
            if reg in ALLOCATABLE:
                restores.append((i, reg))
    if [r for _, r in saves] != [r for _, r in restores] or len(set(r for _, r in saves)) != len(saves):
        return set()
    return {i for i, _ in saves+restores}


def streams(code, canonical=False):
    regs, slots = {}, {}
    scaffold = preservation_scaffold(code) if canonical else set()
    result = []
    for index, (ins, row) in enumerate(code):
        if index in scaffold:
            continue
        refs = {r['offset']: r['identity'] for r in row['references']}
        def register(reg):
            name = ins.reg_name(reg) if reg else ''
            root = canonical_register(name)
            if canonical and root in ALLOCATABLE:
                regs.setdefault(root, 'r'+str(len(regs)))
                # Keep partial-register width and high-byte identity significant.
                return (regs[root], name.endswith('h'))
            return (name, False)
        operands = []
        for op in ins.operands:
            if op.type == X86_OP_REG:
                operands.append(('reg', op.size, register(op.reg)))
            elif op.type == X86_OP_MEM:
                mem = op.mem
                disp = refs.get(ins.disp_offset, mem.disp)
                if canonical and ins.reg_name(mem.base) in ('ebp', 'esp') and not mem.index and not mem.segment:
                    key = (ins.reg_name(mem.base), mem.disp)
                    slots.setdefault(key, 's'+str(len(slots)))
                    disp = slots[key]
                operands.append(('mem', op.size, register(mem.base), register(mem.index),
                                 mem.scale, register(mem.segment), disp))
            else:
                local_branch = (ins.mnemonic.startswith(('j', 'loop')) and
                                refs.get(ins.imm_offset, '').startswith('local:'))
                operands.append(('imm', op.size, 'branch' if local_branch else refs.get(ins.imm_offset, op.imm)))
        result.append((index, (ins.mnemonic, tuple(operands))))
    return result, regs, slots, scaffold


def align(left, right):
    def token(pair):
        ins, row = pair
        # Calls have distinctive identities; branch destinations wait for alignment.
        refs = tuple(r['identity'] for r in row['references'] if not r['identity'].startswith('local:'))
        return ins.mnemonic, tuple((o.type, o.size) for o in ins.operands), refs
    match = SequenceMatcher(None, [token(i) for i in left], [token(i) for i in right], autojunk=False)
    pairs = []
    for tag, a, b, c, d in match.get_opcodes():
        for n in range(max(b-a, d-c)):
            pairs.append((a+n if a+n < b else None, c+n if c+n < d else None))
    return pairs


def branch_mismatches(left, right, pairs):
    paired = {left[a][0].address: right[b][0].address for a, b in pairs if a is not None and b is not None}
    result = []
    for a, b in pairs:
        if a is None or b is None:
            continue
        x, y = left[a][0], right[b][0]
        if x.mnemonic.startswith(('j', 'loop')) and y.mnemonic.startswith(('j', 'loop')):
            if x.operands[0].type == y.operands[0].type == X86_OP_IMM:
                if x.operands[0].imm in paired and paired[x.operands[0].imm] != y.operands[0].imm:
                    result.append({'original': x.address, 'rebuilt': y.address,
                                   'original_target': x.operands[0].imm, 'rebuilt_target': y.operands[0].imm})
    return result


def classify(left, right):
    pairs = align(left, right)
    plain_a, *_ = streams(left)
    plain_b, *_ = streams(right)
    canon_a, regs_a, slots_a, saves_a = streams(left, True)
    canon_b, regs_b, slots_b, saves_b = streams(right, True)
    branches = branch_mismatches(left, right, pairs)
    plain_equal = [t for _, t in plain_a] == [t for _, t in plain_b]
    canonical_equal = [t for _, t in canon_a] == [t for _, t in canon_b]
    def stack_overlaps(code, roles):
        accesses = []
        for ins, _ in code:
            if ins.mnemonic == 'lea':
                continue
            for op in ins.operands:
                if op.type == X86_OP_MEM and not op.mem.index and not op.mem.segment:
                    key = (ins.reg_name(op.mem.base), op.mem.disp)
                    if key in roles:
                        accesses.append((roles[key], key[0], key[1], op.size))
        return sorted({(a[0], b[0], a[3], b[3], a[1] == b[1] and max(a[2], b[2]) < min(a[2]+a[3], b[2]+b[3]))
                       for a in accesses for b in accesses if a[0] != b[0]})
    storage_overlap_equal = stack_overlaps(left, slots_a) == stack_overlaps(right, slots_b)
    # Canonical streams have their own alignment after save/restore exclusions.
    body_pairs = [(a[0], b[0]) for a, b in zip(canon_a, canon_b)] if canonical_equal else pairs
    if canonical_equal:
        scaffold_pairs = [(a, b) for a, b in pairs if a in saves_a and b in saves_b]
        branches = branch_mismatches(left, right, body_pairs+scaffold_pairs)
    if canonical_equal and not storage_overlap_equal:
        kind = 'stack-overlap-difference'
    elif branches:
        kind = 'control-flow-difference'
    elif plain_equal:
        kind = 'same-instruction-contracts'
    elif canonical_equal and bool(saves_a) == bool(saves_b):
        kind = 'allocation-permutation'
    else:
        kind = 'mixed-instruction-or-allocation-difference'
    plain_left, plain_right = dict(plain_a), dict(plain_b)
    weak_refs = []
    def mask_weak(value):
        if isinstance(value, tuple):
            return tuple(mask_weak(v) for v in value)
        if isinstance(value, str) and value.startswith(('section-offset:', 'unresolved-address:')):
            return '<unresolved-reference>'
        return value
    for a, b in pairs:
        if a is not None and b is not None and plain_left[a] != plain_right[b]:
            references = left[a][1]['references']+right[b][1]['references']
            if (any(r['identity'].startswith(('section-offset:', 'unresolved-address:')) for r in references)
                    and mask_weak(plain_left[a]) == mask_weak(plain_right[b])):
                weak_refs.append((a, b))
    divergence = next(({'original_index': a, 'rebuilt_index': b,
                       'original': left[a][1] if a is not None else None,
                       'rebuilt': right[b][1] if b is not None else None}
                       for a, b in pairs if (a, b) not in weak_refs and
                       (a is None or b is None or plain_left[a] != plain_right[b])), None)
    return {'classification': kind, 'canonical_equal': canonical_equal, 'stack_overlap_equal': storage_overlap_equal,
            'branch_mismatches': branches,
            'first_divergence': divergence, 'alignment': pairs,
            'register_roles': {'original': regs_a, 'rebuilt': regs_b},
            'stack_roles': {'original': {str(k): v for k, v in slots_a.items()},
                            'rebuilt': {str(k): v for k, v in slots_b.items()}},
            'preservation_scaffold': {'original': sorted(saves_a), 'rebuilt': sorted(saves_b)},
            'unpaired_instructions': sum(a is None or b is None for a, b in pairs),
            'unresolved_reference_divergences': [{'original': left[a][1], 'rebuilt': right[b][1]} for a, b in weak_refs],
            'scope': 'Allocation screening, never a semantic or byte-match proof. EAX/ECX/EDX and frame registers retain ABI identities.'}


def flow(code, blocks):
    addresses = {ins.address: i for i, (ins, _) in enumerate(code)}
    successors = [set() for _ in code]
    unknown = []
    block_edges = {b['end']: [e['target'] for e in b['edges']] for b in blocks}
    for i, (ins, _) in enumerate(code):
        fallthrough = addresses.get(ins.address+ins.size)
        if ins.mnemonic.startswith('ret') or ins.mnemonic in ('int3', 'ud2'):
            continue
        if ins.address+ins.size in block_edges:
            edges = block_edges[ins.address+ins.size]
            successors[i].update(addresses[a] for a in edges if a in addresses)
            if ins.mnemonic == 'jmp' and ins.operands[0].type != X86_OP_IMM and not edges:
                unknown.append(ins.address)
            continue
        if ins.mnemonic.startswith(('j', 'loop')):
            if ins.operands[0].type == X86_OP_IMM:
                target = addresses.get(ins.operands[0].imm)
                if target is not None:
                    successors[i].add(target)
            else:
                edges = block_edges.get(ins.address+ins.size, [])
                successors[i].update(addresses[a] for a in edges if a in addresses)
                if not edges:
                    unknown.append(ins.address)
            if ins.mnemonic == 'jmp':
                continue
        if fallthrough is not None:
            successors[i].add(fallthrough)
    return successors, unknown


def memory_key(ins, operand, row):
    mem = operand.mem
    if mem.index or mem.segment:
        return None
    base = ins.reg_name(mem.base)
    if base == 'ebp':
        return 'frame:%+d/%d' % (mem.disp, operand.size)
    if not mem.base:
        refs = {r['offset']: r['identity'] for r in row['references']}
        return 'memory:'+str(refs.get(ins.disp_offset, mem.disp))+'/'+str(operand.size)
    return None


def liveness(code, blocks):
    successors, unknown = flow(code, blocks)
    uses, definitions, partials = [], [], []
    slots = set()
    for ins, row in code:
        read, written = ins.regs_access()
        use = {canonical_register(ins.reg_name(r)) for r in read}
        define = {canonical_register(ins.reg_name(r)) for r in written}
        partial = {canonical_register(ins.reg_name(o.reg)) for o in ins.operands
                   if o.type == X86_OP_REG and o.access & 2 and o.size < 4}
        define -= partial  # A byte store does not kill the other bits of EAX, etc.
        for op in ins.operands:
            if op.type != X86_OP_MEM or ins.mnemonic == 'lea':
                continue
            key = memory_key(ins, op, row)
            if key is None or not key.startswith('frame:'):
                continue
            slots.add(key)
            if op.access & 1:
                use.add(key)
            if op.access & 2:
                define.add(key)
        if ins.mnemonic == 'call':
            define |= {'eax', 'ecx', 'edx', 'eflags'}
        uses.append(use); definitions.append(define); partials.append(partial)
    # Overlapping frame accesses do not establish independent source variables.
    def geometry(key):
        offset, size = key.split(':')[1].split('/')
        return int(offset), int(size)
    aliases = {key: {other for other in slots if max(geometry(key)[0], geometry(other)[0]) <
                    min(sum(geometry(key)), sum(geometry(other)))} for key in slots}
    for i in range(len(code)):
        for key in list(uses[i] & slots):
            uses[i] |= aliases[key]
        for key in list(definitions[i] & slots):
            offset, size = geometry(key)
            definitions[i] |= {k for k in aliases[key] if offset <= geometry(k)[0] and
                               offset+size >= sum(geometry(k))}
            partials[i] |= aliases[key]-definitions[i]
    live_in, live_out = [set() for _ in code], [set() for _ in code]
    changed = True
    while changed:
        changed = False
        for i in range(len(code)-1, -1, -1):
            out = set().union(*(live_in[j] for j in successors[i]))
            incoming = uses[i] | (out-definitions[i])
            if incoming != live_in[i] or out != live_out[i]:
                changed = True; live_in[i], live_out[i] = incoming, out
    predecessors = [set() for _ in code]
    for i, succ in enumerate(successors):
        for j in succ:
            predecessors[j].add(i)
    all_locations = set().union(*uses, *definitions)
    incoming, outgoing = [dict() for _ in code], [dict() for _ in code]
    changed = True
    while changed:
        changed = False
        for i, (ins, _) in enumerate(code):
            joined = defaultdict(set)
            for p in predecessors[i]:
                for key, values in outgoing[p].items():
                    joined[key] |= values
            if i == 0:
                for key in all_locations:
                    joined[key].add('entry')
            result = {key: set(value) for key, value in joined.items()}
            for key in definitions[i]:
                result[key] = {hex(ins.address)}
            for key in partials[i]:
                result.setdefault(key, set()).add('partial@'+hex(ins.address))
            if ins.mnemonic == 'call':
                for key in slots:
                    result.setdefault(key, set()).add('may-clobber@'+hex(ins.address))
            if dict(joined) != incoming[i] or result != outgoing[i]:
                changed = True; incoming[i], outgoing[i] = dict(joined), result
    calls = []
    for i, (ins, row) in enumerate(code):
        if ins.mnemonic != 'call':
            continue
        visible = sorted((live_out[i] & PRESERVED) | (live_out[i] & slots))
        calls.append({'index': i, 'address': ins.address, 'assembly': row['assembly'],
                      'live_across': visible,
                      'reaching_definitions': {key: sorted(incoming[i].get(key, {'unknown'})) for key in visible},
                      'memory_caveat': 'Frame locations may be modified through escaped pointers; no ownership or non-aliasing inference.'})
    return {'calls': calls, 'unknown_control_flow': unknown,
            'scope': 'May-reaching definitions and backward liveness; only preserved registers and frame storage are displayed. ESP-relative slots are unresolved; partial writes and overlapping slots remain conservative.'}


def late_loads(left, right, pairs, right_live):
    calls = [(a, b) for a, b in pairs if a is not None and b is not None and
             left[a][0].mnemonic == right[b][0].mnemonic == 'call']
    def loads(code):
        result = []
        for i, (ins, row) in enumerate(code):
            if ins.mnemonic == 'mov' and len(ins.operands) == 2 and ins.operands[0].type == X86_OP_REG and ins.operands[1].type == X86_OP_MEM:
                key = memory_key(ins, ins.operands[1], row)
                if key:
                    result.append((i, key, canonical_register(ins.reg_name(ins.operands[0].reg))))
        return result
    candidates = loads(right)
    live = {c['index']: c for c in right_live['calls']}
    result = []
    for i, key, reg in loads(left):
        matches = [(j, r) for j, k, r in candidates if k == key]
        if not matches:
            continue
        j, candidate_reg = min(matches, key=lambda pair: abs(pair[0]-i))
        crossed = [(a, b) for a, b in calls if a < i and b > j and candidate_reg in live[b]['live_across']]
        if crossed:
            result.append({'storage': key, 'original_load': left[i][0].address,
                           'rebuilt_load': right[j][0].address, 'original_register': reg,
                           'rebuilt_register': candidate_reg,
                           'crossed_calls': [{'original': left[a][0].address, 'rebuilt': right[b][0].address,
                                              'assembly': left[a][1]['assembly']} for a, b in crossed],
                           'confidence': 'heuristic',
                           'caveat': 'Same physical storage is a candidate pairing, not source identity or proof of aliasing.'})
    return result


def zero_uses(code, blocks=()):
    successors, _ = flow(code, blocks)
    predecessors = [set() for _ in code]
    for i, succ in enumerate(successors):
        for j in succ:
            predecessors[j].add(i)
    incoming, outgoing = [None for _ in code], [None for _ in code]
    changed = True
    while changed:
        changed = False
        for i, (ins, _) in enumerate(code):
            known = [outgoing[p] for p in predecessors[i] if outgoing[p] is not None]
            if i != 0 and not known:
                continue
            before = set.intersection(*known) if known and i != 0 else set()
            after = set(before)
            after -= {canonical_register(ins.reg_name(r)) for r in ins.regs_access()[1]}
            op = ins.operands
            if op and op[0].type == X86_OP_REG and op[0].size == 4 and len(op) == 2:
                destination = canonical_register(ins.reg_name(op[0].reg))
                if ((ins.mnemonic == 'mov' and ((op[1].type == X86_OP_IMM and op[1].imm == 0) or
                                               (op[1].type == X86_OP_REG and canonical_register(ins.reg_name(op[1].reg)) in before)))
                        or (ins.mnemonic in ('xor', 'sub') and op[1].type == X86_OP_REG and op[0].reg == op[1].reg)
                        or (ins.mnemonic == 'and' and op[1].type == X86_OP_IMM and op[1].imm == 0)):
                    after.add(destination)
            if ins.mnemonic == 'call':
                after -= {'eax', 'ecx', 'edx'}
            if before != incoming[i] or after != outgoing[i]:
                incoming[i], outgoing[i] = before, after
                changed = True
    zero_register_uses = []
    for i, (ins, row) in enumerate(code):
        if incoming[i] is None:
            continue
        read = {canonical_register(ins.reg_name(r)) for r in ins.regs_access()[0]}
        known = read & incoming[i]
        if known:
            zero_register_uses.append({'address': ins.address, 'assembly': row['assembly'], 'registers': sorted(known)})
    return {'immediate_zero_operands': sum(o.type == X86_OP_IMM and o.imm == 0 for ins, _ in code for o in ins.operands),
            'register_zero_idioms': sum(ins.mnemonic in ('xor', 'sub') and len(ins.operands) == 2 and
                                      ins.operands[0].type == ins.operands[1].type == X86_OP_REG and
                                      ins.operands[0].reg == ins.operands[1].reg for ins, _ in code),
            'known_zero_register_uses': zero_register_uses,
            'note': 'Immediate/idiom counts are syntactic; register-zero evidence uses a CFG must-join. Memory constants and unknown paths are unresolved.'}
