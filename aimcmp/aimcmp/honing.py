"""Bring alignment, liveness, and previous attempts into one short decision view."""
from pathlib import Path
import json
from .pe import Image, sha256, canonical
from .mappings import load, resolve, check_original, number
from .compare import instructions
from .honing_analysis import decode, classify, liveness, late_loads, zero_uses
from .honing_ledger import read, FAMILIES
from .config import load_project
from capstone.x86 import X86_OP_IMM


def hone(project_path, target, selector, args, analyze):
    root = Path(project_path).resolve().parent
    left = Image(root / target['original'])
    right = Image(root / target['rebuilt'], root / target['map'] if target.get('map') else None)
    ledger = load(root / target['mapping'])
    check_original(ledger, left)
    matches = [r for r in ledger['records'] if r['kind'] == 'function' and
               selector in (r['id'], r['name'], str(r['original']))]
    if len(matches) != 1:
        raise ValueError('Honing selector must identify one mapped function')
    row = matches[0]
    left_snapshot, right_snapshot = analyze(left, args), analyze(right, args)
    mapping = resolve(ledger, left, right, left_snapshot, right_snapshot)
    match = next(r for r in mapping['records'] if r['id'] == row['id'])
    if match['rebuilt_address'] is None:
        raise ValueError('Function has no rebuilt selector')
    originals = {f['address']: f for f in left_snapshot['functions']}
    candidates = {f['address']: f for f in right_snapshot['functions']}
    a, b = originals[match['original_address']], candidates[match['rebuilt_address']]
    names_a = {f['original']: 'mapping:'+f['id'] for f in mapping['functions']}
    names_b = {f['rebuilt']: 'mapping:'+f['id'] for f in mapping['functions']}
    globals_a = {f['original']: 'mapping:'+f['id'] for f in mapping['globals']}
    globals_b = {f['rebuilt']: 'mapping:'+f['id'] for f in mapping['globals']}
    bindings_path = args.bindings or target.get('honing_bindings')
    if bindings_path:
        binding_file = Path(args.bindings) if args.bindings else root/bindings_path
        bindings = json.loads(binding_file.read_text(encoding='utf-8'))
        if bindings.get('original_sha256') != sha256(left.path):
            raise ValueError('Honing bindings belong to a different original')
        known = {}
        for item in bindings['functions']:
            for symbol, address in item['bindings'].items():
                if symbol in known and known[symbol] != number(address):
                    raise ValueError('Conflicting original binding: '+symbol)
                known[symbol] = number(address)
        for symbol, address in known.items():
            matches = [(va, s) for va, s in right.symbols.items() if s['name'] == canonical(symbol)]
            if len(matches) != 1 or not left.section(address):
                continue
            rebuilt_address, metadata = matches[0]
            left_table, right_table = (names_a, names_b) if metadata['function'] else (globals_a, globals_b)
            left_table.setdefault(address, 'binding:'+canonical(symbol))
            right_table.setdefault(rebuilt_address, 'binding:'+canonical(symbol))
    rows_a, errors_a = instructions(left, a, names_a, globals_a)
    rows_b, errors_b = instructions(right, b, names_b, globals_b)
    if errors_a or errors_b:
        raise ValueError('Cannot hone partially decoded functions: '+str(errors_a+errors_b))
    # Import jump thunks retain exact API identities across different link layouts.
    for image, rows in ((left, rows_a), (right, rows_b)):
        for decoded, instruction in decode(rows):
            for operand in decoded.operands:
                if operand.type != X86_OP_IMM or decoded.mnemonic.startswith(('j', 'loop', 'call')):
                    continue
                address = operand.imm & 0xffffffff
                if image.section(address) and not any(r['offset'] == decoded.imm_offset for r in instruction['references']):
                    instruction['references'].append({'offset': decoded.imm_offset, 'target': hex(address),
                                                       'identity': image.reference(address, names_a if image is left else names_b,
                                                                                   globals_a if image is left else globals_b)})
            for reference in instruction['references']:
                reference_address = number(reference['target'])
                section = image.section(reference_address)
                if not section:
                    continue
                # Generic comparison avoids very short strings as false positives.
                # Keep them as explicitly heuristic literal identities in this screen.
                if reference['identity'].startswith('section-offset:') and not section.Characteristics & 0x20:
                    data = image.read(reference_address, 16)
                    end = data.find(b'\0')
                    if 0 < end < 4 and all(32 <= byte < 127 for byte in data[:end]):
                        reference['identity'] = 'short-literal-heuristic:'+data[:end].decode('ascii')
                thunk = image.read(reference_address, 6)
                if thunk[:2] == b'\xff\x25' and len(thunk) == 6:
                    slot = int.from_bytes(thunk[2:], 'little')
                    if slot in image.imports:
                        reference['identity'] = 'import-thunk:'+image.imports[slot]
    code_a, code_b = decode(rows_a), decode(rows_b)
    comparison = classify(code_a, code_b)
    live_a, live_b = liveness(code_a, a['blocks']), liveness(code_b, b['blocks'])
    reloads = late_loads(code_a, code_b, comparison['alignment'], live_b)
    ledger_path = Path(args.ledger) if args.ledger else (
        root / load_project(project_path).get('workspace_root', '.') / '.local/analysis/honing/ledger.json')
    history = read(ledger_path)
    prior = [r for r in history['attempts'] if r['function'] == row['id'] and r['original_sha256'] == sha256(left.path)]
    plateaus = [r for r in history['plateaus'] if r['function'] == row['id'] and r['original_sha256'] == sha256(left.path)]
    return {'schema': 1, 'kind': 'aimcmp.honing', 'function': {'id': row['id'], 'name': row['name'],
             'original': a['address'], 'rebuilt': b['address']}, 'original_sha256': sha256(left.path),
            'rebuilt_sha256': sha256(right.path), 'map_sha256': sha256(root/target['map']) if target.get('map') else None,
            'analysis': {'original_engine': left_snapshot['engine_version'], 'rebuilt_engine': right_snapshot['engine_version']},
            'bindings_sha256': sha256(binding_file) if bindings_path else None,
            'comparison': comparison, 'liveness': {'original': live_a, 'rebuilt': live_b},
            'late_loads': reloads, 'zero_uses': {'original': zero_uses(code_a, a['blocks']), 'rebuilt': zero_uses(code_b, b['blocks'])},
            'previous_attempts': prior, 'plateaus': plateaus, 'mutation_families': [f for f in FAMILIES if f != 'baseline']}


def compact(report):
    comparison = report['comparison']
    first = comparison['first_divergence']
    lines = [report['function']['name']+' — '+comparison['classification']]
    if first:
        for side in ('original', 'rebuilt'):
            ins = first[side]
            lines.append(side+': '+(hex(ins['address'])+' '+ins['assembly'] if ins else '(no aligned instruction)'))
    else:
        lines.append('No instruction-contract divergence; this is not an exact byte comparison.')
    lines.append('Canonical body: '+('identical' if comparison['canonical_equal'] else 'different')+
                 '; unmatched instructions: '+str(comparison['unpaired_instructions']))
    if comparison['unresolved_reference_divergences']:
        lines.append('Unresolved reference divergences: '+str(len(comparison['unresolved_reference_divergences']))+
                     '; first instruction divergence excludes these; full report retains them.')
    calls_by_index = {side: {c['index']: c for c in report['liveness'][side]['calls']}
                     for side in ('original', 'rebuilt')}
    paired_calls = [(a, b) for a, b in comparison['alignment']
                    if a in calls_by_index['original'] and b in calls_by_index['rebuilt']]
    focus = {}
    if first and paired_calls:
        coordinate = 1 if first['rebuilt_index'] is not None else 0
        position = first['rebuilt_index'] if coordinate else first['original_index']
        a, b = min(paired_calls, key=lambda pair: abs(pair[coordinate]-position))
        focus = {'original': calls_by_index['original'][a], 'rebuilt': calls_by_index['rebuilt'][b]}
    for side in ('original', 'rebuilt'):
        index = first[side+'_index'] if first else 0
        if index is None and first:
            other_side = 'rebuilt' if side == 'original' else 'original'
            other_index = first[other_side+'_index']
            alternatives = [(a, b) for a, b in comparison['alignment'] if a is not None and b is not None]
            if alternatives:
                nearest = min(alternatives, key=lambda pair: abs(pair[1 if side == 'original' else 0]-other_index))
                index = nearest[0 if side == 'original' else 1]
        calls = report['liveness'][side]['calls']
        nearby = focus.get(side) or (min(calls, key=lambda c: abs(c['index']-(index or 0))) if calls else None)
        if nearby:
            visible = nearby['live_across']
            lines.append(side+' nearest call '+hex(nearby['address'])+': live '+', '.join(visible[:6])+
                         (' …' if len(visible) > 6 else ''))
            regs = {k: v[:3]+(['…'] if len(v)>3 else []) for k, v in nearby['reaching_definitions'].items() if not k.startswith('frame:')}
            lines.append('  reaching definitions: '+json.dumps(regs, sort_keys=True))
    for reload in report['late_loads'][:2]:
        lines.append('Possible late reload '+reload['storage']+': original '+hex(reload['original_load'])+
                     ', candidate '+hex(reload['rebuilt_load'])+'; crosses '+str(len(reload['crossed_calls']))+' matched calls')
    z = report['zero_uses']
    lines.append('Zero operands / zero idioms: '+str(z['original']['immediate_zero_operands'])+'/'+str(z['original']['register_zero_idioms'])+
                 ' → '+str(z['rebuilt']['immediate_zero_operands'])+'/'+str(z['rebuilt']['register_zero_idioms']))
    lines.append('Known zero-register uses: '+str(len(z['original']['known_zero_register_uses']))+
                 ' → '+str(len(z['rebuilt']['known_zero_register_uses'])))
    tried = sorted({a['family']+':'+a['outcome'] for a in report['previous_attempts']})
    lines.append('Recorded attempts: '+str(len(report['previous_attempts']))+'; '+(', '.join(tried) if tried else 'none'))
    lines.append('Untried families: '+', '.join(f for f in FAMILIES if f != 'baseline' and not any(a['family'] == f for a in report['previous_attempts'])))
    lines.append('Memory aliasing, ESP slots, and source identity remain unresolved; see --full for evidence.')
    if any(report['liveness'][s]['unknown_control_flow'] for s in ('original', 'rebuilt')):
        lines.append('Unknown indirect control flow: liveness may omit paths; inspect the full report.')
    if report['plateaus']:
        lines.append('Last plateau: '+report['plateaus'][-1]['reason'])
    return '\n'.join(lines[:20])
