"""Conservative instruction comparisons with explicit evidence levels."""
import difflib
import hashlib
import json
import re
import struct
import capstone
from .pe import canonical


def integer(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def whole_file_timestamp_check(left, right):
    """Mask only parsed, equally located COFF/export timestamp fields.

    This is separate from raw equality, and never writes to either artifact.
    All padding, resources, headers, and overlays remain part of the comparison.
    """
    data = [bytearray(i.path.read_bytes()) for i in (left, right)]
    fields = []
    for image in (left, right):
        offsets = {'COFF': image.pe.FILE_HEADER.get_field_absolute_offset('TimeDateStamp')}
        if hasattr(image.pe, 'DIRECTORY_ENTRY_EXPORT'):
            offsets['export'] = image.pe.DIRECTORY_ENTRY_EXPORT.struct.get_field_absolute_offset('TimeDateStamp')
        fields.append(offsets)
    if fields[0] != fields[1]:
        return False, []
    changed = []
    for name, offset in fields[0].items():
        if data[0][offset:offset+4] != data[1][offset:offset+4]:
            changed.append({'name': name, 'file_offset': offset})
        for value in data:
            value[offset:offset+4] = b'\0'*4
    return data[0] == data[1], changed


def reliable_name(name):
    return not re.match(r'^(sub_|j_sub_|data_|nullsub_|thunk_)[0-9a-f]+$', name, re.I) and name not in ('_start', 'entry')


def function_name(image, function):
    address = function['address']
    if address in image.exports:
        return canonical(image.exports[address])
    if address == image.entry:
        return 'entry'
    if address in image.symbols:
        return image.symbols[address]['name']
    return canonical(function['name'])


def pair_functions(left, right, left_snapshot, right_snapshot, mapping):
    originals = {f['address']: f for f in left_snapshot['functions']}
    rebuilt = {f['address']: f for f in right_snapshot['functions']}
    pairs = []; used_l = set(); used_r = set()
    for match in mapping.get('functions', []):
        a, b = integer(match['original']), integer(match['rebuilt'])
        if a not in originals or b not in rebuilt:
            raise ValueError(f'Mapping {match["name"]} does not identify analyzed function starts')
        if a in used_l or b in used_r:
            raise ValueError('Function mapping is not one-to-one')
        pairs.append((match['name'], originals[a], rebuilt[b], 'explicit mapping'))
        used_l.add(a); used_r.add(b)
    by_name = {}
    for address, function in rebuilt.items():
        name = function_name(right, function)
        by_name.setdefault(name, []).append(function)
    for address, function in originals.items():
        if address in used_l:
            continue
        name = function_name(left, function)
        candidates = [f for f in by_name.get(name, []) if f['address'] not in used_r]
        if len(candidates) == 1 and (name == 'entry' or reliable_name(name)):
            pairs.append((name, function, candidates[0], 'entry point' if name == 'entry' else 'symbol/export name'))
            used_l.add(address); used_r.add(candidates[0]['address'])
        else:
            pairs.append((name, function, None, 'unmatched'))
    extra = [f for address, f in rebuilt.items() if address not in used_r]
    return pairs, extra


def instructions(image, function, names, symbols):
    dis = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    dis.detail = True
    start = function['address']
    result = []; errors = []; seen = set()
    blocks = sorted(function['blocks'], key=lambda b: b['start'])
    block_starts = {b['start'] for b in blocks}
    for block in blocks:
        address, end = block['start'], block['end']
        if address >= end:
            errors.append('Empty/invalid block at ' + hex(address)); continue
        raw = image.read(address, end - address)
        decoded = list(dis.disasm(raw, address))
        if sum(ins.size for ins in decoded) != end - address:
            errors.append('Incomplete instruction decoding in block ' + hex(address))
        for ins in decoded:
            if ins.address in seen:
                continue
            seen.add(ins.address)
            data = bytearray(ins.bytes); refs = []; handled = set()

            def address_reference(offset, width, target):
                if offset in handled or width != 4 or offset + width > len(data):
                    return
                identity = image.reference(target, names, symbols)
                refs.append({'offset': offset, 'target': hex(target), 'identity': identity})
                data[offset:offset+width] = b'\0' * width
                handled.add(offset)

            for relocation in image.relocations:
                offset = relocation - ins.address
                if 0 <= offset <= len(data) - 4:
                    target = struct.unpack_from('<I', ins.bytes, offset)[0]
                    address_reference(offset, 4, target)
            for operand in ins.operands:
                if operand.type == capstone.x86.X86_OP_MEM and operand.mem.base == 0 and operand.mem.index == 0:
                    target = operand.mem.disp & 0xffffffff
                    if image.section(target) or target in image.imports:
                        address_reference(ins.disp_offset, ins.disp_size, target)
            if (ins.mnemonic == 'call' or ins.mnemonic.startswith('j') or ins.mnemonic.startswith('loop')) and ins.operands and ins.operands[0].type == capstone.x86.X86_OP_IMM:
                target = ins.operands[0].imm & 0xffffffff
                # Same-function branches use local coordinates; cross-function
                # transfers keep paired function identities, not blank targets.
                local = any(b['start'] <= target < b['end'] for b in blocks)
                identity = 'local:' + hex(target - start) if local and ins.mnemonic != 'call' else image.reference(target, names, symbols)
                offset, width = ins.imm_offset, ins.imm_size
                refs.append({'offset': offset, 'target': hex(target), 'identity': identity})
                data[offset:offset+width] = b'\0' * width
            elif ins.imm_size == 4 and ins.imm_offset not in handled:
                target = struct.unpack_from('<I', ins.bytes, ins.imm_offset)[0]
                if target in symbols or target in names or image.string(target) is not None:
                    address_reference(ins.imm_offset, 4, target)
            refs.sort(key=lambda r: r['offset'])
            result.append({'address': ins.address, 'offset': ins.address-start, 'size': ins.size,
                           'bytes': ins.bytes.hex(), 'assembly': ins.mnemonic + ' ' + ins.op_str,
                           'normalized_bytes': data.hex(), 'references': refs,
                           'block_start': ins.address in block_starts})
    result.sort(key=lambda row: row['address'])
    return result, errors


def token(row):
    return row['normalized_bytes'], tuple((r['offset'], r['identity']) for r in row['references'])


def aligned_diff(left_rows, right_rows):
    matcher = difflib.SequenceMatcher(None, [token(r) for r in left_rows], [token(r) for r in right_rows], autojunk=False)
    rows = []; matching_bytes = 0
    for tag, a, b, c, d in matcher.get_opcodes():
        for i in range(max(b-a, d-c)):
            left = left_rows[a+i] if a+i < b else None
            right = right_rows[c+i] if c+i < d else None
            rows.append({'kind': tag, 'original': left, 'rebuilt': right})
            if tag == 'equal':
                matching_bytes += left['size']
    return rows, matching_bytes


def compare(left, right, left_snapshot, right_snapshot, mapping=None):
    from .mappings import resolve
    mapping = resolve(mapping or {}, left, right, left_snapshot, right_snapshot)
    pairs, extra = pair_functions(left, right, left_snapshot, right_snapshot, mapping)
    left_names = {f['address']: name for name, f, _, _ in pairs}
    right_names = {g['address']: name for name, _, g, _ in pairs if g}
    # Stable IDs retain reference identity when a reconstructed name changes.
    for row in mapping.get('functions', []):
        if row.get('id'):
            left_names[integer(row['original'])] = right_names[integer(row['rebuilt'])] = 'mapping:'+row['id']
    left_symbols = {integer(s['original']): 'mapping:'+s['id'] if s.get('id') else s['name'] for s in mapping.get('globals', [])}
    right_symbols = {integer(s['rebuilt']): 'mapping:'+s['id'] if s.get('id') else s['name'] for s in mapping.get('globals', [])}
    records = {r['original_address']: r for r in mapping.get('records', [])}
    # MAP-only names on one side are not treated as identities on both sides.
    # Auto-pair data symbols only when both images provide the same unique name.
    left_data = {s['name']: a for a, s in left.symbols.items() if not s['function']}
    right_data = {s['name']: a for a, s in right.symbols.items() if not s['function']}
    for name in left_data.keys() & right_data.keys():
        left_symbols.setdefault(left_data[name], name)
        right_symbols.setdefault(right_data[name], name)
    functions = []
    for name, original, rebuilt, reason in sorted(pairs, key=lambda p: p[1]['address']):
        a, ae = instructions(left, original, left_names, left_symbols)
        b, be = instructions(right, rebuilt, right_names, right_symbols) if rebuilt else ([], [])
        diff, matched_bytes = aligned_diff(a, b)
        original_bytes = sum(r['size'] for r in a)
        raw_exact = bool(rebuilt) and not (ae or be) and [(r['offset'], r['bytes']) for r in a] == [(r['offset'], r['bytes']) for r in b]
        normalized = bool(rebuilt) and not (ae or be) and [token(r) for r in a] == [token(r) for r in b]
        weak = sorted({r['identity'] for row in a+b for r in row['references']
                       if r['identity'].startswith(('section-offset:', 'unresolved-address:'))})
        status = 'missing' if rebuilt is None else 'analysis-error' if ae or be else 'exact' if raw_exact else 'normalized' if normalized else 'different'
        hlil_diff = list(difflib.unified_diff(original['hlil'], rebuilt['hlil'] if rebuilt else [],
                                            fromfile='original HLIL', tofile='rebuilt HLIL', lineterm=''))
        annotation = records.get(original['address'])
        functions.append({'name': name, 'status': status, 'match_reason': reason,
                          'mapping_id': annotation['id'] if annotation else None,
                          'annotation': annotation,
                          'original_address': original['address'], 'rebuilt_address': rebuilt['address'] if rebuilt else None,
                          'original_bytes': original_bytes, 'rebuilt_bytes': sum(r['size'] for r in b),
                          'matched_bytes': matched_bytes, 'coverage_percent': round(100*matched_bytes/original_bytes, 2) if original_bytes else 0,
                          'raw_exact': raw_exact, 'normalized_match': normalized, 'weak_references': weak,
                          'errors': ae+be, 'original_hlil': original['hlil'], 'rebuilt_hlil': rebuilt['hlil'] if rebuilt else [],
                          'hlil_diff': hlil_diff, 'original_blocks': original['blocks'],
                          'rebuilt_blocks': rebuilt['blocks'] if rebuilt else [], 'diff': diff})
    original_meta, rebuilt_meta = left.metadata(), right.metadata()
    metadata_keys = ['machine', 'base', 'entry', 'linker', 'file_alignment', 'section_alignment', 'image_size',
                     'dll_characteristics', 'stack_reserve', 'stack_commit', 'heap_reserve', 'heap_commit',
                     'timestamp', 'export_timestamp', 'size', 'overlay_size', 'imports', 'import_layout', 'exports', 'rich', 'pdb_paths']
    metadata_diff = {k: {'original': original_meta[k], 'rebuilt': rebuilt_meta[k]}
                     for k in metadata_keys if original_meta[k] != rebuilt_meta[k]}
    total = sum(f['original_bytes'] for f in functions)
    matched = sum(f['matched_bytes'] for f in functions)
    timestamp_equivalent, timestamp_fields = whole_file_timestamp_check(left, right)
    return {'schema': 1, 'tool': 'aimcmp 0.1.0', 'original': original_meta, 'rebuilt': rebuilt_meta,
            'analysis': {'original_engine': left_snapshot['engine'], 'rebuilt_engine': right_snapshot['engine'],
                         'original_version': left_snapshot['engine_version'], 'rebuilt_version': right_snapshot['engine_version'],
                         'original_cached': left_snapshot.get('cached', False), 'rebuilt_cached': right_snapshot.get('cached', False)},
            'summary': {'functions': len(functions), 'exact_functions': sum(f['raw_exact'] for f in functions),
                        'normalized_functions': sum(f['normalized_match'] for f in functions),
                        'missing_functions': sum(f['status']=='missing' for f in functions), 'extra_functions': len(extra),
                        'analyzed_original_bytes': total, 'matched_instruction_bytes': matched,
                        'normalized_coverage_percent': round(100*matched/total, 2) if total else 0,
                        'file_exact': original_meta['sha256']==rebuilt_meta['sha256'],
                        'file_match_except_timestamps': timestamp_equivalent,
                        'changed_timestamp_fields': timestamp_fields,
                        'code_sections_exact': original_meta['code_sha256']==rebuilt_meta['code_sha256']},
            'metadata_diff': metadata_diff, 'functions': functions, 'extra_functions': extra,
            'mapping': {'ledger_sha256': mapping.get('ledger_sha256'), 'records': mapping.get('records', []),
                        'original_applied': left_snapshot.get('applied_mappings', []),
                        'rebuilt_applied': right_snapshot.get('applied_mappings', [])},
            'notes': ['Normalized scores measure instruction similarity, not semantic or whole-file equivalence.',
                      'Section-offset references are weaker than explicitly mapped symbols and remain visible.',
                      'HLIL is Binary Ninja automatic analysis, not recovered source.',
                      'Unmatched functions count against coverage; inferred PE boundaries are explicitly labeled.']}
