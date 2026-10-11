"""Read x86 COFF sections and relocation identities for compiler probes."""
import struct
import hashlib
from pathlib import Path

import pefile


def compare_contributions(original, object_dir, manifest):
    """Compare complete selected contributions, retaining explicit fixup evidence."""
    digest = hashlib.sha256(Path(original).read_bytes()).hexdigest()
    if manifest.get('schema') != 1 or manifest.get('original_sha256') != digest:
        raise ValueError('COFF comparison manifest does not identify this original')
    rows = []
    image = pefile.PE(str(original))
    try:
        if image.FILE_HEADER.Machine != 0x14c:
            raise ValueError('Expected a native x86 PE original')
        for item in manifest['functions']:
            path = Path(object_dir) / item['object']
            if not path.resolve().is_relative_to(Path(object_dir).resolve()):
                raise ValueError('COFF object path escapes its directory')
            raw = path.read_bytes()
            sections = section_signature(raw)
            if 'section_index' in item:
                index = item['section_index']
                if type(index) is not int or not 1 <= index <= len(sections):
                    raise ValueError('Invalid one-based COFF section index')
                sections = [sections[index - 1]]
            if 'section' in item:
                sections = [s for s in sections if s['name'] == item['section']]
            else:
                sections = [s for s in sections if s['flags'] & 0x20 and s['size']]
            if len(sections) != 1:
                raise ValueError('Selection must identify exactly one COFF contribution')
            address, size = int(item['address'], 0), item['size']
            if size <= 0 or address < image.OPTIONAL_HEADER.ImageBase:
                raise ValueError('Invalid original function extent')
            expected = image.get_data(address - image.OPTIONAL_HEADER.ImageBase, size)
            if len(expected) != size:
                raise ValueError('Original function extent is truncated')
            bindings = {name: int(value, 0) for name, value in item['bindings'].items()}
            for target in item.get('internal_bindings', []):
                key = ('internal', target['section'], target['offset'])
                if key in bindings:
                    raise ValueError('Duplicate internal COFF binding')
                bindings[key] = int(target['address'], 0)
            rebuilt = relocate_section(sections[0], address, bindings)
            rows.append({'id': item['id'], 'address': address, 'original_size': size,
                         'rebuilt_size': len(rebuilt), 'exact': expected == rebuilt,
                         'original_bytes': expected.hex(), 'rebuilt_bytes': rebuilt.hex(),
                         'object_sha256': hashlib.sha256(raw).hexdigest(),
                         'section': sections[0]['name'], 'bindings': item['bindings'],
                         'internal_bindings': item.get('internal_bindings', []),
                         'relocations': sections[0]['relocations']})
    finally:
        image.close()
    return {'schema': 1, 'kind': 'aimcmp.coff-comparison', 'original_sha256': digest,
            'scope': 'Selected function contributions after explicit relocation binding',
            'functions': rows, 'exact': bool(rows) and all(row['exact'] for row in rows)}


def relocate_section(section, address, bindings):
    """Place a COFF contribution at an original VA using explicit symbol bindings.

    Only recorded DIR32 and REL32 fixups may change bytes. Internal targets use
    ('internal', section, offset) keys; external targets use their symbol names.
    Callers must supply every target rather than masking unresolved operands.
    """
    if section['bytes'] is None:
        raise ValueError('Cannot relocate a section without initialized bytes')
    raw = bytearray.fromhex(section['bytes'])
    occupied = set()
    for fix in section['relocations']:
        offset = fix['offset']
        if offset < 0 or offset + 4 > len(raw):
            raise ValueError('Relocation extends beyond the section')
        positions = set(range(offset, offset + 4))
        if occupied & positions:
            raise ValueError('Overlapping relocations')
        occupied |= positions
        target = fix['target']
        key = target[1] if target[0] == 'external' else tuple(target)
        if key not in bindings:
            raise ValueError(f'Unbound COFF target: {key}')
        addend = struct.unpack_from('<I', raw, offset)[0]
        value = bindings[key] + addend
        if fix['type'] == 0x14:
            value -= address + offset + 4
        elif fix['type'] != 6:
            raise ValueError(f'Unsupported x86 relocation: {fix["type"]}')
        struct.pack_into('<I', raw, offset, value & 0xffffffff)
    return bytes(raw)


def section_signature(raw):
    """Compare emitted sections without timestamps or compiler-local label names.

    Internal relocation targets retain section number and offset. External names,
    relocation types, offsets, addends and section bytes remain significant.
    This is object-contribution equivalence, not a linked-image match.
    """
    def unpack(format, offset):
        size = struct.calcsize(format)
        if offset < 0 or offset + size > len(raw):
            raise ValueError('Truncated COFF structure')
        return struct.unpack_from(format, raw, offset)

    machine, count, _, symbol_offset, symbol_count, optional, _ = unpack('<HHIIIHH', 0)
    if machine != 0x14c or optional:
        raise ValueError('Expected a native x86 COFF object')
    string_offset = symbol_offset + symbol_count * 18
    string_size = unpack('<I', string_offset)[0] if symbol_offset else 0
    if string_size and (string_size < 4 or string_offset + string_size > len(raw)):
        raise ValueError('Invalid COFF string table')

    def string(index):
        if index < 4 or index >= string_size:
            raise ValueError('Invalid COFF string reference')
        end = raw.find(b'\0', string_offset + index, string_offset + string_size)
        if end < 0:
            raise ValueError('Unterminated COFF string')
        return raw[string_offset + index:end].decode('ascii')

    def name(data):
        if data[:4] == b'\0' * 4:
            return string(struct.unpack('<I', data[4:])[0])
        return data.rstrip(b'\0').decode('ascii')

    symbols = {}
    index = 0
    while index < symbol_count:
        data, value, section, _, storage, auxiliary = unpack('<8sIhHBB', symbol_offset + index * 18)
        if index + auxiliary >= symbol_count:
            raise ValueError('Invalid COFF auxiliary symbol count')
        symbols[index] = {'name': name(data), 'value': value, 'section': section, 'storage': storage}
        index += 1 + auxiliary
    rows = []
    for index in range(count):
        data, _, _, size, pointer, relocation_offset, _, relocations, _, flags = unpack(
            '<8sIIIIIIHHI', 20 + index * 40)
        section_name = data.rstrip(b'\0').decode('ascii')
        if section_name.startswith('/'):
            section_name = string(int(section_name[1:]))
        if flags & 0x01000000:
            raise ValueError('COFF extended relocation counts are unsupported')
        if pointer and pointer + size > len(raw):
            raise ValueError('Truncated COFF section')
        fixes = []
        for number in range(relocations):
            offset, symbol, kind = unpack('<IIH', relocation_offset + number * 10)
            if symbol not in symbols:
                raise ValueError('COFF relocation references an absent/auxiliary symbol')
            target = symbols[symbol]
            identity = ['internal', target['section'], target['value']] if target['section'] > 0 else [
                'external', target['name'], target['section'], target['value']]
            fixes.append({'offset': offset, 'type': kind, 'target': identity})
        rows.append({'name': section_name, 'size': size, 'flags': flags,
                     'bytes': raw[pointer:pointer + size].hex() if pointer else None,
                     'relocations': fixes})
    return rows
