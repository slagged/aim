"""PE metadata, address identities, and linker MAP symbols."""
from pathlib import Path
import hashlib
import re
import pefile


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def canonical(name):
    # MSVC x86 C linkage decorations; C++ mangling is kept intact.
    if name.startswith('?'):
        return name
    return re.sub(r'@\d+$', '', name.lstrip('_'))


def map_symbols(path):
    if not path:
        return {}
    result = {}
    for line in Path(path).read_text(errors='replace').splitlines():
        m = re.match(r'\s+[0-9a-fA-F]{4}:[0-9a-fA-F]{8}\s+(\S+)\s+([0-9a-fA-F]{8,16})(?:\s+(f)\s+|\s+)', line)
        if m and int(m[2], 16):
            result[int(m[2], 16)] = {'name': canonical(m[1]), 'function': bool(m[3])}
    return result


class Image:
    def __init__(self, path, map_path=None):
        self.path = Path(path).resolve()
        # Read bytes rather than retaining a Windows mmap handle; build outputs
        # can be replaced and temporary mutation fixtures can be deleted.
        self.pe = pefile.PE(data=self.path.read_bytes())
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.entry = self.base + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.symbols = map_symbols(map_path)
        self.imports = {}
        for directory in getattr(self.pe, 'DIRECTORY_ENTRY_IMPORT', []):
            for item in directory.imports:
                self.imports[item.address] = directory.dll.decode().upper() + '!' + (item.name.decode() if item.name else '#' + str(item.ordinal))
        self.exports = {self.base + item.address: item.name.decode() if item.name else '#' + str(item.ordinal)
                        for item in getattr(getattr(self.pe, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', []) if not item.forwarder}
        self.relocations = {self.base + item.rva for block in getattr(self.pe, 'DIRECTORY_ENTRY_BASERELOC', [])
                            for item in block.entries if item.type == 3}

    def section(self, address):
        return self.pe.get_section_by_rva(address - self.base)

    def read(self, address, length):
        return self.pe.get_data(address - self.base, length)

    def string(self, address):
        section = self.section(address)
        if not section or section.Characteristics & 0x20000000:
            return None
        remaining = section.SizeOfRawData - (address - self.base - section.VirtualAddress)
        if remaining <= 0:
            return None
        data = self.read(address, min(remaining, 512))
        # Recognize terminated printable ANSI strings, never arbitrary data.
        if b'\0' in data:
            value = data.split(b'\0', 1)[0]
            if value and all(32 <= c < 127 or c in (9, 10, 13) for c in value):
                return value.decode('ascii')
        return None

    def reference(self, address, functions, explicit=None):
        if address in self.imports:
            return 'import:' + self.imports[address]
        if address in functions:
            return 'function:' + functions[address]
        if explicit and address in explicit:
            return 'symbol:' + explicit[address]
        value = self.string(address)
        if value is not None:
            return 'string:' + value
        section = self.section(address)
        if section:
            name = section.Name.rstrip(b'\0').decode(errors='replace')
            offset = address - self.base - section.VirtualAddress
            # An offset is weaker evidence than a named data symbol. Mark it.
            return 'section-offset:' + name + '+' + hex(offset)
        return 'unresolved-address:' + hex(address)

    def metadata(self):
        p = self.pe
        rich = p.parse_rich_header()
        values = rich['values'] if rich else []
        sections = []
        for s in p.sections:
            name = s.Name.rstrip(b'\0').decode(errors='replace')
            sections.append({'name': name, 'rva': s.VirtualAddress, 'virtual_size': s.Misc_VirtualSize,
                             'raw_size': s.SizeOfRawData, 'flags': hex(s.Characteristics),
                             'shared': bool(s.Characteristics & 0x10000000),
                             'sha256': hashlib.sha256(s.get_data()[:min(s.Misc_VirtualSize, s.SizeOfRawData)]).hexdigest()})
        raw_end = max((s.PointerToRawData + s.SizeOfRawData for s in p.sections), default=p.OPTIONAL_HEADER.SizeOfHeaders)
        code = b''.join(s.get_data()[:s.Misc_VirtualSize] for s in p.sections if s.Characteristics & 0x20)
        exports = [{'name': x.name.decode() if x.name else None, 'ordinal': x.ordinal, 'rva': x.address,
                    'forwarder': x.forwarder.decode() if x.forwarder else None}
                   for x in getattr(getattr(p, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', [])]
        pdb = []
        for d in getattr(p, 'DIRECTORY_ENTRY_DEBUG', []):
            raw = p.get_data(d.struct.AddressOfRawData, d.struct.SizeOfData)
            if raw.startswith(b'RSDS'):
                pdb.append(raw[24:].split(b'\0')[0].decode(errors='replace'))
        return {'path': str(self.path), 'sha256': sha256(self.path), 'size': self.path.stat().st_size,
                'machine': hex(p.FILE_HEADER.Machine), 'base': self.base, 'entry': self.entry,
                'linker': f'{p.OPTIONAL_HEADER.MajorLinkerVersion}.{p.OPTIONAL_HEADER.MinorLinkerVersion}',
                'timestamp': p.FILE_HEADER.TimeDateStamp, 'file_alignment': p.OPTIONAL_HEADER.FileAlignment,
                'export_timestamp': p.DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp if hasattr(p, 'DIRECTORY_ENTRY_EXPORT') else None,
                'section_alignment': p.OPTIONAL_HEADER.SectionAlignment, 'image_size': p.OPTIONAL_HEADER.SizeOfImage,
                'dll_characteristics': hex(p.OPTIONAL_HEADER.DllCharacteristics), 'sections': sections,
                'stack_reserve': p.OPTIONAL_HEADER.SizeOfStackReserve, 'stack_commit': p.OPTIONAL_HEADER.SizeOfStackCommit,
                'heap_reserve': p.OPTIONAL_HEADER.SizeOfHeapReserve, 'heap_commit': p.OPTIONAL_HEADER.SizeOfHeapCommit,
                'mapped_raw_end': raw_end, 'overlay_size': max(0, self.path.stat().st_size - raw_end),
                'imports': sorted(self.imports.values()),
                'import_layout': [{'rva': a-self.base, 'name': name} for a, name in sorted(self.imports.items())],
                'exports': exports, 'pdb_paths': pdb,
                'code_bytes': len(code), 'code_sha256': hashlib.sha256(code).hexdigest(),
                'rich': [{'product': f'{values[i] >> 16:04x}', 'build': values[i] & 65535, 'count': values[i+1]}
                         for i in range(0, len(values), 2)], 'warnings': list(p.get_warnings())}
