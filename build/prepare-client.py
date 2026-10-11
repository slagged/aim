"""Stage a VC7.1 client build using private original DLLs and resource data.

Usage: python build/prepare-client.py originals/AIM .local/client-build
Requires pefile. No executable code is extracted into the build inputs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct

import pefile


ORIGINAL_SHA256 = '1d150f88b23acdcec2f82d7f603f4f5d200a30fcb23f5fc87bd0af3d94728840'
MODULES = ['oscore.dll', 'AIMToday.dll', 'oscres.dll', 'AIM_xmlp.dll', 'Xpcs.dll', 'Xprt.dll']
STDCALL_IMPORTS = {'OscoreRun': 12, 'OscoreInitLpShare': 8,
                   'OscoreShutdownOtherInstance': 4, 'PHSetString': 12,
                   'RDBLoadString': 16, 'AIMToday_createWindow': 4}


def resource_name(entry):
    if entry.name is not None:
        return str(entry.name).encode('utf-16le') + b'\0\0'
    return struct.pack('<HH', 0xffff, entry.id)


def align(data):
    return data + b'\0' * (-len(data) % 4)


def extract_resources(pe):
    # A null resource leads each Win32 .res stream.
    output = struct.pack('<IIHHHHIHHII', 0, 32, 0xffff, 0, 0xffff, 0, 0, 0, 0, 0, 0)
    count = 0
    for kind in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for name in kind.directory.entries:
            for language in name.directory.entries:
                resource = language.data.struct
                payload = pe.get_data(resource.OffsetToData, resource.Size)
                names = align(resource_name(kind) + resource_name(name))
                metadata = struct.pack('<IHHII', 0, 0x1030, language.id, 0, 0)
                header = struct.pack('<II', len(payload), 8 + len(names) + len(metadata)) + names + metadata
                output += header + align(payload)
                count += 1
    return output, count


def prepare(originals, destination):
    project = Path(__file__).resolve().parent.parent
    original = originals / 'aim.exe'
    if hashlib.sha256(original.read_bytes()).hexdigest() != ORIGINAL_SHA256:
        raise ValueError('The aim.exe resource fixture does not match the pinned original')
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copytree(project / 'src/client', destination / 'src', dirs_exist_ok=True)
    shutil.copyfile(project / 'build/client.cmd', destination / 'build.cmd')
    dependencies = destination / 'deps'
    dependencies.mkdir(exist_ok=True)
    pe = pefile.PE(str(original))
    imports = {entry.dll.decode().lower(): [symbol.name.decode() for symbol in entry.imports]
               for entry in pe.DIRECTORY_ENTRY_IMPORT}
    fixtures = []
    for module in MODULES:
        path = originals / module
        dll = pefile.PE(str(path))
        exports = {symbol.name.decode(): symbol for symbol in dll.DIRECTORY_ENTRY_EXPORT.symbols if symbol.name}
        names = imports[module.lower()]
        rows = []
        for name in names:
            symbol = exports[name]
            section = dll.get_section_by_rva(symbol.address)
            data_export = section is not None and not section.Characteristics & 0x20000000
            rows.append('    ' + name + (' DATA' if data_export else ''))
        (dependencies / (Path(module).stem + '.def')).write_text(
            'LIBRARY ' + module + '\nEXPORTS\n' + '\n'.join(rows) + '\n', encoding='ascii')
        fixtures.append({'module': module, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'imports': names})
    resources, count = extract_resources(pe)
    (dependencies / 'aim.res').write_bytes(resources)
    aliases = ['#ifndef AIM_CLIENT_IMPORT_ALIASES_H', '#define AIM_CLIENT_IMPORT_ALIASES_H']
    # Preserve undecorated DLL export names while providing stdcall COFF names.
    for name, size in STDCALL_IMPORTS.items():
        aliases.append('#pragma comment(linker, "/alternatename:__imp__%s@%d=__imp__%s")' % (name, size, name))
    for name in imports['xpcs.dll']:
        aliases.append('#pragma comment(linker, "/alternatename:__imp_%s=__imp__%s")' % (name, name))
    aliases.append('#endif')
    (destination / 'src/import_aliases.h').write_text('\n'.join(aliases) + '\n', encoding='ascii')
    (destination / 'fixture-manifest.json').write_text(json.dumps({
        'original_sha256': ORIGINAL_SHA256, 'resource_count': count,
        'resource_sha256': hashlib.sha256(resources).hexdigest(), 'dependencies': fixtures,
        'code_extracted': False,
    }, indent=2) + '\n')
    print('Staged source, %d resources, and %d DLL import definitions in %s' % (count, len(MODULES), destination))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('originals', type=Path)
    parser.add_argument('destination', type=Path)
    arguments = parser.parse_args()
    prepare(arguments.originals, arguments.destination)
