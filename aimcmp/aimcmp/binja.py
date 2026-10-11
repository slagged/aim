"""Analyze owned views through the existing Binary Ninja RPyC service.

Views opened here are closed here; the user's active UI view is never reused.
"""
from pathlib import Path
import json
import hashlib
import rpyc
from .pe import Image, sha256


def snapshot(path, cache_dir, host='127.0.0.1', port=18812, refresh=False, annotations=None):
    path = Path(path).resolve()
    digest = sha256(path)
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    conn = rpyc.connect(host, port, config={'sync_request_timeout': 120})
    try:
        bn = conn.root.import_module('binaryninja')
        version = str(bn.core_version())
        safe_version = ''.join(c if c.isalnum() else '_' for c in version)
        annotation_key = '-mapping-'+hashlib.sha256(json.dumps(annotations, sort_keys=True).encode()).hexdigest() if annotations else ''
        cache_path = cache_dir / f'{digest}-{safe_version}-v4{annotation_key}.json'
        if cache_path.exists() and not refresh:
            result = json.loads(cache_path.read_text())
            result['path'] = str(path)
            result['cached'] = True
            return result
        bv = bn.load(str(path))
        if bv is None:
            raise RuntimeError('Binary Ninja could not open ' + str(path))
        try:
            applied = []
            if annotations:
                from .mappings import apply
                applied = apply(bn, bv, annotations)
            result = {'schema': 1, 'engine': 'Binary Ninja', 'engine_version': version,
                      'sha256': digest, 'path': str(path), 'cached': False, 'functions': [],
                      'applied_mappings': applied}
            for function in sorted(list(bv.functions), key=lambda f: f.start):
                blocks = []
                for block in sorted(list(function.basic_blocks), key=lambda b: b.start):
                    blocks.append({'start': int(block.start), 'end': int(block.end),
                                   'edges': [{'target': int(e.target.start), 'type': str(e.type.name)}
                                             for e in list(block.outgoing_edges) if e.target]})
                try:
                    hlil = [str(line) for line in function.hlil.root.lines]
                    hlil_error = None
                except Exception as exc:
                    hlil = []; hlil_error = str(exc)
                result['functions'].append({'address': int(function.start), 'name': str(function.name),
                                            'type': str(function.type),
                                            'blocks': blocks, 'hlil': hlil, 'hlil_error': hlil_error})
            cache_path.write_text(json.dumps(result, indent=2), encoding='utf-8')
            return result
        finally:
            bv.file.close()
    finally:
        conn.close()


def pe_snapshot(image):
    """Explicit, limited fallback: boundaries inferred from exports and entry."""
    starts = dict(image.exports)
    starts[image.entry] = starts.get(image.entry, 'entry')
    starts.update({address: s['name'] for address, s in image.symbols.items() if s['function']})
    functions = []
    for start in sorted(starts):
        section = image.section(start)
        if not section or not section.Characteristics & 0x20000000:
            continue
        end = image.base + section.VirtualAddress + section.Misc_VirtualSize
        later = [a for a in starts if start < a < end]
        if later:
            end = min(later)
        functions.append({'address': start, 'name': starts[start], 'blocks': [{'start': start, 'end': end, 'edges': []}],
                          'hlil': [], 'hlil_error': None})
    return {'schema': 1, 'engine': 'PE boundaries (limited)', 'engine_version': '1',
            'sha256': sha256(image.path), 'path': str(image.path), 'cached': False, 'functions': functions}
