"""Persistent identities and annotations anchored to an immutable original."""
from pathlib import Path
import hashlib
import json
import re
from .pe import canonical, sha256


def number(value):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError('Addresses must be integers or hexadecimal strings')
    return int(value, 0) if isinstance(value, str) else int(value)


def validate(ledger):
    if not isinstance(ledger, dict):
        raise ValueError('Mapping ledger must be an object')
    if ledger.get('schema') != 1 or ledger.get('kind') != 'aimcmp.mapping':
        raise ValueError('Expected an aimcmp.mapping ledger with schema 1')
    original = ledger.get('original')
    if not isinstance(original, dict) or not isinstance(original.get('sha256'), str) or not re.fullmatch('[0-9a-f]{64}', original['sha256']):
        raise ValueError('Mapping original must contain a SHA-256')
    if not isinstance(ledger.get('records'), list):
        raise ValueError('Mapping records must be a list')
    if not isinstance(ledger.get('types', []), list):
        raise ValueError('Mapping types must be a list')
    for entry in ledger.get('types', []):
        if isinstance(entry, str):
            continue  # Legacy declarations have no verified provenance.
        if not isinstance(entry, dict) or not isinstance(entry.get('declaration'), str):
            raise ValueError('Mapping types require a C declaration')
        validate_evidence(entry)
    ids, addresses = set(), set()
    for row in ledger['records']:
        if not isinstance(row, dict):
            raise ValueError('Mapping records must be objects')
        for key in ('id', 'name'):
            if not isinstance(row.get(key), str) or not row[key].strip():
                raise ValueError('Mapping records require nonempty '+key)
        if row['id'] in ids:
            raise ValueError('Duplicate mapping ID: '+row['id'])
        ids.add(row['id'])
        if row.get('kind') not in ('function', 'global', 'import'):
            raise ValueError('Mapping kind must be function, global, or import')
        address = number(row['original'])
        if address in addresses:
            raise ValueError('Original addresses must be unique')
        addresses.add(address)
        if row.get('confidence') not in ('hypothesis', 'supported', 'verified'):
            raise ValueError('Confidence must be hypothesis, supported, or verified')
        if not isinstance(row.get('evidence'), list) or any(not isinstance(e, str) for e in row['evidence']):
            raise ValueError('Evidence must be a list of strings')
        if row.get('type') is not None and not isinstance(row['type'], str):
            raise ValueError('Type must be a C declaration string')
        if row.get('type_confidence') is not None:
            validate_evidence({'confidence': row['type_confidence'],
                               'evidence': row.get('type_evidence'),
                               'verification': row.get('type_verification')})
        if row.get('kind') == 'import' and not isinstance(row.get('import'), str):
            raise ValueError('Import annotations require the exact DLL!symbol identity')
        if row.get('physical_parameter_count') is not None and (type(row['physical_parameter_count']) is not int
                                                              or row['physical_parameter_count'] < 0):
            raise ValueError('Physical parameter count must be a nonnegative integer')
        selector = row.get('rebuilt')
        if selector is None:
            continue
        if not isinstance(selector, dict):
            raise ValueError('Rebuilt selector must be an object')
        if set(selector) == {'symbol'} and isinstance(selector['symbol'], str) and selector['symbol']:
            continue
        if set(selector) == {'address', 'sha256'} and isinstance(selector['sha256'], str) and re.fullmatch('[0-9a-f]{64}', selector['sha256']):
            number(selector['address'])
            continue
        raise ValueError('Rebuilt selector requires a symbol, or an address pinned to a SHA-256')
    return ledger


def validate_evidence(entry):
    if entry.get('confidence') not in ('hypothesis', 'supported', 'verified'):
        raise ValueError('Annotation requires a confidence tier')
    if not isinstance(entry.get('evidence'), list) or not entry['evidence'] or any(
            not isinstance(e, str) or not e.strip() for e in entry['evidence']):
        raise ValueError('Annotation requires nonempty evidence')
    if entry['confidence'] == 'verified' and entry.get('verification') not in ('byte-match', 'probe'):
        raise ValueError('Verified contracts require byte-match or probe verification')


def create(original):
    return {'schema': 1, 'kind': 'aimcmp.mapping',
            'original': {'path': str(Path(original).resolve()), 'sha256': sha256(original)},
            'types': [], 'records': []}


def load(path):
    return validate(json.loads(Path(path).read_text(encoding='utf-8')))


def save(path, ledger):
    validate(ledger)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_name(path.name+'.pending')
    pending.write_text(json.dumps(ledger, indent=2)+'\n', encoding='utf-8')
    pending.replace(path)


def check_original(ledger, image):
    validate(ledger)
    if ledger['original']['sha256'] != sha256(image.path):
        raise ValueError('Mapping ledger belongs to a different original binary')
    for row in ledger['records']:
        if not image.section(number(row['original'])):
            raise ValueError('Original mapping lies outside image sections: '+row['id'])
        if row['kind'] == 'import' and image.imports.get(number(row['original'])) != row['import']:
            raise ValueError('Import identity does not match original: '+row['id'])


def symbols(image, snapshot=None):
    result = {}
    def add(name, address, kind):
        result.setdefault((canonical(name), kind), set()).add(address)
    for address, name in image.exports.items():
        section = image.section(address)
        add(name, address, 'function' if section and section.Characteristics & 0x20000000 else 'global')
    for address, row in image.symbols.items():
        add(row['name'], address, 'function' if row['function'] else 'global')
    for row in (snapshot or {}).get('functions', []):
        add(row['name'], row['address'], 'function')
    add('entry', image.entry, 'function')
    return result


def select(row, image, snapshot=None):
    selector = row.get('rebuilt')
    if selector is None:
        return None
    if 'address' in selector:
        if selector['sha256'] != sha256(image.path):
            raise ValueError('Stale rebuilt address for '+row['id']+'; use a symbol or update its SHA-256 pin')
        address = number(selector['address'])
    else:
        candidates = symbols(image, snapshot).get((canonical(selector['symbol']), row['kind']), set())
        if len(candidates) != 1:
            raise ValueError('Rebuilt symbol is missing or ambiguous for '+row['id']+': '+selector['symbol'])
        address = next(iter(candidates))
    if not image.section(address):
        raise ValueError('Rebuilt mapping lies outside image sections: '+row['id'])
    return address


def annotations(ledger, image, side, layer='all'):
    """Resolve annotations before analysis using MAP/export symbols only."""
    if not ledger or ledger.get('kind') != 'aimcmp.mapping':
        return None
    validate(ledger)
    if layer not in ('all', 'verified'):
        raise ValueError('Annotation layer must be all or verified')
    if side == 'original':
        check_original(ledger, image)
    rows = []
    used = set()
    for row in ledger['records']:
        if row['kind'] == 'import' and side != 'original':
            continue
        address = number(row['original']) if side == 'original' else select(row, image)
        if address is not None:
            if address in used:
                raise ValueError('Annotation addresses must be one-to-one')
            used.add(address)
            item = dict(row, address=address)
            # A matched body does not verify every declaration used to build it.
            if layer == 'verified':
                if row.get('type_confidence') != 'verified':
                    item.pop('type', None)
                if row['kind'] == 'import' and not item.get('type'):
                    continue  # The PE already supplies its exact import symbol.
                if row['confidence'] != 'verified' and not item.get('type'):
                    continue
            rows.append(item)
    passes = []
    for tier in ('verified', 'hypothesis'):
        declarations = []
        for entry in ledger.get('types', []):
            confidence = entry.get('confidence') if isinstance(entry, dict) else 'hypothesis'
            if (confidence == 'verified') == (tier == 'verified'):
                declarations.append(entry['declaration'] if isinstance(entry, dict) else entry)
        if tier == 'verified' or layer == 'all':
            passes.append({'layer': tier, 'types': declarations})
    return {'types': [], 'type_layers': passes, 'records': rows, 'layer': layer,
            'original_sha256': ledger['original']['sha256'] if side == 'original' else None}


def resolve(mapping, left, right, left_snapshot, right_snapshot):
    if mapping.get('kind') != 'aimcmp.mapping':
        return mapping
    check_original(mapping, left)
    result = {'functions': [], 'globals': [], 'records': [],
              'ledger_sha256': hashlib.sha256(json.dumps(mapping, sort_keys=True).encode()).hexdigest()}
    used = set()
    for row in mapping['records']:
        if row['kind'] == 'import':
            continue
        address = select(row, right, right_snapshot)
        resolved = dict(row, original_address=number(row['original']), rebuilt_address=address)
        result['records'].append(resolved)
        if address is None:
            continue
        if address in used:
            raise ValueError('Rebuilt mapping addresses must be one-to-one')
        used.add(address)
        result['functions' if row['kind'] == 'function' else 'globals'].append(
            {'name': row['name'], 'id': row['id'], 'original': number(row['original']), 'rebuilt': address})
    return result


def apply(bn, bv, data):
    """Only called for workbench-owned views; errors abort annotation analysis."""
    for declarations in [data.get('types', [])] + [p['types'] for p in data.get('type_layers', [])]:
        if not declarations:
            continue
        parsed = bv.parse_types_from_string('\n'.join(declarations))
        for name in list(parsed.types):
            bv.define_user_type(str(name), parsed.types[name])
    applied = []
    for row in data['records']:
        address = row['address']
        try:
            observed_type = None
            if row['kind'] == 'function':
                function = bv.get_function_at(address)
                if function is None:
                    raise ValueError('Not an analyzed function start')
                bv.define_user_symbol(bn.Symbol(bn.SymbolType.FunctionSymbol, address, row['name']))
                if row.get('type'):
                    function.set_user_type(bv.parse_type_string(row['type'])[0])
                observed_type = str(function.type)
            elif row.get('type'):
                if row['kind'] == 'import':
                    symbol = bv.get_symbol_at(address)
                    if symbol is None or str(symbol.raw_name) != row['import'].split('!', 1)[1]:
                        raise ValueError('BN import symbol identity mismatch')
                bv.define_user_data_var(address, bv.parse_type_string(row['type'])[0], row['name'])
                observed_type = str(bv.get_data_var_at(address).type)
            else:
                bv.define_user_symbol(bn.Symbol(bn.SymbolType.DataSymbol, address, row['name']))
            applied.append({'id': row['id'], 'address': address, 'name': row['name'],
                            'type': row.get('type'), 'confidence': row['confidence'],
                            'type_confidence': row.get('type_confidence'),
                            'type_evidence': row.get('type_evidence', [])})
            applied[-1]['observed_type'] = observed_type
        except Exception as exc:
            raise ValueError('Cannot apply mapping '+row['id']+': '+str(exc)) from exc
    bv.update_analysis_and_wait()
    # Function type changes become visible after analysis completes.
    for row, record in zip(data['records'], applied):
        if row['kind'] == 'function':
            record['observed_type'] = str(bv.get_function_at(row['address']).type)
        elif row.get('type'):
            record['observed_type'] = str(bv.get_data_var_at(row['address']).type)
    return applied
