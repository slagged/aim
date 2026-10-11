"""Reproduce independent baseline, verified, and hypothesis BN analyses."""
from pathlib import Path
import hashlib
import json
import rpyc
from .pe import Image, sha256
from .mappings import load, check_original, annotations, apply, number


def study(binary, ledger_path, output, addresses, host='127.0.0.1', port=18812):
    binary, output = Path(binary).resolve(), Path(output)
    image, ledger = Image(binary), load(ledger_path)
    check_original(ledger, image)
    for row in ledger['records']:
        if row['kind'] == 'import' and row.get('type') and row.get('physical_parameter_count') is None:
            raise ValueError('Study import requires physical_parameter_count: '+row['id'])
    if binary.suffix.lower() == '.bndb':
        raise ValueError('Study input must be an original PE, never a manually edited database')
    worker = Path(__file__).with_name('annotation_metrics.py').read_text(encoding='utf-8')
    output.mkdir(parents=True, exist_ok=True)
    status_path = output / 'status.json'
    status_path.write_text(json.dumps({'status': 'running'})+'\n', encoding='utf-8')
    conn = None
    try:
        conn = rpyc.connect(host, port, config={'sync_request_timeout': 120})
        builtins = conn.root.import_module('builtins')
        namespace = builtins.dict()
        builtins.exec(worker, namespace)
        bn = conn.root.import_module('binaryninja')
        digest = sha256(binary)
        # Hash the service's file as well: a path on another host is not identity.
        remote_hash = lambda: str(conn.root.import_module('hashlib').sha256(
            conn.root.import_module('pathlib').Path(str(binary)).read_bytes()).hexdigest())
        if remote_hash() != digest:
            raise ValueError('BN service file differs from the pinned original')
        definitions = json.loads(str(conn.root.import_module('json').dumps(namespace['METRICS'])))
        protocol = {'schema': 1, 'kind': 'aimcmp.annotation-study', 'original_sha256': digest,
                    'ledger_sha256': sha256(ledger_path), 'engine_version': str(bn.core_version()),
                    'collector_sha256': hashlib.sha256(worker.encode()).hexdigest(),
                    'annotation_engine_sha256': sha256(Path(__file__).with_name('mappings.py')),
                    'bn_settings': json.loads(str(bn.Settings().serialize_settings())),
                    'addresses': addresses, 'metrics': definitions,
                    'layers': ['baseline', 'verified', 'hypotheses'],
                    'method': 'Fresh BN load of the hash-verified PE for every layer; no analysis cache or saved BN database.',
                    'interpretation': 'Per-function deltas are diagnostics. Lower counts do not establish correctness.'}
        # Freeze the protocol on disk before collecting any annotated output.
        (output / 'protocol.json').write_text(json.dumps(protocol, indent=2)+'\n', encoding='utf-8')
        (output / 'ledger.json').write_bytes(Path(ledger_path).read_bytes())
        expected_counts = {str(number(row['original'])): row['physical_parameter_count']
                           for row in ledger['records'] if row['kind'] == 'import' and row.get('type')}
        results = {}
        for layer in protocol['layers']:
            if sha256(binary) != digest or remote_hash() != digest:
                raise ValueError('Original changed during annotation study')
            view = bn.load(str(binary))
            if view is None:
                raise RuntimeError('BN failed to open original')
            try:
                applied = []
                if layer != 'baseline':
                    applied += apply(bn, view, annotations(ledger, image, 'original', 'verified'))
                if layer == 'hypotheses':
                    applied += apply(bn, view, annotations(ledger, image, 'original', 'all'))
                # Use ledger prototypes as the common count reference for all layers.
                if layer != 'baseline':
                    for row in ledger['records']:
                        if row['kind'] != 'import' or not row.get('type'):
                            continue
                        signature = view.parse_type_string(row['type'])[0].target
                        if len(signature.parameters) != row['physical_parameter_count']:
                            raise ValueError('Physical parameter count differs from declaration: '+row['id'])
                data = json.loads(str(namespace['collect'](view, json.dumps({
                    'addresses': addresses, 'expected_counts': expected_counts,
                    'import_addresses': list(image.imports)}))))
                data['applied_annotations'] = applied
                results[layer] = data
                (output / (layer+'.json')).write_text(json.dumps(data, indent=2)+'\n', encoding='utf-8')
            finally:
                view.file.close()
        if sha256(binary) != digest or remote_hash() != digest:
            raise ValueError('Original changed during annotation study')
        comparisons = []
        baseline = {r['address']: r for r in results['baseline']['functions']}
        verified = {r['address']: r for r in results['verified']['functions']}
        for row in results['hypotheses']['functions']:
            address = row['address']
            base, known = baseline[address], verified[address]
            def delta(left, right):
                if left['metrics'] is None or right['metrics'] is None:
                    return None
                return {key: right['metrics'][key]-left['metrics'][key] for key in definitions}
            comparisons.append({'address': address, 'name': row.get('name'),
                                'baseline': base['metrics'], 'verified': known['metrics'],
                                'hypotheses': row['metrics'],
                                'verified_minus_baseline': delta(base, known),
                                'hypotheses_minus_verified': delta(known, row),
                                'errors': {name: f['error'] for name in results
                                           for f in results[name]['functions']
                                           if f['address'] == address and f['error']}})
        report = dict(protocol, functions=comparisons)
        (output / 'report.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
        status_path.write_text(json.dumps({'status': 'analysis-error' if any(f['errors'] for f in comparisons)
                                          else 'complete', 'original_sha256': digest})+'\n', encoding='utf-8')
        return report
    except Exception as exc:
        status_path.write_text(json.dumps({'status': 'failed', 'error': str(exc)})+'\n', encoding='utf-8')
        raise
    finally:
        if conn is not None:
            conn.close()
