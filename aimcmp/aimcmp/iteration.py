"""Small iteration reports derived from saved comparison evidence."""
import json


def validate_baseline(report, baseline):
    if baseline is None:
        return
    if (not isinstance(baseline, dict) or baseline.get('schema') != 1 or
            not isinstance(baseline.get('functions'), list) or
            not isinstance(baseline.get('metadata_diff'), dict) or
            not isinstance(baseline.get('analysis'), dict) or
            'code_sha256' not in baseline.get('rebuilt', {})):
        raise ValueError('Baseline must be a full aimcmp comparison report, not a compact report')
    if baseline.get('original', {}).get('sha256') != report['original']['sha256']:
        raise ValueError('Baseline compares a different original binary')


def preview(value, limit=6):
    if isinstance(value, list):
        if len(value) <= limit:
            return [preview(v, limit) for v in value]
        return {'count': len(value), 'sample': [preview(v, limit) for v in value[:limit]], 'truncated': True}
    if isinstance(value, dict):
        return {k: preview(v, limit) for k, v in value.items()}
    if isinstance(value, str) and len(value) > 300:
        return {'length': len(value), 'prefix': value[:300], 'truncated': True}
    return value


def instruction(row):
    if row is None:
        return None
    return {k: row[k] for k in ('address', 'offset', 'assembly', 'bytes', 'references')}


def differences(function):
    for row in function['diff']:
        a, b = row['original'], row['rebuilt']
        if row['kind'] != 'equal':
            yield {'kind': row['kind'], 'original': instruction(a), 'rebuilt': instruction(b)}
        elif a['bytes'] != b['bytes']:
            yield {'kind': 'address-bytes', 'original': instruction(a), 'rebuilt': instruction(b)}


def identity(function):
    # The original SHA is validated before comparing these stable coordinates.
    return function['original_address']


def rebuilt_signature(function):
    rows = [r['rebuilt'] for r in function['diff'] if r['rebuilt'] is not None]
    return (function['status'], function['rebuilt_address'], function['rebuilt_bytes'],
            function['errors'], function['coverage_percent'],
            [(r['offset'], r['bytes']) for r in rows])


def iteration_delta(report, baseline):
    if baseline is None:
        return None
    validate_baseline(report, baseline)
    before = {identity(f): f for f in baseline['functions']}
    after = {identity(f): f for f in report['functions']}
    changes = []
    for key in sorted(before.keys() | after.keys()):
        a, b = before.get(key), after.get(key)
        if a is None or b is None or rebuilt_signature(a) != rebuilt_signature(b):
            changes.append({'name': (b or a)['name'], 'original_address': key,
                            'mapping_id': (b or a).get('mapping_id'),
                            'before_status': a['status'] if a else None,
                            'after_status': b['status'] if b else None,
                            'coverage_delta': round(b['coverage_percent'] - a['coverage_percent'], 2) if a and b else None})
    keys = report['metadata_diff'].keys() | baseline['metadata_diff'].keys()
    # Compare rebuilt values, including a field that now equals the original.
    metadata = {k: {'before': preview(baseline['rebuilt'].get(k)), 'after': preview(report['rebuilt'].get(k))}
                for k in sorted(keys) if baseline['rebuilt'].get(k) != report['rebuilt'].get(k)}
    numeric = ('exact_functions', 'missing_functions', 'extra_functions', 'matched_instruction_bytes', 'normalized_coverage_percent')
    return {'baseline_rebuilt_sha256': baseline['rebuilt']['sha256'],
            'summary_delta': {k: round(report['summary'][k] - baseline['summary'][k], 2) for k in numeric},
            'changed_functions': changes, 'metadata_changes': metadata,
            'annotations_changed': report.get('mapping', {}).get('ledger_sha256') != baseline.get('mapping', {}).get('ledger_sha256'),
            'code_sections_changed': report['rebuilt']['code_sha256'] != baseline['rebuilt']['code_sha256'],
            'whole_file_changed': report['rebuilt']['sha256'] != baseline['rebuilt']['sha256']}


def compact_report(report, baseline=None, diff_limit=3, function_limit=20):
    if diff_limit < 1 or function_limit < 1:
        raise ValueError('Difference and function limits must be positive')
    validate_baseline(report, baseline)
    priority = {'analysis-error': 0, 'missing': 1, 'different': 2, 'normalized': 3, 'exact': 4}
    pending = sorted((f for f in report['functions'] if f['status'] != 'exact'),
                     key=lambda f: (priority[f['status']], f['original_address']))
    functions = []
    for f in pending[:function_limit]:
        changes = list(differences(f))
        functions.append({'name': f['name'], 'status': f['status'], 'match_reason': f['match_reason'],
                          'original_address': f['original_address'], 'rebuilt_address': f['rebuilt_address'],
                          'original_bytes': f['original_bytes'], 'rebuilt_bytes': f['rebuilt_bytes'],
                          'coverage_percent': f['coverage_percent'], 'errors': f['errors'],
                          'weak_references': preview(f['weak_references']),
                          'difference_count': len(changes), 'first_differences': changes[:diff_limit],
                          'differences_truncated': len(changes) > diff_limit})
    summary = report['summary']
    warnings = []
    if not summary['code_sections_exact'] and summary['exact_functions'] == summary['functions']:
        warnings.append('Analyzed functions match, but code-section payloads differ; inspect extra functions, gaps, or padding.')
    if any(f['errors'] for f in report['functions']):
        warnings.append('Analysis errors are present; coverage is not sufficient to certify a match.')
    if report['analysis']['original_engine'] != 'Binary Ninja' or report['analysis']['rebuilt_engine'] != 'Binary Ninja':
        warnings.append('Function boundaries use limited PE/MAP inference; no Binary Ninja HLIL is available.')
    if any(f['weak_references'] for f in pending):
        warnings.append('Normalized matches include weak data/address identities; review them before claiming equivalence.')
    if baseline and any(report['analysis'].get(k) != baseline['analysis'].get(k)
                        for k in ('original_engine', 'rebuilt_engine', 'original_version', 'rebuilt_version')):
        warnings.append('Analysis engines or versions changed since the baseline; function deltas may reflect analysis changes.')
    if summary['extra_functions']:
        warnings.append('Extra rebuilt functions are present.')
    records = report.get('mapping', {}).get('records', [])
    if any(r['confidence'] == 'hypothesis' for r in records if r['rebuilt_address'] is not None):
        warnings.append('Some explicit mapping identities are hypotheses; review their evidence before interpreting normalized scores.')
    return {'schema': 1, 'report_kind': 'aimcmp.iteration',
            'outcome': 'analysis-error' if any(f['errors'] for f in report['functions']) else 'exact-code' if summary['code_sections_exact'] else 'incomplete',
            'original': {k: report['original'][k] for k in ('path', 'sha256', 'code_sha256')},
            'rebuilt': {k: report['rebuilt'][k] for k in ('path', 'sha256', 'code_sha256')},
            'analysis': report['analysis'], 'summary': summary,
            'whole_file_status': 'exact' if summary['file_exact'] else 'timestamps-only' if summary.get('file_match_except_timestamps') else 'different',
            'pending_function_count': len(pending), 'functions': functions,
            'functions_truncated': len(pending) > function_limit,
            'extra_functions': preview([{'name': f['name'], 'address': f['address']} for f in report['extra_functions']]),
            'metadata_differences': {k: preview(v) for k, v in report['metadata_diff'].items()},
            'delta': iteration_delta(report, baseline), 'warnings': warnings,
            'mapping': {'ledger_sha256': report.get('mapping', {}).get('ledger_sha256'),
                        'record_count': len(records),
                        'unpaired_ids': [r['id'] for r in records if r['rebuilt_address'] is None]},
            'evidence_note': 'Exact code, normalized similarity, and whole-file equality are separate checks. Artifacts retain real timestamps.'}


def render_text(report):
    if report.get('outcome') == 'error':
        error = report['error']
        return f'ERROR at {error["stage"]}: {error["message"]}\nDetails: {error.get("log_path") or "failure.json"}'
    s = report['summary']
    lines = [f'{report.get("target", "comparison")}: {s["exact_functions"]}/{s["functions"]} functions exact; '
             f'{s["normalized_coverage_percent"]}% normalized instruction coverage',
             f'Code sections: {"exact" if s["code_sections_exact"] else "different"}; whole file: {report["whole_file_status"]}']
    for f in report['functions']:
        lines.append(f'{f["name"]} @ {f["original_address"]:#x}: {f["status"]}, {f["coverage_percent"]}% '
                     f'({f["original_bytes"]} -> {f["rebuilt_bytes"]} bytes)')
        for row in f['first_differences']:
            for side in ('original', 'rebuilt'):
                ins = row[side]
                if ins:
                    refs = ', '.join(r['identity'] for r in ins['references'])
                    lines.append(f'  {row["kind"]} {side} +{ins["offset"]:#x}: {ins["assembly"]} [{ins["bytes"]}]' + (f' [{refs}]' if refs else ''))
        for error in f['errors']:
            lines.append('  Analysis: '+error)
        if f['differences_truncated']:
            lines.append(f'  Showing {len(f["first_differences"])} of {f["difference_count"]} differences; full report retains all.')
    if report['functions_truncated']:
        lines.append(f'Showing {len(report["functions"])} of {report["pending_function_count"]} pending functions.')
    if report['metadata_differences']:
        lines.append('Metadata differences: '+', '.join(report['metadata_differences']))
    if report['delta'] is None:
        lines.append('Previous build: no baseline')
    else:
        delta = report['delta']
        lines.append(f'Previous build: {len(delta["changed_functions"])} changed functions; '
                     f'coverage {delta["summary_delta"]["normalized_coverage_percent"]:+g} percentage points; '
                     f'exact functions {delta["summary_delta"]["exact_functions"]:+g}')
        for change in delta['changed_functions']:
            lines.append(f'  {change["name"]}: {change["before_status"]} -> {change["after_status"]}')
        if delta['metadata_changes']:
            lines.append('Changed metadata since baseline: '+', '.join(delta['metadata_changes']))
        if delta.get('annotations_changed'):
            lines.append('Mapping annotations changed since baseline; normalized scores may reflect updated identities.')
    lines.extend('Warning: '+w for w in report['warnings'])
    if report.get('artifacts'):
        lines.append('Reports: '+report['artifacts']['full_json'])
    return '\n'.join(lines)


def format_report(report, output_format):
    return json.dumps(report, indent=2) if output_format == 'json' else render_text(report)
