"""Build, analyze, compare, and publish an iteration with stage diagnostics."""
from pathlib import Path
from time import monotonic
from copy import copy
import json
import traceback
from .build import build, BuildError
from .pe import Image, sha256
from .compare import compare
from .iteration import compact_report, render_text, validate_baseline
from .mappings import annotations, check_original


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2)+'\n', encoding='utf-8')


def iterate(project_path, target, args, analyze, write_report):
    root = project_path.parent
    output = Path(args.output_dir).resolve() if args.output_dir else root / 'reports/iterations' / target['name']
    output.mkdir(parents=True, exist_ok=True)
    latest = output / 'latest.json'
    failure_path = output / 'failure.json'
    stage = 'baseline'
    start = monotonic()
    try:
        baseline_path = Path(args.baseline).resolve() if args.baseline else latest
        baseline_text = baseline_path.read_text(encoding='utf-8') if baseline_path.exists() else None
        if args.baseline and baseline_text is None:
            raise ValueError('Requested baseline does not exist: '+str(baseline_path))
        baseline = json.loads(baseline_text) if baseline_text else None
        original = root / target['original']
        # Validate before remote writes, and before the old report is replaced.
        validate_baseline({'original': {'sha256': sha256(original)}}, baseline)
        stage = 'configuration'
        if args.diff_limit < 1 or args.function_limit < 1:
            raise ValueError('Difference and function limits must be positive')
        mapping = json.loads((root / target['mapping']).read_text()) if target.get('mapping') else {}
        if mapping.get('kind') == 'aimcmp.mapping':
            check_original(mapping, Image(original))
        build_info = None
        if not args.no_build:
            stage = 'build'
            build_info = build(project_path, target)
        stage = 'load-images'
        left = Image(original)
        right = Image(root / target['rebuilt'], root / target['map'] if target.get('map') else None)
        if left.pe.FILE_HEADER.Machine != 0x14c or right.pe.FILE_HEADER.Machine != 0x14c:
            raise ValueError('This version supports native x86 PE files only')
        stage = 'analyze-original'
        left_args, right_args = copy(args), copy(args)
        left_args.mapping_annotations = annotations(mapping, left, 'original')
        left_snapshot = analyze(left, left_args)
        stage = 'analyze-rebuilt'
        right_args.mapping_annotations = annotations(mapping, right, 'rebuilt')
        right_snapshot = analyze(right, right_args)
        stage = 'compare'
        report = compare(left, right, left_snapshot, right_snapshot, mapping)
        brief = compact_report(report, baseline, args.diff_limit, args.function_limit)
        brief['target'] = target['name']
        brief['baseline_path'] = str(baseline_path) if baseline else None
        brief['elapsed_seconds'] = round(monotonic()-start, 3)
        brief['build'] = {k: build_info[k] for k in ('elapsed_seconds', 'artifacts_dir', 'log_path')} if build_info else None
        brief['artifacts'] = {'full_json': str(latest), 'html': str(output/'latest.html'),
                              'compact_json': str(output/'iteration.json'), 'text': str(output/'iteration.txt')}
        stage = 'save-reports'
        # Render everything first; publish the full JSON baseline last.
        pending_json, pending_html = output/'pending.json', output/'pending.html'
        write_report(report, pending_json, pending_html)
        write_json(output/'pending-iteration.json', brief)
        (output/'pending-iteration.txt').write_text(render_text(brief)+'\n', encoding='utf-8')
        if baseline_text:
            (output/'previous.json').write_text(baseline_text, encoding='utf-8')
        pending_html.replace(output/'latest.html')
        (output/'pending-iteration.json').replace(output/'iteration.json')
        (output/'pending-iteration.txt').replace(output/'iteration.txt')
        pending_json.replace(latest)
        if brief['outcome'] == 'analysis-error':
            return brief, 1
        return brief, 2 if args.require_exact and not report['summary']['code_sections_exact'] else 0
    except Exception as error:
        if isinstance(error, BuildError):
            stage = error.stage
        log_path = output/'failure.log'
        log_path.write_text(traceback.format_exc(), encoding='utf-8')
        failure = {'schema': 1, 'report_kind': 'aimcmp.iteration', 'outcome': 'error', 'target': target['name'],
                   'elapsed_seconds': round(monotonic()-start, 3),
                   'error': {'stage': stage, 'message': str(error),
                             'log_path': error.log_path if isinstance(error, BuildError) else str(log_path)},
                   'failure_path': str(failure_path)}
        write_json(failure_path, failure)
        return failure, 1
