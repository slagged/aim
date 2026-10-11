"""CLI entry point; reports are static HTML with no external dependencies."""
from pathlib import Path
import argparse
import json
import sys
from .pe import Image
from .binja import snapshot, pe_snapshot
from .compare import compare
from .build import build
from .iteration import compact_report, format_report
from .mappings import annotations
from .config import load_project


def write_report(report, json_path, html_path):
    if json_path:
        path = Path(json_path); path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2), encoding='utf-8')
    if html_path:
        path = Path(html_path); path.parent.mkdir(parents=True, exist_ok=True)
        template = Path(__file__).with_name('report.html').read_text(encoding='utf-8')
        # Embedded binary strings and symbol names cannot break out of the data
        # script. The frontend only renders them through textContent.
        data = json.dumps(report, ensure_ascii=True).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
        path.write_text(template.replace('__REPORT_DATA__', data), encoding='utf-8')


def analyze(image, args):
    if args.analysis == 'pe':
        return pe_snapshot(image)
    return snapshot(image.path, args.cache, args.bn_host, args.bn_port, args.refresh,
                    getattr(args, 'mapping_annotations', None))


def load_target(path, name):
    path = Path(path).resolve()
    project = load_project(path)
    matches = [t for t in project['targets'] if t['name'] == name]
    if len(matches) != 1:
        raise ValueError('Unknown or duplicate target: ' + name)
    return path, matches[0]


def run_compare(original, rebuilt, map_path, mapping, args):
    from copy import copy
    left, right = Image(original), Image(rebuilt, map_path)
    if left.pe.FILE_HEADER.Machine != 0x14c or right.pe.FILE_HEADER.Machine != 0x14c:
        raise ValueError('This version supports native x86 PE files only')
    left_args, right_args = copy(args), copy(args)
    left_args.mapping_annotations = annotations(mapping, left, 'original')
    right_args.mapping_annotations = annotations(mapping, right, 'rebuilt')
    report = compare(left, right, analyze(left, left_args), analyze(right, right_args), mapping)
    write_report(report, args.json, args.html)
    print(json.dumps(report['summary'], indent=2))
    if args.require_exact and not report['summary']['code_sections_exact']:
        return 2
    return 0


def analysis_options(parser):
    parser.add_argument('--analysis', choices=['binja', 'pe'], default='binja')
    parser.add_argument('--bn-host', default='127.0.0.1')
    parser.add_argument('--bn-port', type=int, default=18812)
    parser.add_argument('--cache', default='.aimcmp-cache')
    parser.add_argument('--refresh', action='store_true')


def report_options(parser):
    analysis_options(parser)
    parser.add_argument('--json')
    parser.add_argument('--html')
    parser.add_argument('--require-exact', action='store_true', help='Exit 2 unless complete code sections match raw bytes')


def positive_integer(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError('must be a positive integer')
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(prog='aimcmp', description='Binary Ninja assisted matching-decompilation workbench')
    sub = parser.add_subparsers(dest='command', required=True)
    inv = sub.add_parser('inspect', help='Inspect PE and toolchain metadata')
    inv.add_argument('binary'); inv.add_argument('--json')
    snap = sub.add_parser('snapshot', help='Cache function boundaries, CFGs and HLIL from Binary Ninja')
    snap.add_argument('binary'); snap.add_argument('--map'); snap.add_argument('--json', required=True)
    snap.add_argument('--mapping'); snap.add_argument('--side', choices=['original', 'rebuilt'], default='original')
    analysis_options(snap)
    cmp = sub.add_parser('compare', help='Compare two binaries directly')
    cmp.add_argument('original'); cmp.add_argument('rebuilt'); cmp.add_argument('--map'); cmp.add_argument('--mapping')
    report_options(cmp)
    project_cmp = sub.add_parser('target', help='Compare a configured project target')
    project_cmp.add_argument('project'); project_cmp.add_argument('name'); project_cmp.add_argument('--build', action='store_true')
    report_options(project_cmp)
    builder = sub.add_parser('build', help='Upload sources and build a configured target on the SSH VM')
    builder.add_argument('project'); builder.add_argument('name')
    matrix = sub.add_parser('matrix', help='Build configured flag variants and rank comparison reports')
    matrix.add_argument('project'); matrix.add_argument('name'); matrix.add_argument('--output', required=True)
    analysis_options(matrix)
    brief = sub.add_parser('brief', help='Print a compact iteration report from saved comparison JSON')
    brief.add_argument('report'); brief.add_argument('--baseline'); brief.add_argument('--output')
    brief.add_argument('--format', choices=['text', 'json'], default='text')
    brief.add_argument('--diff-limit', type=positive_integer, default=3)
    brief.add_argument('--function-limit', type=positive_integer, default=20)
    iteration = sub.add_parser('iterate', help='Build, analyze, compare, and report changes since the previous build')
    iteration.add_argument('project'); iteration.add_argument('name')
    iteration.add_argument('--output-dir'); iteration.add_argument('--baseline')
    iteration.add_argument('--no-build', action='store_true', help='Assess existing artifacts without building')
    iteration.add_argument('--format', choices=['text', 'json'], default='text')
    iteration.add_argument('--diff-limit', type=positive_integer, default=3)
    iteration.add_argument('--function-limit', type=positive_integer, default=20)
    iteration.add_argument('--require-exact', action='store_true')
    analysis_options(iteration)
    from .mapping_cli import add_parser, execute
    add_parser(sub)
    from .checkpoint_cli import add_parser as checkpoint_parser, execute as checkpoint_execute
    checkpoint_parser(sub, analysis_options)
    from .query import add_parser as query_parser, execute as query_execute
    query_parser(sub, analysis_options, positive_integer)
    from .variants import add_parser as variants_parser, execute as variants_execute
    variants_parser(sub, analysis_options)
    args = parser.parse_args(argv)
    try:
        if args.command=='variants':
            return variants_execute(args,load_target,analyze,write_report)
        if args.command in ('query','query-target'):
            return query_execute(args, load_target)
        if args.command == 'checkpoint':
            return checkpoint_execute(args, load_target, analyze, write_report)
        if args.command == 'mapping':
            return execute(args)
        if args.command == 'brief':
            report = json.loads(Path(args.report).read_text(encoding='utf-8'))
            baseline = json.loads(Path(args.baseline).read_text(encoding='utf-8')) if args.baseline else None
            result = compact_report(report, baseline, args.diff_limit, args.function_limit)
            output = format_report(result, args.format)
            if args.output:
                path = Path(args.output); path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(output+'\n', encoding='utf-8')
            print(output)
            return 1 if result['outcome'] == 'analysis-error' else 0
        if args.command == 'iterate':
            from .workflow import iterate
            path, target = load_target(args.project, args.name)
            result, status = iterate(path, target, args, analyze, write_report)
            print(format_report(result, args.format))
            return status
        if args.command == 'inspect':
            metadata = Image(args.binary).metadata()
            if args.json:
                Path(args.json).write_text(json.dumps(metadata, indent=2), encoding='utf-8')
            print(json.dumps(metadata, indent=2)); return 0
        if args.command == 'snapshot':
            image = Image(args.binary, args.map)
            if args.mapping:
                ledger = json.loads(Path(args.mapping).read_text(encoding='utf-8'))
                args.mapping_annotations = annotations(ledger, image, args.side)
            result = analyze(image, args)
            path = Path(args.json); path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(result, indent=2), encoding='utf-8')
            print(f'{len(result["functions"])} functions; {result["engine"]} {result["engine_version"]}'); return 0
        if args.command == 'build':
            path, target = load_target(args.project, args.name)
            print(build(path, target)['log']); return 0
        if args.command == 'matrix':
            from .matrix import sweep
            path, target = load_target(args.project, args.name)
            records = sweep(path, target, args, write_report)
            print('Best variant: '+records[0]['variant']); return 0
        if args.command == 'target':
            path, target = load_target(args.project, args.name)
            if args.build:
                print(build(path, target)['log'])
            root = path.parent
            mapping = json.loads((root / target['mapping']).read_text()) if target.get('mapping') else {}
            return run_compare(root / target['original'], root / target['rebuilt'],
                               root / target['map'] if target.get('map') else None, mapping, args)
        mapping = json.loads(Path(args.mapping).read_text()) if args.mapping else {}
        return run_compare(args.original, args.rebuilt, args.map, mapping, args)
    except (OSError, ValueError, RuntimeError, KeyError) as exc:
        print('aimcmp: ' + str(exc), file=sys.stderr); return 1


if __name__ == '__main__':
    raise SystemExit(main())
