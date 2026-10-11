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
    snap.add_argument('--annotation-layer', choices=['all', 'verified'], default='all')
    analysis_options(snap)
    honing = sub.add_parser('hone', help='Show first divergence, allocation classification, liveness and experiment history')
    honing.add_argument('project'); honing.add_argument('name'); honing.add_argument('function')
    honing.add_argument('--ledger'); honing.add_argument('--bindings'); honing.add_argument('--json'); honing.add_argument('--full', action='store_true')
    analysis_options(honing)
    log = sub.add_parser('hone-log', help='Deduplicate attempts and record explicit plateau reasons')
    log.add_argument('action', choices=['check', 'add', 'stop'])
    log.add_argument('ledger'); log.add_argument('function'); log.add_argument('--original-sha256', required=True)
    log.add_argument('--preprocessed'); log.add_argument('--toolchain'); log.add_argument('--flags')
    log.add_argument('--hypothesis'); log.add_argument('--family')
    log.add_argument('--outcome', choices=['assessed', 'build-failed', 'untested'])
    log.add_argument('--report'); log.add_argument('--reason'); log.add_argument('--classification')
    log.add_argument('--tried-family', action='append')
    study_parser = sub.add_parser('annotation-study', help='Compare fresh baseline, verified, and hypothesis BN views')
    study_parser.add_argument('binary'); study_parser.add_argument('mapping')
    study_parser.add_argument('--output', required=True)
    study_parser.add_argument('--function', action='append', required=True, type=lambda s: int(s, 0))
    study_parser.add_argument('--bn-host', default='127.0.0.1')
    study_parser.add_argument('--bn-port', default=18812, type=int)
    cmp = sub.add_parser('compare', help='Compare two binaries directly')
    cmp.add_argument('original'); cmp.add_argument('rebuilt'); cmp.add_argument('--map'); cmp.add_argument('--mapping')
    report_options(cmp)
    project_cmp = sub.add_parser('target', help='Compare a configured project target')
    project_cmp.add_argument('project'); project_cmp.add_argument('name'); project_cmp.add_argument('--build', action='store_true')
    report_options(project_cmp)
    builder = sub.add_parser('build', help='Upload sources and build a configured target on the SSH VM')
    builder.add_argument('project'); builder.add_argument('name')
    coff = sub.add_parser('coff-compare', help='Compare selected COFF contributions with explicit symbol bindings')
    coff.add_argument('original'); coff.add_argument('object_dir'); coff.add_argument('manifest')
    coff.add_argument('--json')
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
    objects = sub.add_parser('objects', help='Extract byte-verified object and ABI observations from a BN export')
    objects.add_argument('export', type=Path)
    objects.add_argument('original', type=Path)
    objects.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'hone':
            from .honing import hone, compact
            path, target = load_target(args.project, args.name)
            report = hone(path, target, args.function, args, analyze)
            write_report(report, args.json, None)
            print(json.dumps(report, indent=2) if args.full else compact(report))
            return 0
        if args.command == 'hone-log':
            from .honing_ledger import identity, check, record, plateau
            if args.action == 'stop':
                result = plateau(args.ledger, args.function, args.original_sha256, args.reason or '',
                                 args.classification or '', args.tried_family or [])
            else:
                if not args.preprocessed or not args.toolchain or args.flags is None:
                    raise ValueError('Attempt requires --preprocessed, --toolchain and --flags')
                item = identity(args.function, args.original_sha256, args.flags,
                                json.loads(Path(args.toolchain).read_text(encoding='utf-8')),
                                Path(args.preprocessed).read_text(encoding='utf-8'))
                if args.action == 'check':
                    previous = check(args.ledger, item)
                    result = {'duplicate': previous is not None, 'previous': previous, 'identity': item}
                else:
                    report = json.loads(Path(args.report).read_text(encoding='utf-8')) if args.report else None
                    result = record(args.ledger, item, args.hypothesis or '', args.family, args.outcome, report)
            print(json.dumps(result, indent=2))
            return 0
        if args.command == 'annotation-study':
            from .annotation_study import study
            report = study(args.binary, args.mapping, args.output, sorted(set(args.function)), args.bn_host, args.bn_port)
            print(json.dumps(report['functions'], indent=2))
            return int(any(f['errors'] for f in report['functions']))
        if args.command == 'objects':
            from .object_analysis import main as object_main
            return object_main([str(args.export), str(args.original), '--output', str(args.output)])
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
                args.mapping_annotations = annotations(ledger, image, args.side, args.annotation_layer)
            result = analyze(image, args)
            path = Path(args.json); path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(result, indent=2), encoding='utf-8')
            print(f'{len(result["functions"])} functions; {result["engine"]} {result["engine_version"]}'); return 0
        if args.command == 'coff-compare':
            from .coff import compare_contributions
            manifest = json.loads(Path(args.manifest).read_text())
            result = compare_contributions(args.original, args.object_dir, manifest)
            write_report(result, args.json, None)
            print(json.dumps({'exact': result['exact'], 'functions': [
                {'id': row['id'], 'exact': row['exact'], 'size': row['original_size']}
                for row in result['functions']]}))
            return 0 if result['exact'] else 2
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
