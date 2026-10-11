"""Reproducible flag sweeps with Binary Ninja snapshots and per-build reports."""
from pathlib import Path
import copy
import csv
import json
import re
from .build import build
from .pe import Image
from .binja import snapshot, pe_snapshot
from .compare import compare
from .mappings import annotations


def sweep(project_path, target, args, report_writer):
    root = Path(project_path).resolve().parent
    original = Image(root / target['original'])
    mapping = json.loads((root / target['mapping']).read_text()) if target.get('mapping') else {}
    def snap(image, side):
        data = annotations(mapping, image, side)
        return pe_snapshot(image) if args.analysis == 'pe' else snapshot(image.path, args.cache, args.bn_host, args.bn_port, args.refresh, data)
    original_snapshot = snap(original, 'original')
    destination = Path(args.output).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    records = []; names = set()
    variants = target.get('variants', [])
    if not variants:
        raise ValueError('Target has no configured variants')
    for index, variant in enumerate(variants):
        name = variant['name']
        if not re.fullmatch(r'[A-Za-z0-9_.-]+', name) or name in names or name in ('.', '..'):
            raise ValueError('Variant names must be unique simple directory names')
        names.add(name)
        relative = 'builds/matrix/' + target['name'] + '/' + name
        result = build(project_path, target, flags=variant['flags'], download_dir=relative, upload=index==0)
        rebuilt_path = root / relative / Path(target['rebuilt']).name
        map_path = root / relative / Path(target['map']).name if target.get('map') else None
        rebuilt = Image(rebuilt_path, map_path)
        report = compare(original, rebuilt, original_snapshot, snap(rebuilt, 'rebuilt'), mapping)
        report['variant'] = variant
        report_writer(report, destination / (name+'.json'), destination / (name+'.html'))
        record = {'variant': name, 'flags': variant['flags'], 'exact_functions': report['summary']['exact_functions'],
                  'coverage_percent': report['summary']['normalized_coverage_percent'],
                  'code_bytes': report['rebuilt']['code_bytes'], 'code_exact': report['summary']['code_sections_exact'],
                  'elapsed_seconds': result['elapsed_seconds']}
        records.append(record)
        print(f'{name}: {record["coverage_percent"]}% instruction coverage; {record["code_bytes"]} code bytes', flush=True)
    records.sort(key=lambda r: (-r['exact_functions'], -r['coverage_percent'], r['variant']))
    with (destination/'results.csv').open('w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=list(records[0])); writer.writeheader(); writer.writerows(records)
    (destination/'results.json').write_text(json.dumps(records, indent=2), encoding='utf-8')
    return records
