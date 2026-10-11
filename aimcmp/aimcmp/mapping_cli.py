"""Small inspectable commands for the persistent mapping ledger."""
from pathlib import Path
import json
from .mappings import create, load, save, number, resolve
from .pe import Image, sha256
from .binja import pe_snapshot


def add_parser(sub):
    parser = sub.add_parser('mapping', help='Maintain persistent function/data identities and types')
    commands = parser.add_subparsers(dest='mapping_command', required=True)
    init = commands.add_parser('init', help='Create a ledger anchored to the original SHA-256')
    init.add_argument('ledger'); init.add_argument('original')
    show = commands.add_parser('show', help='Print the complete ledger')
    show.add_argument('ledger')
    put = commands.add_parser('set', help='Create/update one stable identity; retain omitted fields')
    put.add_argument('ledger'); put.add_argument('id')
    put.add_argument('--kind', choices=['function', 'global'])
    put.add_argument('--original'); put.add_argument('--name'); put.add_argument('--type')
    put.add_argument('--confidence', choices=['hypothesis', 'supported', 'verified'])
    put.add_argument('--evidence', action='append', help='Append an evidence note; repeat as needed')
    select = put.add_mutually_exclusive_group()
    select.add_argument('--rebuilt-symbol')
    select.add_argument('--rebuilt-address')
    select.add_argument('--unpaired', action='store_true')
    put.add_argument('--rebuilt-binary', help='Required to pin an explicit rebuilt address to its SHA-256')
    types = commands.add_parser('type', help='Append a shared C type declaration')
    types.add_argument('ledger'); types.add_argument('declaration')
    resolved = commands.add_parser('resolve', help='Resolve MAP/export selectors and validate analyzed PE starts')
    resolved.add_argument('ledger'); resolved.add_argument('original'); resolved.add_argument('rebuilt')
    resolved.add_argument('--map')


def execute(args):
    path = Path(args.ledger)
    if args.mapping_command == 'init':
        if path.exists():
            raise ValueError('Mapping ledger already exists: '+str(path))
        ledger = create(args.original)
        save(path, ledger)
    else:
        ledger = load(path)
    if args.mapping_command == 'set':
        row = next((r for r in ledger['records'] if r['id'] == args.id), None)
        if row is None:
            if not all((args.kind, args.original, args.name)):
                raise ValueError('New records require --kind, --original, and --name')
            row = {'id': args.id, 'kind': args.kind, 'original': hex(number(args.original)),
                   'name': args.name, 'type': None, 'confidence': 'hypothesis', 'evidence': [], 'rebuilt': None}
            ledger['records'].append(row)
        for key in ('kind', 'name', 'type', 'confidence'):
            value = getattr(args, key)
            if value is not None:
                row[key] = value
        if args.original:
            row['original'] = hex(number(args.original))
        for evidence in args.evidence or []:
            if evidence not in row['evidence']:
                row['evidence'].append(evidence)
        if args.rebuilt_symbol:
            row['rebuilt'] = {'symbol': args.rebuilt_symbol}
        elif args.rebuilt_address:
            if not args.rebuilt_binary:
                raise ValueError('--rebuilt-address requires --rebuilt-binary to prevent stale addresses')
            row['rebuilt'] = {'address': hex(number(args.rebuilt_address)), 'sha256': sha256(args.rebuilt_binary)}
        elif args.unpaired:
            row['rebuilt'] = None
        save(path, ledger)
    elif args.mapping_command == 'type':
        if args.declaration not in ledger['types']:
            ledger['types'].append(args.declaration)
        save(path, ledger)
    elif args.mapping_command == 'resolve':
        left, right = Image(args.original), Image(args.rebuilt, args.map)
        result = resolve(ledger, left, right, pe_snapshot(left), pe_snapshot(right))
        # Also enforce the existing function-start and one-to-one checks.
        from .compare import pair_functions
        pair_functions(left, right, pe_snapshot(left), pe_snapshot(right), result)
        print(json.dumps(result, indent=2))
        return 0
    print(json.dumps(ledger, indent=2))
    return 0
