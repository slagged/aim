"""CLI for named checkpoints; saved comparisons need no VM or BN service."""
import json
from .checkpoints import save_checkpoint, compare_checkpoints, restore_checkpoint, list_checkpoints, location
from .iteration import format_report


def add_parser(sub, analysis_options):
    parser = sub.add_parser('checkpoint', help='Save, compare, list, and restore named experiments')
    commands = parser.add_subparsers(dest='checkpoint_command', required=True)
    for command in ('save','list','compare','restore'):
        p = commands.add_parser(command)
        p.add_argument('project'); p.add_argument('name', help='Configured target')
        if command == 'compare':
            p.add_argument('before'); p.add_argument('after')
            p.add_argument('--format', choices=['text','json'], default='text')
        elif command in ('save','restore'):
            p.add_argument('checkpoint_name')
        if command == 'save':
            analysis_options(p)
            p.add_argument('--flags', help='Override the configured flags for this attempt and its restore recipe')
            p.add_argument('--require-exact', action='store_true')


def execute(args, load_target, analyze, writer):
    path, target = load_target(args.project, args.name)
    if args.checkpoint_command == 'save':
        result, status = save_checkpoint(path, target, args.checkpoint_name, args, analyze, writer)
        print(json.dumps(result, indent=2))
        return status
    if args.checkpoint_command == 'list':
        print(json.dumps(list_checkpoints(path, target), indent=2))
    elif args.checkpoint_command == 'restore':
        print(json.dumps(restore_checkpoint(path, target, args.checkpoint_name), indent=2))
    else:
        result = compare_checkpoints(location(path,target,args.before), location(path,target,args.after))
        print(format_report(result, args.format))
        if args.format == 'text':
            delta = result['checkpoint_delta']
            print('Sources/mappings changed: '+(', '.join(delta['changed_source_or_mapping_paths']) or 'none'))
            print('Configured flags: '+repr(delta['configured_flags']['before'])+' -> '+repr(delta['configured_flags']['after']))
            print('Toolchain inventory changed: '+str(delta['toolchain_changed']))
    return 0
