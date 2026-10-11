"""Named source/artifact snapshots, verified comparisons, and recoverable restore."""
from pathlib import Path
from datetime import datetime, timezone
import copy
import json
import os
import re
import uuid
import pefile
from .pe import sha256
from .build import run
from .iteration import compact_report
from .workflow import iterate
from .config import load_project, portable_target


def now():
    return datetime.now(timezone.utc).isoformat()


def simple_name(value):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,95}', value):
        raise ValueError('Checkpoint and target names must be simple names of at most 96 characters')
    return value


def location(project_path, target, name):
    root = Path(project_path).resolve().parent
    return root/'checkpoints'/simple_name(target['name'])/simple_name(name)


def inside(root, path):
    root = Path(root).resolve()
    path = Path(path)
    path = (root/path).resolve() if not path.is_absolute() else path.resolve()
    if not path.is_relative_to(root) or path == root:
        raise ValueError('Checkpoint file path must stay inside '+str(root))
    return path


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_name(path.name+'.pending-'+uuid.uuid4().hex)
    pending.write_text(json.dumps(value, indent=2)+'\n', encoding='utf-8')
    pending.replace(path)


def copy_file(source, destination):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    data = Path(source).read_bytes()
    pending = destination.with_name(destination.name+'.pending-'+uuid.uuid4().hex)
    pending.write_bytes(data)
    pending.replace(destination)


def inventory(folder):
    return [{'stored': p.relative_to(folder).as_posix(), 'sha256': sha256(p), 'size': p.stat().st_size}
            for p in sorted(folder.rglob('*')) if p.is_file() and p not in (folder/'checkpoint.json',folder/'checkpoint.sha256')]


def seal(folder, manifest):
    manifest['files'] = inventory(folder)
    write_json(folder/'checkpoint.json', manifest)
    (folder/'checkpoint.sha256').write_text(sha256(folder/'checkpoint.json')+'\n', encoding='ascii')


def begin(project_path, target, name, kind):
    folder = location(project_path, target, name)
    folder.mkdir(parents=True, exist_ok=False)
    manifest = {'schema': 1, 'kind': 'aimcmp.checkpoint', 'checkpoint_kind': kind,
                'name': name, 'target': target['name'], 'created_at': now(), 'status': 'preparing',
                'original_sha256': sha256(Path(project_path).parent/target['original']),
                'restore_target': copy.deepcopy(target), 'restore_files': [], 'missing_files': []}
    write_json(folder/'checkpoint.json', manifest)
    return folder, manifest


def validate_destination(root, path, project_path, original):
    project = json.loads(Path(project_path).read_text())
    boundary = (root/project.get('workspace_root', '.')).resolve()
    if not root.resolve().is_relative_to(boundary) or boundary == Path(boundary.anchor):
        raise ValueError('Checkpoint workspace boundary must contain the project directory')
    path = inside(boundary, root/path if not Path(path).is_absolute() else path)
    if path == Path(project_path).resolve() or path == Path(original).resolve() or path.is_relative_to(root/'checkpoints'):
        raise ValueError('Checkpoint restore cannot overwrite project identity, original, or checkpoint storage')
    if path.is_relative_to(boundary/'.git') or path.is_relative_to(boundary/'originals'):
        raise ValueError('Checkpoint restore cannot overwrite Git metadata or originals')
    return path


def relative_path(root, path):
    return Path(os.path.relpath(Path(path).resolve(), Path(root).resolve())).as_posix()


def remember(root, folder, manifest, source, stored, role):
    # Callers validate against the configured workspace boundary first.
    source = Path(source).resolve()
    stored_path = inside(folder, stored)
    copy_file(source, stored_path)
    manifest['restore_files'].append({'path': relative_path(root, source),
                                     'stored': stored_path.relative_to(folder).as_posix(), 'role': role})


def configured_paths(root, target):
    config = target['build']
    result = [(root/config['source_dir']/file, 'source') for file in config['files']]
    result += [(Path(path), 'recipe') for path in config.get('_recipe_inputs', [])]
    result += [(root/target[key], 'artifact') for key in ('rebuilt', 'map') if target.get(key)]
    result += [(root/config['download_dir']/Path(a).name, 'artifact') for a in config['artifacts']]
    result += [(root/config['download_dir']/file, 'build') for file in ('aimcmp-flags.txt','build.log')]
    if target.get('mapping'):
        result.append((root/target['mapping'], 'mapping'))
    reports = root/'reports/iterations'/simple_name(target['name'])
    result += [(reports/file, 'report') for file in ('latest.json','latest.html','iteration.json','iteration.txt','previous.json')]
    return result


def capture_working(project_path, target, name, extra_paths=()):
    """Backup edits as they are; do not pretend current binaries came from them."""
    root = Path(project_path).resolve().parent
    folder, manifest = begin(project_path, target, name, 'working-state')
    manifest['provenance'] = 'Unbuilt working-state backup; sources and artifacts may describe different attempts.'
    paths = configured_paths(root, target) + [(root/p, 'restore-backup') for p in extra_paths]
    seen = set()
    for source, role in paths:
        source = validate_destination(root, source, project_path, root/target['original'])
        if source in seen:
            continue
        seen.add(source)
        if source.is_file():
            remember(root, folder, manifest, source, 'files/'+str(len(seen))+'/'+source.name, role)
        elif source.exists():
            raise ValueError('Working-state destination is not a regular file: '+str(source))
        else:
            manifest['missing_files'].append(relative_path(root, source))
    copy_file(project_path, folder/'project-before.json')
    manifest['status'] = 'complete'
    seal(folder, manifest)
    return folder, manifest


def tool_inventory(project, folder):
    config = project.get('toolchain')
    if not config:
        return {'status':'unconfigured', 'tools':[], 'note':'No compiler-tool inventory configured; analysis versions remain in the report.'}
    host = config['ssh']
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', host):
        raise ValueError('Invalid toolchain SSH alias')
    tools = []
    for name, remote in config['files'].items():
        simple_name(name)
        if not re.fullmatch(r'[A-Za-z]:/[A-Za-z0-9 _./-]+', remote) or '..' in remote.split('/'):
            raise ValueError('Toolchain files must be simple absolute Windows paths')
        path = folder/'toolchain'/name
        path.parent.mkdir(parents=True, exist_ok=True)
        run(['scp','-o','BatchMode=yes',host+':'+remote,str(path)])
        pe = pefile.PE(data=path.read_bytes())
        fixed = getattr(pe, 'VS_FIXEDFILEINFO', [])
        version = None
        if fixed:
            v = fixed[0]
            version = '.'.join(str(n) for n in (v.FileVersionMS>>16, v.FileVersionMS&65535, v.FileVersionLS>>16, v.FileVersionLS&65535))
        tools.append({'name':name, 'remote_path':remote, 'version':version, 'sha256':sha256(path)})
    return {'status':'captured', 'ssh':host, 'tools':tools,
            'note':'Configured tool files captured after the build; build-script bytes record the selected toolchain environment.'}


def save_checkpoint(project_path, target, name, args, analyze, report_writer):
    root = Path(project_path).resolve().parent
    folder, manifest = begin(project_path, target, name, 'built-attempt')
    stage = 'snapshot-sources'
    try:
        project = load_project(project_path)
        frozen = copy.deepcopy(target)
        config = frozen['build']
        for file in config['files'] + config['artifacts']:
            if not re.fullmatch(r'[A-Za-z0-9_./-]+', file) or '..' in file.split('/'):
                raise ValueError('Checkpoint build paths must be simple relative paths')
        if getattr(args, 'flags', None) is not None:
            config['flags'] = args.flags
            manifest['restore_target']['build']['flags'] = args.flags
        for file in config['files']:
            source = validate_destination(root, root/config['source_dir']/file, project_path, root/target['original'])
            remember(root, folder, manifest, source, 'sources/'+file, 'source')
        for index, path in enumerate(config.get('_recipe_inputs', [])):
            source = validate_destination(root, Path(path), project_path, root/target['original'])
            remember(root, folder, manifest, source, 'recipe/'+str(index)+'/'+source.name, 'recipe')
        if target.get('mapping'):
            source = validate_destination(root, root/target['mapping'], project_path, root/target['original'])
            remember(root, folder, manifest, source, 'mapping.json', 'mapping')
            frozen['mapping'] = (folder/'mapping.json').relative_to(root).as_posix()
        config['source_dir'] = (folder/'sources').relative_to(root).as_posix()
        config['download_dir'] = (folder/'artifacts').relative_to(root).as_posix()
        config['remote_dir'] = config['remote_dir'].rstrip('/\\')+'/checkpoints/'+name+'-'+uuid.uuid4().hex[:8]
        for key in ('rebuilt', 'map'):
            if target.get(key):
                frozen[key] = config['download_dir']+'/'+Path(target[key]).name
        stage = 'build-and-assess'
        attempt_args = copy.copy(args)
        attempt_args.output_dir = str(folder/'reports')
        attempt_args.no_build = False
        attempt_args.baseline = None
        attempt_args.diff_limit = getattr(args, 'diff_limit', 3)
        attempt_args.function_limit = getattr(args, 'function_limit', 20)
        brief, status = iterate(Path(project_path), frozen, attempt_args, analyze, report_writer)
        if status == 1:
            raise RuntimeError('Checkpoint assessment failed: '+json.dumps(brief.get('error', {'outcome':brief['outcome']})))
        for artifact in config['artifacts']:
            original_path = inside(root, root/target['build']['download_dir']/Path(artifact).name)
            manifest['restore_files'].append({'path':original_path.relative_to(root).as_posix(),
                'stored':'artifacts/'+Path(artifact).name, 'role':'artifact'})
        for file in ('aimcmp-flags.txt', 'build.log'):
            manifest['restore_files'].append({'path':inside(root, root/target['build']['download_dir']/file).relative_to(root).as_posix(),
                'stored':'artifacts/'+file, 'role':'build'})
        report_directory = root/'reports/iterations'/simple_name(target['name'])
        for file in ('latest.json','latest.html','iteration.json','iteration.txt'):
            manifest['restore_files'].append({'path':(report_directory/file).relative_to(root).as_posix(),
                                             'stored':'reports/'+file, 'role':'report'})
        manifest['missing_files'].append((report_directory/'previous.json').relative_to(root).as_posix())
        stage = 'toolchain-inventory'
        manifest['toolchain'] = tool_inventory(project, folder)
        manifest['analysis'] = brief['analysis']
        manifest['summary'] = brief['summary']
        manifest['configured_flags'] = config.get('flags', '')
        manifest['build_target'] = frozen
        manifest['report'] = 'reports/latest.json'
        manifest['status'] = 'complete'
        manifest['completed_at'] = now()
        seal(folder, manifest)
        return {'name':name, 'path':str(folder), 'summary':brief['summary'], 'status':'complete'}, status
    except Exception as exc:
        manifest.update(status='failed', error={'stage':stage,'message':str(exc)})
        write_json(folder/'checkpoint.json', manifest)
        raise RuntimeError('Checkpoint failed at '+stage+'; evidence retained in '+str(folder)+': '+str(exc)) from exc


def verify(folder):
    folder = Path(folder).resolve()
    manifest = json.loads((folder/'checkpoint.json').read_text())
    if manifest.get('schema') != 1 or manifest.get('kind') != 'aimcmp.checkpoint' or manifest.get('status') != 'complete':
        raise ValueError('Checkpoint is incomplete or failed: '+str(folder))
    seal_path = folder/'checkpoint.sha256'
    if not seal_path.is_file() or seal_path.read_text().strip() != sha256(folder/'checkpoint.json'):
        raise ValueError('Checkpoint manifest integrity check failed: '+str(folder))
    recorded = set()
    for file in manifest['files']:
        path = inside(folder, file['stored'])
        if path in recorded:
            raise ValueError('Duplicate checkpoint inventory path')
        recorded.add(path)
        if not path.is_file() or path.stat().st_size != file['size'] or sha256(path) != file['sha256']:
            raise ValueError('Checkpoint integrity check failed: '+file['stored'])
    for file in manifest['restore_files']:
        if inside(folder, file['stored']) not in recorded:
            raise ValueError('Restore payload is absent from verified inventory')
    if manifest.get('report') and inside(folder, manifest['report']) not in recorded:
        raise ValueError('Report is absent from verified inventory')
    return manifest


def compare_checkpoints(before_folder, after_folder):
    before, after = verify(before_folder), verify(after_folder)
    if before['target'] != after['target'] or before['original_sha256'] != after['original_sha256']:
        raise ValueError('Checkpoints must share a target and original SHA-256')
    if not before.get('report') or not after.get('report'):
        raise ValueError('Unbuilt working-state backups cannot provide assessment deltas')
    read = lambda folder,m:json.loads((Path(folder)/m['report']).read_text())
    result = compact_report(read(after_folder, after), read(before_folder, before))
    def hashes(m):
        inventory_by_path = {f['stored']:f['sha256'] for f in m['files']}
        return {f['path']:inventory_by_path[f['stored']] for f in m['restore_files'] if f['role'] in ('source','mapping')}
    a, b = hashes(before), hashes(after)
    result['checkpoint_delta'] = {'before':before['name'], 'after':after['name'],
        'changed_source_or_mapping_paths':[p for p in sorted(a.keys()|b.keys()) if a.get(p)!=b.get(p)],
        'configured_flags':{'before':before.get('configured_flags'), 'after':after.get('configured_flags')},
        'toolchain_changed':before.get('toolchain') != after.get('toolchain')}
    return result


def install_files(project_path, target, folder, manifest):
    root = Path(project_path).resolve().parent
    original = root/target['original']
    destinations = set()
    writes = []
    for file in manifest['restore_files']:
        destination = validate_destination(root, file['path'], project_path, original)
        if destination in destinations:
            raise ValueError('Duplicate restore destination')
        destinations.add(destination)
        writes.append((inside(folder, file['stored']), destination))
    missing = [validate_destination(root, p, project_path, original) for p in manifest.get('missing_files', [])]
    if any(p in destinations for p in missing):
        raise ValueError('Restore path cannot be both present and missing')
    for source, destination in writes:
        copy_file(source, destination)
    # Saved evidence may predate portable path metadata. Normalize only the
    # active ledger copy, leaving the sealed checkpoint payload unchanged.
    for file in manifest['restore_files']:
        if file['role'] == 'mapping':
            path = validate_destination(root, file['path'], project_path, original)
            ledger = json.loads(path.read_text())
            if ledger.get('kind') == 'aimcmp.mapping':
                ledger['original']['path'] = target['original']
                write_json(path, ledger)
    for path in missing:
        if path.is_file():
            path.unlink()
        elif path.exists():
            raise ValueError('Cannot restore a missing file over a directory: '+str(path))
    project = json.loads(Path(project_path).read_text())
    index = next(i for i,t in enumerate(project['targets']) if t['name']==target['name'])
    restored_target = copy.deepcopy(manifest['restore_target'])
    # The original identity is SHA-anchored; retain its current project path
    # when restoring evidence saved before a workspace relocation.
    restored_target['original'] = target['original']
    project['targets'][index] = portable_target(project, restored_target)
    write_json(project_path, project)


def restore_checkpoint(project_path, target, name):
    root = Path(project_path).resolve().parent
    folder = location(project_path, target, name)
    manifest = verify(folder)
    if manifest['target'] != target['name'] or manifest['original_sha256'] != sha256(root/target['original']):
        raise ValueError('Checkpoint does not match the current target/original')
    manifest = relocated_sources(root, target, manifest)
    # Validate every destination before creating the backup or overwriting files.
    all_paths = [f['path'] for f in manifest['restore_files']] + manifest.get('missing_files', [])
    for path in all_paths:
        validate_destination(root, path, project_path, root/target['original'])
    if manifest['restore_target']['name'] != target['name']:
        raise ValueError('Restore cannot rename a target')
    # Reject duplicate destinations before any mutation.
    if len({validate_destination(root,p,project_path,root/target['original']) for p in all_paths}) != len(all_paths):
        raise ValueError('Duplicate restore destination')
    backup_name = 'before-restore-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+uuid.uuid4().hex[:8]
    backup_folder, backup = capture_working(project_path, target, backup_name, all_paths)
    try:
        install_files(project_path, target, folder, manifest)
    except Exception as exc:
        try:
            install_files(project_path, target, backup_folder, backup)
        except Exception as rollback:
            raise RuntimeError('Restore and rollback failed; preserved backup '+str(backup_folder)+': '+str(rollback)) from exc
        raise RuntimeError('Restore failed and was rolled back; preserved backup '+str(backup_folder)+': '+str(exc)) from exc
    return {'restored':name, 'backup':backup_name, 'backup_path':str(backup_folder),
            'note':'Local files and target recipe restored. Next build uploads the restored sources. Existing experiment checkpoints remain intact.'}


def relocated_sources(root, target, manifest):
    """Rebase verified source payloads without rewriting sealed evidence."""
    result = copy.deepcopy(manifest)
    saved = result['restore_target']['build']
    current = target['build']
    # Legacy batch files remain sealed evidence. A recipe-based target always
    # builds through its current renderer, never through a restored old script.
    if current.get('recipe') and not saved.get('recipe'):
        result['restore_files'] = [file for file in result['restore_files']
            if not (file['role'] == 'source' and
                    (root/file['path']).resolve() == (root/saved['source_dir']/saved['script']).resolve() and
                    saved['script'] not in current['files'])]
        for key in ('recipe', 'recipe_data', '_recipe_inputs', 'files', 'script'):
            if key in current:
                saved[key] = copy.deepcopy(current[key])
        if 'flags' not in saved:
            saved['flags'] = current.get('flags', '')
    old_root = (root/saved['source_dir']).resolve()
    new_root = (root/current['source_dir']).resolve()
    if old_root != new_root:
        def rebase(path):
            resolved = (root/path).resolve()
            if not resolved.is_relative_to(old_root):
                raise ValueError('Source restore path must stay inside the saved source directory')
            name = resolved.relative_to(old_root).as_posix()
            if name not in saved['files'] or name not in current['files']:
                raise ValueError('Relocated source is absent from the current upload file list: '+name)
            return relative_path(root, new_root/name)
        for file in result['restore_files']:
            if file['role'] == 'source':
                file['path'] = rebase(file['path'])
        result['missing_files'] = [rebase(path) if (root/path).resolve().is_relative_to(old_root) else path
                                   for path in result.get('missing_files', [])]
    saved['source_dir'] = current['source_dir']
    return result


def list_checkpoints(project_path, target):
    root = location(project_path, target, 'placeholder').parent
    result = []
    if root.exists():
        for folder in sorted(root.iterdir()):
            if folder.is_dir() and (folder/'checkpoint.json').is_file():
                m = json.loads((folder/'checkpoint.json').read_text())
                result.append({k:m.get(k) for k in ('name','checkpoint_kind','created_at','status','summary','error')})
    return result
