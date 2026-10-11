"""Upload, build, and retrieve artifacts using an explicitly configured SSH VM."""
from pathlib import Path
import re
import subprocess
import time
from .recipes import render_recipe


class BuildError(RuntimeError):
    def __init__(self, stage, message, log_path):
        super().__init__(message)
        self.stage = stage
        self.log_path = str(log_path)


def run(args, timeout=300):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                            errors='replace', timeout=timeout)
    if result.returncode:
        raise RuntimeError(f'Command failed ({result.returncode}): {args[0]}\n{result.stdout}{result.stderr}')
    return result.stdout + result.stderr


def build(project_path, target, flags=None, download_dir=None, upload=True):
    root = Path(project_path).resolve().parent
    config = target['build']
    host = config['ssh']
    remote = config['remote_dir'].replace('\\', '/').rstrip('/')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', host):
        raise ValueError('SSH alias must contain only letters, digits, dot, underscore or hyphen')
    if not re.fullmatch(r'[A-Za-z]:/[A-Za-z0-9 _./-]+', remote) or '..' in remote.split('/'):
        raise ValueError('Remote build directory must be a simple absolute Windows path')
    script = config['script']
    paths = config['files'] + config['artifacts'] + [script]
    for path in paths:
        if not re.fullmatch(r'[A-Za-z0-9_./-]+', path) or '..' in path.split('/'):
            raise ValueError('Build paths must be simple relative paths')
    destination = (root / (download_dir or config['download_dir'])).resolve()
    if not destination.is_relative_to(root):
        raise ValueError('Artifact destination must stay inside the project directory')
    destination.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    logs = []
    log_path = destination / 'build.log'
    flags = config.get('flags', '') if flags is None else flags
    if flags and not re.fullmatch(r'[A-Za-z0-9 /:_.+-]+', flags):
        raise ValueError('Matrix flags contain unsupported characters')

    def perform(stage, args, timeout=300):
        logs.append(f'[{stage}] ' + subprocess.list2cmdline(args))
        try:
            logs.append(run(args, timeout))
        except Exception as error:
            logs.append(str(error))
            log_path.write_text('\n'.join(logs), encoding='utf-8')
            raise BuildError(stage, str(error), log_path) from error
        log_path.write_text('\n'.join(logs), encoding='utf-8')

    win_dir = remote.replace('/', '\\')
    perform('prepare-remote', ['ssh', '-n', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', host,
                     f'cmd /c if not exist "{win_dir}" mkdir "{win_dir}"'])
    source_root = (root / config['source_dir']).resolve()
    for file in config['files'] if upload else []:
        local = (source_root / file).resolve()
        if not local.is_relative_to(source_root) or not local.is_file():
            raise ValueError('Source file missing or outside source directory: ' + file)
        if '/' in file:
            parent = (remote + '/' + str(Path(file).parent).replace('\\', '/')).replace('/', '\\')
            perform('upload', ['ssh', '-n', '-o', 'BatchMode=yes', host,
                             f'cmd /c if not exist "{parent}" mkdir "{parent}"'])
        perform('upload', ['scp', '-o', 'BatchMode=yes', str(local), f'{host}:{remote}/{file}'])
    if config.get('recipe_data'):
        generated = destination/script
        generated.write_text(render_recipe(config['recipe_data']), encoding='utf-8', newline='')
        perform('upload', ['scp', '-o', 'BatchMode=yes', str(generated), f'{host}:{remote}/{script}'])
    if flags is not None:
        flags_path = destination / 'aimcmp-flags.txt'
        flags_path.write_text(flags+'\n', encoding='ascii')
        perform('upload', ['scp', '-o', 'BatchMode=yes', str(flags_path), f'{host}:{remote}/aimcmp-flags.txt'])
    remote_script = (remote + '/' + script).replace('/', '\\')
    perform('build', ['ssh', '-n', '-o', 'BatchMode=yes', host, f'cmd /c "{remote_script}"'], config.get('timeout_seconds', 300))
    for artifact in config['artifacts']:
        local = destination / Path(artifact).name
        perform('retrieve', ['scp', '-o', 'BatchMode=yes', f'{host}:{remote}/{artifact}', str(local)])
    elapsed = round(time.monotonic() - start, 3)
    log = '\n'.join(logs) + f'\nElapsed seconds: {elapsed}\n'
    log_path.write_text(log, encoding='utf-8')
    return {'target': target['name'], 'elapsed_seconds': elapsed, 'artifacts_dir': str(destination), 'log': log, 'log_path': str(log_path)}
