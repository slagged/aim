"""Build isolated inputs locally or through an explicitly configured SSH VM."""
from pathlib import Path
import copy
import os
import re
import shutil
import subprocess
import tempfile
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
    backend = target['build'].get('backend', 'ssh')
    if backend == 'local':
        return build_local(project_path, target, flags, download_dir)
    if backend != 'ssh':
        raise ValueError('Unknown build backend: '+str(backend))
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


def local_path(value):
    """Validate paths before inserting them into a quoted batch command."""
    path = Path(value).resolve()
    if any(character in str(path) for character in '\r\n"%!^&|<>'):
        raise ValueError('Local build path contains batch metacharacters')
    return path


def local_run(environment, script, timeout=300):
    if os.name != 'nt':
        raise ValueError('Local native builds require Windows')
    environment, script = local_path(environment), local_path(script)
    if not environment.is_file() or not script.is_file():
        raise ValueError('Local environment or build script is missing')
    # A fresh command session keeps the compiler environment out of the host.
    with tempfile.TemporaryDirectory(prefix='aimcmp-command-') as directory:
        wrapper = local_path(Path(directory)/'run.cmd')
        wrapper.write_text('@echo off\ncall "'+str(environment)+'"\n'
                           'if errorlevel 1 exit /b %errorlevel%\n'
                           'call "'+str(script)+'"\nexit /b %errorlevel%\n')
        return run(['cmd', '/d', '/c', str(wrapper)], timeout)


def effective_recipe(config):
    recipe = copy.deepcopy(config['recipe_data'])
    if config.get('backend', 'ssh') == 'local':
        recipe['toolchain']['environment'] = str(local_path(config['environment'])).replace('\\', '/')
    return recipe


def build_local(project_path, target, flags=None, download_dir=None):
    root = Path(project_path).resolve().parent
    config = target['build']
    destination = (root/(download_dir or config['download_dir'])).resolve()
    if not destination.is_relative_to(root):
        raise ValueError('Artifact destination must stay inside the project directory')
    destination.mkdir(parents=True, exist_ok=True)
    log_path = destination/'build.log'
    source_root = (root/config['source_dir']).resolve()
    for name in config['files']+config['artifacts']+[config['script']]:
        if not re.fullmatch(r'[A-Za-z0-9_./-]+', name) or '..' in name.split('/'):
            raise ValueError('Build paths must be simple relative paths')
    flags = config.get('flags', '') if flags is None else flags
    if not isinstance(flags, str) or not re.fullmatch(r'[A-Za-z0-9 /:_.+-]*', flags):
        raise ValueError('Matrix flags contain unsupported characters')
    start = time.monotonic()
    logs = []
    stage = 'stage-local'
    workspace = root/'.local/build-work'
    workspace.mkdir(parents=True, exist_ok=True)
    try:
        # Re-stage each build, including matrix retries, so stale products cannot pass.
        with tempfile.TemporaryDirectory(prefix='build-', dir=workspace) as temporary:
            work = Path(temporary)
            for name in config['files']:
                source = (source_root/name).resolve()
                if not source.is_relative_to(source_root) or not source.is_file():
                    raise ValueError('Source file missing or outside source directory: '+name)
                path = work/name
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, path)
            if config.get('recipe_data'):
                (work/config['script']).write_text(render_recipe(effective_recipe(config)), encoding='utf-8', newline='')
            (work/'aimcmp-flags.txt').write_text(flags+'\n', encoding='ascii')
            stage = 'build-local'
            logs.append('[build-local] '+config['script'])
            logs.append(local_run(config['environment'], work/config['script'], config.get('timeout_seconds', 300)))
            stage = 'retrieve-local'
            for name in config['artifacts']:
                shutil.copyfile(work/name, destination/Path(name).name)
    except Exception as error:
        logs.append(str(error))
        log_path.write_text('\n'.join(logs), encoding='utf-8')
        raise BuildError(stage, str(error), log_path) from error
    elapsed = round(time.monotonic()-start, 3)
    log = '\n'.join(logs)+f'\nElapsed seconds: {elapsed}\n'
    log_path.write_text(log, encoding='utf-8')
    return {'target':target['name'], 'backend':'local', 'elapsed_seconds':elapsed,
            'artifacts_dir':str(destination), 'log':log, 'log_path':str(log_path)}
