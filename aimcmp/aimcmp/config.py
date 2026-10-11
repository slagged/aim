"""Portable project recipes with optional, machine-only local overrides."""
from pathlib import Path
import copy
import json
from .recipes import load_recipe


MACHINE_BUILD_FIELDS = {'ssh', 'remote_dir', 'timeout_seconds'}


def resolve_recipes(project, path):
    for target in project['targets']:
        config = target.get('build', {})
        if config.get('recipe'):
            recipe, inputs = load_recipe(path.parent, config['recipe'])
            config['recipe_data'] = recipe
            config['_recipe_inputs'] = [str(p) for p in inputs]
            config.setdefault('flags', recipe['flags'])
            config.setdefault('script', 'aimcmp-build.cmd')
            files = []
            for product in recipe['products']:
                filenames = [product['source'], product.get('definition'), product.get('resource', {}).get('source')]
                filenames += [unit['source'] for unit in product.get('additional_sources', [])]
                for filename in filenames:
                    if filename and filename not in files:
                        files.append(filename)
            config.setdefault('files', files)
            products = [p for p in recipe['products'] if Path(p['binary']).stem == target['name']]
            if len(products) != 1:
                raise ValueError('Recipe must identify one product for target '+target['name'])
            config.setdefault('artifacts', [products[0]['binary'], products[0]['map']])
    tools = project.get('toolchain', {})
    if tools.get('profile'):
        profile = json.loads((path.parent/tools['profile']).read_text())
        tools['files'] = {name: item['path'] for name, item in profile['tools'].items()}
    return project


def load_project(path):
    path = Path(path).resolve()
    project = resolve_recipes(json.loads(path.read_text()), path)
    local_path = project.get('local_config')
    if not local_path:
        return project
    local_path = (path.parent/local_path).resolve()
    if not local_path.exists():
        return project
    local = json.loads(local_path.read_text())
    if local.get('schema') != 1 or set(local) - {'schema', 'targets', 'toolchain', 'batch_archive_tool'}:
        raise ValueError('Local machine configuration has unsupported schema or fields')
    targets = {target['name']: target for target in project['targets']}
    for name, overrides in local.get('targets', {}).items():
        if name not in targets or not isinstance(overrides, dict) or set(overrides) - MACHINE_BUILD_FIELDS:
            raise ValueError('Local configuration may only override known targets and machine build fields')
        targets[name]['build'].update(overrides)
    if 'toolchain' in local:
        overrides = local['toolchain']
        if not isinstance(overrides, dict) or set(overrides) - {'ssh', 'files'}:
            raise ValueError('Local toolchain configuration may only override ssh and files')
        toolchain = project.setdefault('toolchain', {})
        if 'ssh' in overrides:
            toolchain['ssh'] = overrides['ssh']
        if 'files' in overrides:
            if not isinstance(overrides['files'], dict):
                raise ValueError('Local toolchain files must be a dictionary')
            toolchain.setdefault('files', {}).update(overrides['files'])
    if 'batch_archive_tool' in local:
        project['batch_archive_tool'] = local['batch_archive_tool']
    return project


def portable_target(project, target):
    """Never serialize effective machine overrides back into a public recipe."""
    result = copy.deepcopy(target)
    base = next(item for item in project['targets'] if item['name'] == target['name'])
    recipe = result['build'].pop('recipe_data', None)
    result['build'].pop('_recipe_inputs', None)
    if recipe and 'flags' not in base['build'] and result['build'].get('flags') == recipe['flags']:
        result['build'].pop('flags', None)
    if recipe:
        for field in ('files', 'artifacts', 'script'):
            if field not in base['build']:
                result['build'].pop(field, None)
    for field in MACHINE_BUILD_FIELDS:
        if field in base['build']:
            result['build'][field] = base['build'][field]
        else:
            result['build'].pop(field, None)
    return result
