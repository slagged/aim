"""Render pinned native build recipes into disposable Windows batch scripts."""
from pathlib import Path
import copy
import json
import re


def load_recipe(project_root, filename):
    path = (project_root/filename).resolve()
    recipe = json.loads(path.read_text())
    profile_path = (path.parent/recipe['profile']).resolve()
    profile = json.loads(profile_path.read_text())
    if recipe.get('schema') != 1 or profile.get('schema') != 1:
        raise ValueError('Unsupported build recipe/profile schema')
    result = copy.deepcopy(recipe)
    result['toolchain'] = profile
    # Validate before any remote writes.
    render_recipe(result)
    return result, [path, profile_path]


def safe_path(value):
    if not re.fullmatch(r'[A-Za-z0-9_./-]+', value) or '..' in value.split('/'):
        raise ValueError('Recipe paths must be simple relative paths')
    return value.replace('/', '\\')


def safe_options(values):
    if not all(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9 /:_.=+@,\\"-]+', value) for value in values):
        raise ValueError('Unsupported build recipe options')
    return ' '.join(values)


def render_recipe(recipe):
    environment = recipe['toolchain']['environment']
    if not re.fullmatch(r'[A-Za-z]:/[A-Za-z0-9 _./-]+', environment) or '..' in environment.split('/'):
        raise ValueError('Recipe environment must be a simple absolute Windows path')
    flags = safe_options([recipe['flags']])
    lines = ['@echo off', 'call "'+environment.replace('/', '\\')+'"',
             'if errorlevel 1 exit /b 1', 'cd /d "%~dp0"',
             'if not exist builds mkdir builds', 'set "AIMCMP_CFLAGS='+flags+'"',
             'if exist aimcmp-flags.txt set /p AIMCMP_CFLAGS=<aimcmp-flags.txt']
    for product in recipe['products']:
        definitions = safe_options(['/D'+value for value in product.get('defines', [])])
        objects = []
        for unit in [product] + product.get('additional_sources', []):
            source, obj = safe_path(unit['source']), safe_path(unit['object'])
            lines += [('cl /nologo %AIMCMP_CFLAGS% '+safe_options(recipe['compile_options'])+
                       ' /c '+definitions+' /Fo'+obj+' '+source).replace('  ', ' '),
                      'if errorlevel 1 exit /b 1']
            objects.append(obj)
        if product.get('resource'):
            resource = product['resource']
            output = safe_path(resource['output'])
            lines += ['rc /fo'+output+' '+safe_path(resource['source']), 'if errorlevel 1 exit /b 1']
            objects.append(output)
        options = safe_options(recipe['link_options'])
        if product.get('definition'):
            options += ' /def:'+safe_path(product['definition'])
        lines += ['link /nologo '+options+' /out:'+safe_path(product['binary'])+
                  ' /map:'+safe_path(product['map'])+' '+' '.join(objects)+
                  ' '+safe_options(recipe['libraries']), 'if errorlevel 1 exit /b 1']
    lines.append('echo Build complete. No candidate was executed.')
    return '\r\n'.join(lines)+'\r\n'
