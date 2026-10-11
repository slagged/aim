"""Configurable source fragments, one isolated remote batch, explicit promotion."""
from pathlib import Path
import copy
import itertools
import json
import math
import re
import stat
import sys
import uuid
import zipfile
from .build import run
from .pe import Image, sha256
from .compare import compare
from .iteration import compact_report, render_text
from .mappings import annotations
from .config import load_project
from .recipes import render_recipe
from .checkpoints import (begin, inside, simple_name, write_json, copy_file, seal, verify,
                          tool_inventory, restore_checkpoint, location, validate_destination, relative_path)
from .checkpoints import remember


def expand(spec, templates):
    if spec.get('schema')!=1 or not isinstance(spec.get('axes'),list) or not spec['axes']:
        raise ValueError('Variant specification requires schema 1 and a nonempty axes list')
    names = set()
    if spec.get('flags') is not None and (not isinstance(spec['flags'],str) or not re.fullmatch(r'[A-Za-z0-9 /:_.+-]*',spec['flags'])):
        raise ValueError('Variant flags contain unsupported characters')
    for axis in spec['axes']:
        simple_name(axis['name'])
        if axis['name'] in names or not axis.get('choices'):
            raise ValueError('Variant axes must have unique names and nonempty choices')
        names.add(axis['name'])
        choices = set()
        marker = '{{'+axis['name']+'}}'
        present = any(marker in text for text in templates.values())
        for choice in axis['choices']:
            simple_name(choice['name'])
            if choice['name'] in choices:
                raise ValueError('Duplicate variant choice name')
            choices.add(choice['name'])
            if ('text' in choice)!=present or ('text' in choice and not isinstance(choice['text'],str)):
                raise ValueError('Each fragment choice must supply text for its template marker: '+marker)
            if not present and 'flags' not in choice:
                raise ValueError('An axis without a template marker must select flags')
            if 'flags' in choice and (not isinstance(choice['flags'],str) or
                    not re.fullmatch(r'[A-Za-z0-9 /:_.+-]*',choice['flags'])):
                raise ValueError('Variant flags contain unsupported characters')
    total = math.prod(len(a['choices']) for a in spec['axes'])
    maximum = spec.get('max_variants',256)
    if not isinstance(maximum,int) or isinstance(maximum,bool) or maximum<1 or total>maximum:
        raise ValueError('Variant combination count exceeds max_variants')
    result = []
    for index,choices in enumerate(itertools.product(*(a['choices'] for a in spec['axes']))):
        rendered = dict(templates)
        flags = spec.get('flags')
        selection = {}
        for axis,choice in zip(spec['axes'],choices):
            selection[axis['name']] = choice['name']
            if 'text' in choice:
                for file in rendered:
                    rendered[file] = rendered[file].replace('{{'+axis['name']+'}}',choice['text'])
            if 'flags' in choice:
                if flags is not None and any('flags' in c for c in choices[:len(selection)-1]):
                    raise ValueError('Only one axis may select the complete flag string')
                flags = choice['flags']
        if any(re.search(r'\{\{[A-Za-z0-9_.-]+\}\}',text) for text in rendered.values()):
            raise ValueError('Template contains an unresolved fragment marker')
        result.append({'id':f'v{index:04d}','selection':selection,'sources':rendered,'flags':flags})
    return result


def safe_extract(archive, destination):
    destination = Path(destination).resolve()
    with zipfile.ZipFile(archive) as zipped:
        for item in zipped.infolist():
            name = item.filename.replace('\\','/')
            if ':' in name or name.startswith('/') or '..' in name.split('/') or stat.S_ISLNK(item.external_attr>>16):
                raise ValueError('Unsafe path in variant artifact archive')
            path = inside(destination,name)
            if item.is_dir():
                path.mkdir(parents=True,exist_ok=True)
            else:
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes(zipped.read(item))


def remote_batch(host, remote, archive_tool, folder):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+',host):
        raise ValueError('Invalid batch SSH alias')
    for path in (remote,archive_tool):
        if not re.fullmatch(r'[A-Za-z]:/[A-Za-z0-9 _./-]+',path) or '..' in path.split('/'):
            raise ValueError('Batch paths must be simple absolute Windows paths')
    win = remote.replace('/','\\')
    tool = archive_tool.replace('/','\\')
    log = []
    def action(args,timeout=300):
        try:
            output = run(args,timeout)
            log.append(output)
        except Exception as exc:
            log.append(str(exc))
            raise
        finally:
            (folder/'batch.log').write_text('\n'.join(log),encoding='utf-8')
    action(['ssh','-n','-o','BatchMode=yes',host,f'cmd /c if not exist "{win}" mkdir "{win}"'])
    action(['scp','-o','BatchMode=yes',str(folder/'sources.zip'),host+':'+remote+'/sources.zip'])
    action(['ssh','-n','-o','BatchMode=yes',host,f'cmd /c ""{tool}" x -y "{win}\\sources.zip" -o"{win}""'])
    action(['ssh','-n','-o','BatchMode=yes',host,f'cmd /c ""{win}\\run.cmd""'],timeout=3600)
    action(['scp','-o','BatchMode=yes',host+':'+remote+'/artifacts.zip',str(folder/'artifacts.zip')])


def run_variants(project_path, target, spec_path, name, args, analyze, writer):
    root = Path(project_path).resolve().parent
    simple_name(name); simple_name(target['name'])
    spec_path = Path(spec_path).resolve()
    spec = json.loads(spec_path.read_text())
    templates = {}
    for file,path in spec.get('templates',{}).items():
        if file not in target['build']['files']:
            raise ValueError('Template destination must be a configured source file: '+file)
        templates[file] = inside(spec_path.parent,path).read_text(encoding='utf-8')
    variants = expand(spec,templates)
    folder = root/'experiments/runs'/target['name']/name
    folder.mkdir(parents=True,exist_ok=False)
    manifest = {'schema':1,'kind':'aimcmp.variant-run','name':name,'target':target['name'],
                'status':'preparing','records':[],'original_sha256':sha256(root/target['original'])}
    write_json(folder/'run.json',manifest)
    frozen = []
    try:
        project = load_project(project_path)
        config = target['build']
        for file in config['files']+config['artifacts']+[config['script']]:
            if not re.fullmatch(r'[A-Za-z0-9_./-]+',file) or '..' in file.split('/'):
                raise ValueError('Variant build paths must be simple relative paths')
        for variant in variants:
            flags = variant['flags'] if variant['flags'] is not None else config.get('flags','')
            if not isinstance(flags,str) or not re.fullmatch(r'[A-Za-z0-9 /:_.+-]*',flags):
                raise ValueError('Variant flags contain unsupported characters')
        archive_tool = spec.get('archive_tool',project.get('batch_archive_tool'))
        if not archive_tool:
            raise ValueError('Set batch_archive_tool to the VM 7z.exe path')
        base_files = {}
        for file in config['files']:
            if not re.fullmatch(r'[A-Za-z0-9_./-]+',file) or '..' in file.split('/'):
                raise ValueError('Variant source paths must be simple relative paths')
            source = validate_destination(root,root/config['source_dir']/file,project_path,root/target['original'])
            base_files[file] = source.read_bytes()
        mapping_bytes = (root/target['mapping']).read_bytes() if target.get('mapping') else None
        for variant in variants:
            checkpoint_name = simple_name(name+'-'+variant['id'])
            checkpoint,cm = begin(project_path,target,checkpoint_name,'built-attempt')
            frozen.append((variant,checkpoint,cm))
            cm['variant'] = {'run':name, 'id':variant['id'],'selection':variant['selection']}
            cm['restore_target']['build']['flags'] = variant['flags'] if variant['flags'] is not None else config.get('flags','')
            for file in config['files']:
                if not re.fullmatch(r'[A-Za-z0-9_./-]+',file) or '..' in file.split('/'):
                    raise ValueError('Variant source paths must be simple relative paths')
                source = validate_destination(root,root/config['source_dir']/file,project_path,root/target['original'])
                destination = inside(checkpoint/'sources',file)
                destination.parent.mkdir(parents=True,exist_ok=True)
                if file in variant['sources']:
                    destination.write_text(variant['sources'][file],encoding='utf-8')
                else:
                    destination.write_bytes(base_files[file])
                cm['restore_files'].append({'path':relative_path(root, source),
                                           'stored':'sources/'+file,'role':'source'})
            if target.get('mapping'):
                source = validate_destination(root,root/target['mapping'],project_path,root/target['original'])
                (checkpoint/'mapping.json').write_bytes(mapping_bytes)
                cm['restore_files'].append({'path':source.relative_to(root).as_posix(),'stored':'mapping.json','role':'mapping'})
            for index, path in enumerate(config.get('_recipe_inputs', [])):
                source = validate_destination(root,Path(path),project_path,root/target['original'])
                remember(root,checkpoint,cm,source,'recipe/'+str(index)+'/'+source.name,'recipe')
            if config.get('recipe_data'):
                (checkpoint/'sources'/config['script']).write_text(render_recipe(config['recipe_data']),encoding='utf-8',newline='')
            (checkpoint/'sources/aimcmp-flags.txt').write_text(cm['restore_target']['build']['flags']+'\n',encoding='ascii')
        write_json(folder/'specification.json',spec)
        write_json(folder/'target-recipe.json',target)
        resolved_spec = copy.deepcopy(spec)
        for file,text in templates.items():
            destination = inside(folder/'templates',file)
            destination.parent.mkdir(parents=True,exist_ok=True)
            destination.write_text(text,encoding='utf-8')
            resolved_spec['templates'][file] = 'templates/'+file
        write_json(folder/'specification-resolved.json',resolved_spec)
        lines = ['@echo off','cd /d "%~dp0"']
        for variant,checkpoint,cm in frozen:
            lines += ['pushd '+variant['id'],'call '+config['script']+' > build.log 2>&1',
                      'echo %errorlevel% > exit-code.txt','popd']
        lines += ['"'+archive_tool.replace('/','\\')+'" a -tzip artifacts.zip .\\v*','exit /b %errorlevel%']
        (folder/'run.cmd').write_text('\r\n'.join(lines)+'\r\n',encoding='ascii')
        with zipfile.ZipFile(folder/'sources.zip','w',zipfile.ZIP_DEFLATED) as zipped:
            zipped.write(folder/'run.cmd','run.cmd')
            for variant,checkpoint,cm in frozen:
                for source in (checkpoint/'sources').rglob('*'):
                    if source.is_file():
                        zipped.write(source,variant['id']+'/'+source.relative_to(checkpoint/'sources').as_posix())
        remote = config['remote_dir'].rstrip('/\\')+'/variants/'+name+'-'+uuid.uuid4().hex[:8]
        manifest['remote_dir'] = remote
        manifest['status'] = 'building'
        write_json(folder/'run.json',manifest)
        remote_batch(config['ssh'],remote,archive_tool,folder)
        safe_extract(folder/'artifacts.zip',folder/'returned')
        tools = tool_inventory(project,folder)
        left = Image(root/target['original'])
        if sha256(left.path)!=manifest['original_sha256']:
            raise ValueError('Original binary changed during the variant run')
        mapping = json.loads(mapping_bytes) if mapping_bytes is not None else {}
        left_args = copy.copy(args)
        left_args.mapping_annotations = annotations(mapping,left,'original')
        left_snapshot = analyze(left,left_args)
        for variant,checkpoint,cm in frozen:
            record = {'variant':variant['id'],'checkpoint':cm['name'],'selection':variant['selection'],
                      'flags':cm['restore_target']['build']['flags']}
            try:
                returned = folder/'returned'/variant['id']
                if not (returned/'exit-code.txt').is_file():
                    raise RuntimeError('Remote variant has no exit status')
                code = int((returned/'exit-code.txt').read_text().strip())
                copy_file(returned/'build.log',checkpoint/'build.log')
                if code:
                    raise RuntimeError('Compiler/build script exited '+str(code)+'; see build.log')
                for artifact in config['artifacts']:
                    source = inside(returned,artifact)
                    stored = 'artifacts/'+Path(artifact).name
                    copy_file(source,checkpoint/stored)
                    cm['restore_files'].append({'path':inside(root,root/config['download_dir']/Path(artifact).name).relative_to(root).as_posix(),
                                               'stored':stored,'role':'artifact'})
                for file,stored in (('build.log','build.log'),('aimcmp-flags.txt','sources/aimcmp-flags.txt')):
                    cm['restore_files'].append({'path':inside(root,root/config['download_dir']/file).relative_to(root).as_posix(),
                                               'stored':stored,'role':'build'})
                rebuilt = Image(checkpoint/'artifacts'/Path(target['rebuilt']).name,
                                checkpoint/'artifacts'/Path(target['map']).name if target.get('map') else None)
                right_args = copy.copy(args)
                right_args.mapping_annotations = annotations(mapping,rebuilt,'rebuilt')
                report = compare(left,rebuilt,left_snapshot,analyze(rebuilt,right_args),mapping)
                brief = compact_report(report)
                if brief['outcome']=='analysis-error':
                    raise RuntimeError('Function analysis errors; cannot rank this variant')
                writer(report,checkpoint/'reports/latest.json',checkpoint/'reports/latest.html')
                write_json(checkpoint/'reports/iteration.json',brief)
                (checkpoint/'reports/iteration.txt').write_text(render_text(brief)+'\n',encoding='utf-8')
                for file in ('latest.json','latest.html','iteration.json','iteration.txt'):
                    cm['restore_files'].append({'path':'reports/iterations/'+target['name']+'/'+file,'stored':'reports/'+file,'role':'report'})
                cm['missing_files'].append('reports/iterations/'+target['name']+'/previous.json')
                cm.update(status='complete',report='reports/latest.json',analysis=report['analysis'],summary=report['summary'],
                          configured_flags=record['flags'],toolchain=tools)
                seal(checkpoint,cm)
                record.update(status='complete',summary=report['summary'],report=str(checkpoint/'reports/latest.json'))
            except Exception as exc:
                cm.update(status='failed',error={'stage':'compile-or-assess','message':str(exc)})
                write_json(checkpoint/'checkpoint.json',cm)
                record.update(status='failed',error=str(exc))
            manifest['records'].append(record)
            print(variant['id']+': '+record['status']+(f' {record["summary"]["normalized_coverage_percent"]}%' if record.get('summary') else ''),file=sys.stderr,flush=True)
            write_json(folder/'run.json',manifest)
        def rank(record):
            s = record.get('summary',{})
            return (record['status']=='complete',s.get('file_match_except_timestamps',False),
                    s.get('code_sections_exact',False),s.get('normalized_coverage_percent',0),s.get('exact_functions',0))
        manifest['records'].sort(key=rank,reverse=True)
        manifest['status'] = 'complete'
        manifest['toolchain'] = tools
        write_json(folder/'run.json',manifest)
        (folder/'run.sha256').write_text(sha256(folder/'run.json')+'\n',encoding='ascii')
        return manifest, 1 if any(r['status']=='failed' for r in manifest['records']) else 0
    except Exception as exc:
        manifest.update(status='failed',error=str(exc))
        write_json(folder/'run.json',manifest)
        for variant,checkpoint,cm in frozen:
            if cm['status']!='complete' and cm['status']!='failed':
                cm.update(status='failed',error={'stage':'batch-run','message':str(exc)})
                write_json(checkpoint/'checkpoint.json',cm)
        raise


def promote(project_path,target,run_name,variant_id,require_exact=False):
    folder = Path(project_path).parent/'experiments/runs'/simple_name(target['name'])/simple_name(run_name)
    if not (folder/'run.sha256').is_file() or (folder/'run.sha256').read_text().strip()!=sha256(folder/'run.json'):
        raise ValueError('Variant run integrity check failed')
    manifest = json.loads((folder/'run.json').read_text())
    records = [r for r in manifest['records'] if r['variant']==variant_id and r['status']=='complete']
    if len(records)!=1:
        raise ValueError('Variant is missing or failed')
    checkpoint = location(project_path,target,records[0]['checkpoint'])
    cm = verify(checkpoint)
    report = json.loads((checkpoint/cm['report']).read_text())
    actual = Image(checkpoint/'artifacts'/Path(target['rebuilt']).name).metadata()
    if actual['sha256']!=report['rebuilt']['sha256'] or sha256(Path(project_path).parent/target['original'])!=report['original']['sha256']:
        raise ValueError('Variant report does not describe the saved binaries')
    exact = actual['code_sha256']==Image(Path(project_path).parent/target['original']).metadata()['code_sha256']
    if exact!=report['summary']['code_sections_exact']:
        raise ValueError('Raw-code verification disagrees with saved match claim')
    if require_exact and not exact:
        raise ValueError('Selected variant does not match raw code bytes')
    result = restore_checkpoint(project_path,target,records[0]['checkpoint'])
    result.update(variant=variant_id,raw_code_verified=exact)
    return result


def add_parser(sub, analysis_options):
    p = sub.add_parser('variants',help='Batch source-fragment combinations and explicitly promote a result')
    commands = p.add_subparsers(dest='variants_command',required=True)
    run_parser = commands.add_parser('run')
    run_parser.add_argument('project'); run_parser.add_argument('name'); run_parser.add_argument('specification'); run_parser.add_argument('run_name')
    analysis_options(run_parser)
    put = commands.add_parser('promote')
    put.add_argument('project'); put.add_argument('name'); put.add_argument('run_name'); put.add_argument('variant')
    put.add_argument('--require-exact',action='store_true')


def execute(args,load_target,analyze,writer):
    path,target = load_target(args.project,args.name)
    if args.variants_command=='promote':
        print(json.dumps(promote(path,target,args.run_name,args.variant,args.require_exact),indent=2))
        return 0
    result,status = run_variants(path,target,args.specification,args.run_name,args,analyze,writer)
    print(json.dumps({'run':result['name'],'status':result['status'],'variants':len(result['records']),
                      'best':result['records'][0]},indent=2))
    return status
