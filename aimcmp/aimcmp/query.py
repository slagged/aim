"""Focused BN evidence exports from owned views, with content-keyed caches."""
from pathlib import Path
from itertools import islice
import hashlib
import json
import rpyc
from .pe import Image, canonical, sha256
from .mappings import annotations, apply, number
from .compare import instructions

FIELDS = ('assembly','hlil','callers','references','types')


def bounded(values, limit, convert=lambda value:value):
    rows = list(islice(values, limit+1))
    return {'items':[convert(v) for v in rows[:limit]], 'truncated':len(rows)>limit}


def resolve_address(bv, image, selector, data, kind):
    try:
        return number(selector)
    except ValueError:
        pass
    matches = {r['address'] for r in (data or {}).get('records', [])
               if r['kind'] == ('function' if kind=='function' else 'global') and selector in (r['id'],r['name'])}
    if selector == 'entry' and kind == 'function':
        matches.add(image.entry)
    for address,name in image.exports.items():
        if canonical(name)==canonical(selector):
            matches.add(address)
    for address,row in image.symbols.items():
        if canonical(row['name'])==canonical(selector) and row['function']==(kind=='function'):
            matches.add(address)
    for symbol in list(bv.get_symbols_by_name(selector)):
        matches.add(int(symbol.address))
    if len(matches)!=1:
        raise ValueError('Query selector is missing or ambiguous: '+selector)
    return next(iter(matches))


def reference(bv, image, address, names=None, globals_=None):
    symbol = bv.get_symbol_at(address)
    return {'address':int(address), 'name':str(symbol.name) if symbol else None,
            'identity':image.reference(int(address),names or {},globals_ or {})}


def export(bv, image, address, kind, fields, limit, data):
    symbol = bv.get_symbol_at(address)
    result = {'address':address, 'name':str(symbol.name) if symbol else hex(address),
              'kind':kind, 'fields':{}, 'errors':[]}
    function = bv.get_function_at(address) if kind=='function' else None
    if kind=='function' and function is None:
        raise ValueError('Query address is not an analyzed function start: '+hex(address))
    if not image.section(address):
        raise ValueError('Query address lies outside image sections')
    if kind=='data' and any(f in fields for f in ('assembly','hlil','callers')):
        raise ValueError('Data queries support references and types')
    blocks = []
    if function is not None:
        result['name'] = str(function.name)
        if 'assembly' in fields or 'references' in fields:
            blocks = [{'start':int(b.start),'end':int(b.end),'edges':[]} for b in list(function.basic_blocks)]
    names = dict(image.exports)
    names.update({a:s['name'] for a,s in image.symbols.items() if s['function']})
    globals_ = {r['address']:'mapping:'+r['id'] for r in (data or {}).get('records',[]) if r['kind']=='global'}
    for row in (data or {}).get('records',[]):
        if row['kind']=='function':
            names[row['address']] = 'mapping:'+row['id']
    for field in fields:
        try:
            if field=='assembly':
                rows,errors = instructions(image, {'address':address,'blocks':blocks},names,globals_)
                result['fields'][field] = bounded(iter(rows),limit)
                result['errors'].extend(errors)
            elif field=='hlil':
                result['fields'][field] = bounded(iter(function.hlil.root.lines),limit,str)
            elif field=='callers':
                result['fields'][field] = bounded(iter(function.caller_sites),limit,
                    lambda ref:{'address':int(ref.address), 'function_address':int(ref.function.start) if ref.function else None,
                                'function_name':str(ref.function.name) if ref.function else None})
            elif field=='types':
                if function is not None:
                    result['fields'][field] = {'signature':str(function.type),
                        'variables':bounded(iter(function.vars),limit,lambda v:{'name':str(v.name),'type':str(v.type)})}
                else:
                    variable = bv.get_data_var_at(address)
                    section = image.section(address)
                    remaining = image.base+section.VirtualAddress+section.Misc_VirtualSize-address
                    width = int(variable.type.width) if variable else min(remaining,64)
                    length = min(limit,64,remaining,width)
                    result['fields'][field] = {'type':str(variable.type) if variable else None,
                        'bytes':image.read(address,length).hex(), 'bytes_truncated':length<width,
                        'string':image.string(address)}
            else:
                incoming = bounded(iter(bv.get_code_refs(address)),limit,
                    lambda ref:{'address':int(ref.address),'function_address':int(ref.function.start) if ref.function else None,
                                'function_name':str(ref.function.name) if ref.function else None})
                incoming_data = bounded(iter(bv.get_data_refs(address)),limit,int)
                outgoing = []
                if function is not None:
                    for block in blocks:
                        length = block['end']-block['start']
                        for target in list(bv.get_code_refs_from(block['start'],function,length=length)):
                            outgoing.append(dict(reference(bv,image,int(target),names,globals_), reference_kind='code',
                                                 range_start=block['start'],range_end=block['end']))
                        for target in list(bv.get_data_refs_from(block['start'],length=length)):
                            outgoing.append(dict(reference(bv,image,int(target),names,globals_), reference_kind='data',
                                                 range_start=block['start'],range_end=block['end']))
                else:
                    outgoing = [dict(reference(bv,image,int(t),names,globals_),reference_kind='data') for t in list(bv.get_data_refs_from(address))]
                result['fields'][field] = {'incoming_code':incoming,'incoming_data':incoming_data,
                                          'outgoing':bounded(iter(outgoing),limit)}
        except Exception as exc:
            result['errors'].append(field+': '+str(exc))
    return result


def query(image, selector, args, ledger=None):
    if image.pe.FILE_HEADER.Machine!=0x14c:
        raise ValueError('Focused queries currently support native x86 PE files only')
    fields = (args.fields or ('references,types' if args.kind=='data' else ','.join(FIELDS))).split(',')
    if len(set(fields)) != len(fields) or any(f not in FIELDS for f in fields):
        raise ValueError('Query fields must be a comma-separated subset of '+','.join(FIELDS))
    if args.limit < 1:
        raise ValueError('Query limit must be positive')
    data = annotations(ledger, image, args.side) if ledger else None
    digest = sha256(image.path)
    conn = rpyc.connect(args.bn_host,args.bn_port,config={'sync_request_timeout':120})
    try:
        bn = conn.root.import_module('binaryninja')
        version = str(bn.core_version())
        key = {'binary':digest,'version':version,'adapter':'query-v2','selector':selector,
               'kind':args.kind,'fields':fields,'limit':args.limit,'annotations':data,'symbols':image.symbols}
        cache_key = hashlib.sha256(json.dumps(key,sort_keys=True).encode()).hexdigest()
        cache = Path(args.cache)/('query-'+cache_key+'.json')
        if cache.exists() and not args.refresh:
            result = json.loads(cache.read_text())
            result['path'] = str(image.path)
            result['cached'] = True
            return result
        bv = bn.load(str(image.path))
        if bv is None:
            raise RuntimeError('Binary Ninja could not load query image')
        try:
            if data:
                apply(bn,bv,data)
            address = resolve_address(bv,image,selector,data,args.kind)
            result = export(bv,image,address,args.kind,fields,args.limit,data)
            result.update(schema=1,report_kind='aimcmp.query',engine='Binary Ninja',engine_version=version,
                          sha256=digest,path=str(image.path),cached=False,
                          outcome='analysis-error' if result['errors'] else 'complete')
            if not result['errors']:
                cache.parent.mkdir(parents=True,exist_ok=True)
                cache.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
            return result
        finally:
            bv.file.close()
    finally:
        conn.close()


def render(result):
    lines = [f'{result["name"]} @ {result["address"]:#x} ({result["kind"]}); cached={result["cached"]}']
    for field,value in result['fields'].items():
        lines.append(field+':')
        if field=='assembly':
            lines += [f'  {r["address"]:#x}: {r["assembly"]} [{r["bytes"]}]' for r in value['items']]
        elif field=='hlil':
            lines += ['  '+r for r in value['items']]
        else:
            lines.append(json.dumps(value,indent=2))
        if isinstance(value,dict) and value.get('truncated'):
            lines.append('  Output truncated; increase --limit for more.')
    lines += ['Error: '+e for e in result['errors']]
    return '\n'.join(lines)


def add_parser(sub, analysis_options, positive_integer):
    for command in ('query','query-target'):
        p = sub.add_parser(command,help='Export focused assembly, HLIL, callers, references, and types')
        if command=='query':
            p.add_argument('binary'); p.add_argument('--map'); p.add_argument('--mapping')
        else:
            p.add_argument('project'); p.add_argument('name')
        p.add_argument('selector',help='Function/data virtual address, symbol, or persistent mapping ID')
        p.add_argument('--kind',choices=['function','data'],default='function')
        p.add_argument('--side',choices=['original','rebuilt'],default='original')
        p.add_argument('--fields',help='Comma-separated fields; data defaults to references,types')
        p.add_argument('--limit',type=positive_integer,default=80)
        p.add_argument('--format',choices=['text','json'],default='text'); p.add_argument('--output')
        analysis_options(p)


def execute(args, load_target):
    ledger = None
    if args.command=='query-target':
        path,target = load_target(args.project,args.name)
        root = path.parent
        image = Image(root/target[args.side],root/target['map'] if args.side=='rebuilt' and target.get('map') else None)
        if target.get('mapping'):
            ledger = json.loads((root/target['mapping']).read_text())
    else:
        image = Image(args.binary,args.map)
        if args.mapping:
            ledger = json.loads(Path(args.mapping).read_text())
    if args.analysis!='binja':
        raise ValueError('Focused queries require Binary Ninja; PE fallback has no caller/type/HLIL evidence')
    result = query(image,args.selector,args,ledger)
    output = json.dumps(result,indent=2) if args.format=='json' else render(result)
    if args.output:
        path = Path(args.output); path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(output+'\n',encoding='utf-8')
    print(output)
    return 1 if result['errors'] else 0
