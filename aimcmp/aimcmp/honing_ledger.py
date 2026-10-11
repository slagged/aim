"""Content-addressed honing attempts and explicit plateau declarations."""
from pathlib import Path
import hashlib
import json
import re
import datetime
from contextlib import contextmanager

TOKEN = re.compile(r'''(?:u8|[LuU])?"(?:\\.|[^"\\])*"|(?:[LuU])?'(?:\\.|[^'\\])*'|//[^\n]*|/\*[\s\S]*?\*/|[A-Za-z_$][\w$]*|(?:\d|\.\d)(?:[eEpP][+-]|[\w.])*|>>=|<<=|->\*|\.\.\.|##|::|->|\+\+|--|&&|\|\||==|!=|<=|>=|<<|>>|[+*/%&|^!-]=|[^\s]''')
FAMILIES = ('baseline', 'declaration-order', 'first-use-order', 'initialization-placement', 'named-intermediate',
            'reload-at-use', 'if-else-inversion', 'comparison-operand-order', 'zero-constant-uses')


def token_hash(preprocessed):
    # Compiler line markers encode paths, not source tokens. Pragmas stay significant.
    text = re.sub(r'^[ \t]*#[ \t]*(?:line[ \t]+)?\d+[^\n]*$', '', preprocessed, flags=re.M)
    clean = TOKEN.sub(lambda match: ' ' if match[0].startswith(('//', '/*')) else match[0], text)
    if re.search(r'^[ \t]*#[ \t]*(?:include|define|undef|if|ifdef|ifndef|elif|else|endif)\b', clean, re.M):
        raise ValueError('Deduplication requires compiler-preprocessed input, not raw source')
    tokens = TOKEN.findall(clean)
    return hashlib.sha256(json.dumps(tokens, ensure_ascii=True).encode()).hexdigest()


def tool_hash(inventory):
    tools = inventory.get('tools', [])
    if inventory.get('status') != 'captured' or not tools:
        raise ValueError('A captured compiler tool inventory is required')
    if any(not re.fullmatch('[0-9a-f]{64}', t.get('sha256', '')) for t in tools):
        raise ValueError('Every captured tool requires a SHA-256')
    identities = sorted((t['name'], t['sha256']) for t in tools)
    return hashlib.sha256(json.dumps(identities).encode()).hexdigest()


def read(path):
    path = Path(path)
    data = json.loads(path.read_text(encoding='utf-8')) if path.exists() else {
        'schema': 1, 'kind': 'aimcmp.honing-ledger', 'attempts': [], 'plateaus': []}
    if data.get('schema') != 1 or data.get('kind') != 'aimcmp.honing-ledger':
        raise ValueError('Unsupported honing ledger')
    return data


@contextmanager
def locked(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = path.with_name(path.name+'.lock')
    try:
        handle = lock.open('x')
    except FileExistsError as exc:
        raise ValueError('Honing ledger is in use; inspect any abandoned lock before retrying') from exc
    try:
        handle.close()
        data = read(path)
        yield data
        pending = path.with_name(path.name+'.pending')
        pending.write_text(json.dumps(data, indent=2)+'\n', encoding='utf-8')
        pending.replace(path)
    finally:
        lock.unlink()


def identity(function, original_sha256, flags, inventory, preprocessed):
    if not re.fullmatch('[0-9a-f]{64}', original_sha256):
        raise ValueError('Honing attempts require the pinned original hash')
    result = {'function': function, 'original_sha256': original_sha256, 'flags': flags,
              'toolchain_sha256': tool_hash(inventory), 'normalized_source_sha256': token_hash(preprocessed),
              'preprocessed_sha256': hashlib.sha256(preprocessed.encode()).hexdigest()}
    # Cosmetic changes do not affect identity; tool changes and flag order do.
    key = {k: v for k, v in result.items() if k != 'preprocessed_sha256'}
    result['key'] = hashlib.sha256(json.dumps(key, sort_keys=True).encode()).hexdigest()
    return result


def check(path, attempt):
    return next((row for row in read(path)['attempts'] if row['key'] == attempt['key']), None)


def record(path, attempt, hypothesis, family, outcome, report=None):
    if not hypothesis.strip() or family not in FAMILIES:
        raise ValueError('Attempt needs a stated hypothesis and a known mutation family')
    if outcome not in ('assessed', 'build-failed', 'untested'):
        raise ValueError('Outcome must be assessed, build-failed, or untested')
    if outcome == 'assessed' and not report:
        raise ValueError('Assessed attempts require a honing report')
    if report and (report['function']['id'] != attempt['function'] or
                   report['original_sha256'] != attempt['original_sha256']):
        raise ValueError('Attempt and report identify different original functions')
    with locked(path) as ledger:
        duplicate = next((r for r in ledger['attempts'] if r['key'] == attempt['key']), None)
        if duplicate:
            return {'duplicate': True, 'attempt': duplicate}
        item = dict(attempt, hypothesis=hypothesis, family=family, outcome=outcome,
                    time=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    toolchain_scope='Captured tool binaries; preprocessed translation-unit tokens capture included source.',
                    provenance='Assessment supplied by caller; a report hash alone does not prove source-to-artifact correspondence.',
                    assessment=report['comparison'] if outcome == 'assessed' else None,
                    report_sha256=hashlib.sha256(json.dumps(report, sort_keys=True).encode()).hexdigest() if report else None)
        ledger['attempts'].append(item)
    return {'duplicate': False, 'attempt': item}


def plateau(path, function, original_sha256, reason, classification, families):
    if not reason.strip() or not classification.strip() or not families:
        raise ValueError('Stopping requires a reason, remaining classification, and tried families')
    with locked(path) as ledger:
        attempts = [a for a in ledger['attempts'] if a['function'] == function and
                    a['original_sha256'] == original_sha256]
        tried = {a['family'] for a in attempts if a['outcome'] != 'untested' and a['family'] != 'baseline'}
        if not set(families) <= tried:
            raise ValueError('Plateau cites mutation families without recorded attempts')
        entry = {'function': function, 'original_sha256': original_sha256, 'reason': reason,
                 'classification': classification, 'families': families,
                 'attempt_keys': [a['key'] for a in attempts],
                 'time': datetime.datetime.now(datetime.timezone.utc).isoformat()}
        ledger['plateaus'].append(entry)
    return entry
