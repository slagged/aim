"""Runs inside the BN service against a workbench-owned view.

These measurements describe decompiler output, not recovered-source correctness.
Keep their definitions stable between the baseline and annotated runs.
"""
import json
import binaryninja as bn


METRICS = {
    'unresolved_stack_nodes': 'Nodes in BN unresolved_stack_adjustment_graph; absent graph means zero.',
    'hlil_variables': 'Distinct variables reported by the function HLIL.',
    'conversions': 'HLIL_SX, ZX, LOW_PART, FLOAT_TO_INT and INT_TO_FLOAT expression nodes. BN has no dedicated HLIL_CAST operation; these are not rendered cast counts.',
    'gotos': 'HLIL_GOTO nodes in the expression tree.',
    'contract_argument_mismatches': 'Resolved import calls whose HLIL parameter count differs from the ledger physical prototype, including explicit this and hidden result.',
    'contract_calls': 'Resolved import calls checked against a ledger physical prototype; denominator for argument mismatches.',
    'direct_result_type_divergences': 'Direct call assignments/initializers whose destination type string differs from the declared return type. A diagnostic, not proof of an error.',
}


def walk(node):
    if isinstance(node, bn.HighLevelILInstruction):
        yield node
        for operand in node.operands:
            yield from walk(operand)
    elif isinstance(node, (list, tuple)):
        for operand in node:
            yield from walk(operand)


def collect(view, selection_json):
    selection = json.loads(selection_json)
    addresses = selection['addresses']
    expected_counts = selection['expected_counts']
    import_addresses = selection['import_addresses']
    rows = []
    for address in addresses:
        function = view.get_function_at(address)
        row = {'address': address, 'metrics': None, 'error': None}
        try:
            if function is None:
                raise ValueError('Not an analyzed function start')
            il = function.hlil
            nodes = list(walk(il.root))
            graph = function.unresolved_stack_adjustment_graph
            calls, divergences = [], []
            for node in nodes:
                if node.operation.name in ('HLIL_CALL', 'HLIL_TAILCALL'):
                    destination = node.dest
                    target = (int(destination.operands[0]) if destination.operation.name in
                              ('HLIL_IMPORT', 'HLIL_CONST_PTR') else None)
                    expected = expected_counts.get(str(target))
                    calls.append({'address': int(node.address), 'target': target,
                                  'expression': str(node), 'recovered_arguments': len(node.params),
                                  'expected_arguments': expected,
                                  'argument_mismatch': expected is not None and expected != len(node.params)})
                if node.operation.name in ('HLIL_VAR_INIT', 'HLIL_ASSIGN'):
                    source = node.src
                    if source.operation.name != 'HLIL_CALL':
                        continue
                    destination_type = source.dest.expr_type
                    if destination_type.type_class == bn.TypeClass.PointerTypeClass:
                        destination_type = destination_type.target
                    if destination_type.type_class != bn.TypeClass.FunctionTypeClass:
                        continue
                    actual = str(node.dest.type if node.operation.name == 'HLIL_VAR_INIT' else node.dest.expr_type)
                    declared = str(destination_type.return_value)
                    if actual != declared:
                        divergences.append({'address': int(node.address), 'destination_type': actual,
                                            'declared_return_type': declared, 'expression': str(node)})
            row.update(name=str(function.name), type=str(function.type),
                       hlil=[str(line) for line in il.root.lines], calls=calls,
                       result_type_divergences=divergences,
                       metrics={'unresolved_stack_nodes': len(list(graph.nodes)) if graph else 0,
                                'hlil_variables': len(list(il.vars)),
                                'conversions': sum(n.operation.name in ('HLIL_SX', 'HLIL_ZX', 'HLIL_LOW_PART',
                                                                       'HLIL_FLOAT_TO_INT', 'HLIL_INT_TO_FLOAT') for n in nodes),
                                'gotos': sum(n.operation.name == 'HLIL_GOTO' for n in nodes),
                                'contract_argument_mismatches': sum(c['argument_mismatch'] for c in calls),
                                'contract_calls': sum(c['expected_arguments'] is not None for c in calls),
                                'direct_result_type_divergences': len(divergences)})
        except Exception as exc:
            row['error'] = str(exc)
        rows.append(row)
    imports = []
    for address in import_addresses:
        variable = view.get_data_var_at(address)
        symbol = view.get_symbol_at(address)
        imports.append({'address': address, 'name': str(symbol.raw_name) if symbol else None,
                        'type': str(variable.type) if variable else None})
    return json.dumps({'functions': rows, 'imports': imports,
                       'type_libraries': [str(lib.name) for lib in view.type_libraries]})
