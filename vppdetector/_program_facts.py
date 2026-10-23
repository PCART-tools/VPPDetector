"""Shared source-matched fact readers; domain policy stays with each consumer."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

from ._creation_metadata import _observer, creation_metadata_premises
from .models import FunctionIdentity, SourceSpan


def capture_names(node, enclosing):
    """Use shared relay facts, retaining a diagnostic fallback for older dependencies."""

    try:
        from pcresolve.scope_facts import transitive_captured_names
    except ImportError:
        from pcresolve.scope_facts import captured_names, function_scope_facts

        return captured_names(function_scope_facts(node), enclosing)
    return transitive_captured_names(node, enclosing)


def immediate_body(node):
    """A synchronous named function call executes its body only if it is not a generator."""

    if not isinstance(node, ast.FunctionDef):
        return False
    pending = list(node.body)
    while pending:
        child = pending.pop()
        if isinstance(child, (ast.Yield, ast.YieldFrom)):
            return False
        if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            pending.extend(ast.iter_child_nodes(child))
    return True


def scalar_truth_protocol(analysis, call):
    """Validate the producer's bool model, whose exact input is a query obligation."""
    fact = getattr(call, 'implicit_protocol', {})
    if (not isinstance(fact, dict) or fact.get('kind') != 'builtin_scalar_truth'
            or fact.get('builtin') != 'bool' or call.callee_name != 'bool'
            or call.target is not None or call.target_status != 'python_protocol'
            or call.binding_status != 'complete' or call.binding_issues or call.effects
            or fact.get('status') != 'requires_exact_input'
            or fact.get('runtime_input_confirmed') is not False
            or fact.get('precondition') != {'argument': {'position': 0},
                'exact_types': ['NoneType', 'bool', 'int', 'float', 'str', 'bytes']}
            or fact.get('completion') != 'normal_return_if_precondition'
            or fact.get('effects') != 'none_if_precondition'
            or fact.get('call_id') != call.id
            or fact.get('source_hash') != analysis.inputs.get('sha256', {}).get(
                call.caller.file_path)
            or not isinstance(fact.get('evidence'), dict)
            or fact['evidence'].get('file_path') != call.caller.file_path
            or _location(fact['evidence']) != (call.lineno, call.col_offset,
                                              call.end_lineno, call.end_col_offset)
            or any(item.get('implicit_protocol') != fact
                   for item in getattr(call, 'analysis_contexts', ()))):
        return None
    return fact


def exact_callability_protocol(analysis, call):
    """Read callability only for exact noncallable builtin input types."""
    fact = getattr(call, 'implicit_protocol', {})
    if (not isinstance(fact, dict) or fact.get('kind') != 'builtin_exact_callability'
            or fact.get('builtin') != 'callable' or call.callee_name != 'callable'
            or call.target is not None or call.target_status != 'python_protocol'
            or call.binding_status != 'complete' or call.binding_issues or call.effects
            or fact.get('status') != 'requires_exact_input'
            or fact.get('runtime_input_confirmed') is not False
            or fact.get('precondition') != {'argument': {'position': 0}, 'exact_types': [
                'NoneType', 'bool', 'int', 'float', 'str', 'bytes',
                'dict', 'list', 'tuple', 'set', 'frozenset']}
            or fact.get('result') is not False
            or fact.get('dependency') != 'input_object_type_only'
            or fact.get('completion') != 'normal_return_if_precondition'
            or fact.get('effects') != 'none_if_precondition'
            or fact.get('call_id') != call.id
            or fact.get('source_hash') != analysis.inputs.get('sha256', {}).get(
                call.caller.file_path)
            or not isinstance(fact.get('evidence'), dict)
            or fact['evidence'].get('file_path') != call.caller.file_path
            or _location(fact['evidence']) != (call.lineno, call.col_offset,
                                              call.end_lineno, call.end_col_offset)
            or any(item.get('implicit_protocol') != fact
                   for item in getattr(call, 'analysis_contexts', ()))):
        return None
    return fact


def container_length_protocol(analysis, call):
    """Read a length obligation; the consumer must establish the exact input type."""
    fact = getattr(call, 'implicit_protocol', {})
    if (not isinstance(fact, dict) or fact.get('kind') != 'builtin_container_length'
            or fact.get('builtin') != 'len' or call.callee_name != 'len'
            or call.target is not None or call.target_status != 'python_protocol'
            or call.binding_status != 'complete' or call.binding_issues or call.effects
            or fact.get('status') != 'requires_exact_input'
            or fact.get('runtime_input_confirmed') is not False
            or fact.get('precondition') != {'argument': {'position': 0},
                'exact_types': ['dict', 'list', 'tuple', 'str', 'bytes', 'set', 'frozenset']}
            or fact.get('completion') != 'normal_return_if_precondition'
            or fact.get('effects') != 'none_if_precondition'
            or fact.get('call_id') != call.id
            or fact.get('source_hash') != analysis.inputs.get('sha256', {}).get(
                call.caller.file_path)
            or not isinstance(fact.get('evidence'), dict)
            or fact['evidence'].get('file_path') != call.caller.file_path
            or _location(fact['evidence']) != (call.lineno, call.col_offset,
                                              call.end_lineno, call.end_col_offset)
            or any(item.get('implicit_protocol') != fact
                   for item in getattr(call, 'analysis_contexts', ()))):
        return None
    return fact


def source_alias_entry(analysis, requested):
    """Read a lexical API reference without claiming runtime attribute binding."""
    fact = analysis.inputs.get('entry_alias', {})
    if not isinstance(fact, dict):
        return None
    query = fact.get('requested', {})
    if not isinstance(query, dict):
        return None
    alias_target = fact.get('target')
    if (not isinstance(alias_target, dict)
            or not all(isinstance(alias_target.get(name), str)
                       for name in ('module', 'qualname', 'file_path'))
            or type(alias_target.get('lineno')) is not int
            or not isinstance(query.get('file_path', ''), str)):
        return None
    assignments = fact.get('assignments', ())
    target = identity_from_target(analysis.entry)
    if (fact.get('kind') != 'source_entry_alias' or fact.get('status') != 'source_reference'
            or fact.get('basis') != 'source_snapshot'
            or fact.get('scope') != 'definition_selection'
            or fact.get('runtime_target_confirmed') is not False
            or query.get('module') != requested.module
            or query.get('qualname') != requested.qualname
            or query.get('lineno', 0) != (requested.lineno or 0)
            or requested.file_path and Path(query.get('file_path', '')) != requested.file_path
            or identity_from_target(fact.get('target')) != target
            or fact.get('source_hashes') != analysis.inputs.get('sha256')
            or fact.get('assumptions') != ['source_snapshot_bindings_hold',
                'no_external_monkeypatch_or_import_hook', 'no_unmodeled_indirect_function_mutation']
            or not isinstance(fact.get('conditions'), (list, tuple))
            or len(fact['conditions']) > 128
            or any(not isinstance(condition, dict) for condition in fact['conditions'])
            or not isinstance(assignments, (list, tuple))
            or not 1 <= len(assignments) <= 64):
        return None
    previous = target.qualname.rsplit('.', 1)[-1]
    for assignment in assignments:
        if not isinstance(assignment, dict) or assignment.get('source_name') != previous:
            return None
        evidence = assignment.get('evidence', {})
        if (not isinstance(evidence, dict)
                or evidence.get('file_path') not in fact['source_hashes']
                or Path(evidence['file_path']) != target.file_path
                or not isinstance(assignment.get('name'), str)
                or not all(type(value) is int for value in _location(evidence))):
            return None
        previous = assignment['name']
    if previous != requested.qualname.rsplit('.', 1)[-1]:
        return None
    activation = [boundary.get('conditions', ()) for boundary in analysis.boundaries
                  if boundary.get('reason') == 'conditional_definition_unconfirmed'
                  and identity_from_target(boundary.get('function')) == target]
    if (fact['conditions'] and fact['conditions'] not in activation
            or any(conditions != fact['conditions'] for conditions in activation)):
        return None
    if not any(boundary.get('reason') == 'source_entry_alias'
               and identity_from_target(boundary.get('function')) == target
               and boundary.get('assumptions') == fact['assumptions']
               for boundary in analysis.boundaries):
        return None
    return fact


def _location(value):
    return tuple(value.get(name) for name in (
        'lineno', 'col_offset', 'end_lineno', 'end_col_offset',
    ))


def _node_location(node):
    return (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)


def _expression(text):
    if not isinstance(text, str) or len(text) > 4096:
        return None
    try:
        node = ast.parse(text, mode='eval').body
        return node if sum(1 for _ in ast.walk(node)) <= 128 else None
    except (SyntaxError, ValueError, RecursionError):
        return None


def copy_protocol_target(owner, analysis, call, value) -> Optional[FunctionIdentity]:
    """Check an exact copy edge, its output object and its indexed source witness."""

    obj = value.get('container_object', {})
    results = call.result_sources
    if not (
        call.target_status == 'local_container_protocol'
        and call.analysis_status == 'analyzed'
        and CallFacts(analysis, call).complete_binding
        and not call.target
        and not call.target_candidates
        and value.get('kind') == 'call_result'
        and value.get('source') == call.id
        and value.get('object_only')
        and value.get('relation') == 'direct'
        and not any(value.get(flag) for flag in ('value_incomplete', 'projection', 'output_path'))
        and len(results) == 1
        and results[0].get('kind') == 'call_result'
        and results[0].get('relation') == 'direct'
        and not any(results[0].get(flag) for flag in (
            'value_incomplete', 'projection', 'output_path',
        ))
        and results[0].get('object_only')
        and results[0].get('source') == call.id
        and results[0].get('container_object') == obj
        and obj.get('source') and obj.get('copied_from')
        and obj.get('container_shape') in {'dict', 'list', 'tuple'}
        and obj.get('identity') in {'shallow_copy', 'argument_alias'}
        and len(call.effects) == 1
    ):
        return None
    effect = call.effects[0]
    if not (
        effect.get('kind') == 'container_copy'
        and effect.get('operation') == 'copy'
        and effect.get('status') == 'bounded'
        and effect.get('completion') == 'normal_return'
        and effect.get('input_container') == obj['copied_from']
        and effect.get('output_container') == obj['source']
        and effect.get('container_shape') == obj['container_shape']
        and effect.get('identity') == obj['identity']
        and (obj['identity'] != 'shallow_copy' or obj['source'] != obj['copied_from'])
        and (obj['identity'] != 'argument_alias' or (
            obj['container_shape'] == 'tuple' and obj['source'] == obj['copied_from']))
        and not any(b.get('call_id') == call.id and b.get('reason') not in {'depth_limit'}
                    for b in analysis.boundaries)
    ):
        return None
    witness = effect.get('evidence', {})
    node = _expression(witness.get('source_text'))
    location = (call.lineno, call.col_offset, call.end_lineno, call.end_col_offset)
    if (not isinstance(node, ast.Call) or _location(witness) != location
            or Path(witness.get('file_path', '')) != owner.identity.file_path
            or ast.unparse(node.func) != call.callee_name
            or not any(isinstance(source, ast.Call) and _node_location(source) == location
                       and ast.dump(source) == ast.dump(node) for source in ast.walk(owner.node))):
        return None
    if (isinstance(node.func, ast.Attribute) and node.func.attr == 'copy'
            and obj['container_shape'] == 'dict' and not node.args and not node.keywords):
        return FunctionIdentity('builtins', 'dict.copy')
    if (isinstance(node.func, ast.Name) and node.func.id == obj['container_shape']
            and len(node.args) == 1 and not isinstance(node.args[0], ast.Starred)
            and not node.keywords):
        return FunctionIdentity('builtins', node.func.id)
    return None


def mapping_protocol(owner, analysis, call, operation, key=None) -> bool:
    """Validate bounded PCResolve facts for exact builtin mapping operations."""
    if (operation not in ('clear', 'get', 'setdefault')
            or analysis.inputs.get('conditional_source_state')
            or call.target_status != 'local_container_protocol'
            or call.analysis_status != 'analyzed' or call.target or call.target_candidates
            or not CallFacts(analysis, call).complete_binding
            or identity_from_target(call.caller) != owner.identity
            or str(owner.identity.file_path) not in analysis.inputs.get('sha256', {})
            or not call.receiver_sources
            or any(not isinstance(value, dict) for value in call.receiver_sources)
            or any(not isinstance(value, dict) for value in call.result_sources + call.effects)
            or any(not isinstance(value.get('kind'), str)
                   or not isinstance(value.get('source'), str)
                   for value in call.receiver_sources)
            or any(value.get(flag) for value in call.receiver_sources for flag in (
                'value_incomplete', 'import_incomplete', 'import_modified'))
            or (operation != 'setdefault' and any(
                value.get('projection') for value in call.receiver_sources))
            or any(b.get('call_id') == call.id and b.get('reason') not in {'depth_limit'}
                   for b in analysis.boundaries)
            or any(not isinstance(item, dict)
                   or any(item.get(field) != getattr(call, field) for field in (
                       'effects', 'result_sources', 'binding_status', 'target_status'))
                   for item in getattr(call, 'analysis_contexts', ()))):
        return False
    location = (call.lineno, call.col_offset, call.end_lineno, call.end_col_offset)
    nodes = [node for node in ast.walk(owner.node)
             if isinstance(node, ast.Call) and _node_location(node) == location]
    if len(nodes) != 1:
        return False
    node = nodes[0]
    if (not isinstance(node.func, ast.Attribute) or node.func.attr != operation
            or ast.unparse(node.func) != call.callee_name or node.keywords):
        return False

    def witness(evidence):
        parsed = _expression(evidence.get('source_text')) if isinstance(evidence, dict) else None
        return (isinstance(parsed, ast.Call) and ast.dump(parsed) == ast.dump(node)
                and evidence.get('file_path') == call.caller.file_path
                and _location(evidence) == location)

    if operation == 'clear':
        if node.args or len(call.effects) != 1 or call.result_sources:
            return False
        effect = call.effects[0]
        objects = [value['container_object'].get('source') for value in call.receiver_sources
                   if isinstance(value.get('container_object'), dict)]
        if not objects:
            objects = ['$parameter:{}:{}:{}'.format(call.caller.file_path,
                       call.caller.qualname, value['source']) for value in call.receiver_sources
                       if value.get('kind') == 'parameter' and value.get('source')
                       and value.get('output_path') == ['*']]
        return (effect.get('kind') == 'container_clear' and effect.get('operation') == 'clear'
                and effect.get('status') == 'exact' and effect.get('completion') == 'normal_return'
                and effect.get('element_path') == [] and bool(objects)
                and effect.get('object_sources') == list(dict.fromkeys(objects))
                and isinstance(effect.get('conditions'), (list, tuple))
                and consistent_conditions(effect['conditions']) and witness(effect.get('evidence')))
    if operation == 'setdefault':
        kwarg = owner.node.args.kwarg
        if (kwarg is None or not isinstance(node.func.value, ast.Name)
                or node.func.value.id != kwarg.arg or not isinstance(key, str)
                or not isinstance(node.args[0], ast.Constant)
                or type(node.args[0].value) is not str or node.args[0].value != key
                or len(node.args) not in (1, 2)
                or len(call.effects) != 1):
            return False
        parameter_name = kwarg.arg
        object_source = '$parameter:{}:{}:{}'.format(
            call.caller.file_path, owner.identity.qualname, parameter_name)
        effect = call.effects[0]
        mapping_roots = effect.get('mapping')
        parameter_location = (kwarg.lineno, kwarg.col_offset,
                              kwarg.end_lineno, kwarg.end_col_offset)

        def receiver_witness(evidence):
            parsed = (_expression(evidence.get('source_text'))
                      if isinstance(evidence, dict) else None)
            return (isinstance(parsed, ast.Name)
                    and parsed.id == parameter_name
                    and evidence.get('file_path') == call.caller.file_path
                    and _location(evidence) == parameter_location)

        direct_results = [value for value in call.result_sources
                          if value.get('kind') == 'call_result'
                          and value.get('relation') == 'direct'
                          and value.get('object_only') is True]
        receiver_parameters = [value for value in call.receiver_sources
                               if value.get('kind') == 'parameter'
                               and value.get('source') == parameter_name]
        return (
            effect.get('kind') == 'mapping_element'
            and effect.get('operation') == 'setdefault'
            and effect.get('object_source') == object_source
            and effect.get('element_path') == [key]
            and effect.get('status') == 'bounded'
            and effect.get('completion') == 'normal_return'
            and effect.get('state_before') in {'present', 'absent', 'unknown'}
            and effect.get('insertion') in {'never', 'always', 'conditional'}
            and isinstance(effect.get('conditions'), (list, tuple))
            and consistent_conditions(effect['conditions'])
            and witness(effect.get('evidence'))
            and bool(direct_results)
            and any(isinstance(value.get('evidence'), (list, tuple))
                    and any(witness(evidence) for evidence in value['evidence'])
                    for value in direct_results)
            and isinstance(mapping_roots, (list, tuple))
            and any(isinstance(value, dict)
                    and value.get('kind') == 'parameter'
                    and value.get('name') == parameter_name
                    for value in mapping_roots)
            and bool(receiver_parameters)
            and all(isinstance(value.get('output_path'), (list, tuple))
                    and bool(value['output_path'])
                    and all(isinstance(part, str) for part in value['output_path'])
                    and (not value.get('projection')
                         or value.get('projection') == value.get('output_path'))
                    and not any(value.get(flag) for flag in (
                        'value_incomplete', 'import_incomplete', 'import_modified'))
                    and isinstance(value.get('evidence'), (list, tuple))
                    and any(receiver_witness(evidence) for evidence in value['evidence'])
                    for value in receiver_parameters)
            and all(value in receiver_parameters or value.get('relation') == 'contained'
                    for value in call.receiver_sources)
        )
    if (len(node.args) not in (1, 2) or not isinstance(node.args[0], ast.Constant)
            or type(node.args[0].value) is not str or node.args[0].value != key or call.effects):
        return False
    receivers = {(value.get('kind'), value.get('source')) for value in call.receiver_sources}
    return any(isinstance(value.get('kind'), str) and isinstance(value.get('source'), str)
               and value.get('projection') == [key]
               and (value.get('kind'), value.get('source')) in receivers
               and not value.get('value_incomplete')
               and isinstance(value.get('evidence'), (list, tuple))
               and any(witness(evidence) for evidence in value['evidence'])
               for value in call.result_sources)


def _constant_truth(node, depth=0):
    if depth > 16:
        return None
    if isinstance(node, ast.Constant) and type(node.value) in (
        str, bytes, int, float, bool, type(None),
    ):
        return bool(node.value)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        truth = _constant_truth(node.operand, depth + 1)
        return not truth if truth is not None else None
    if isinstance(node, ast.BoolOp):
        values = [_constant_truth(value, depth + 1) for value in node.values]
        decisive = isinstance(node.op, ast.Or)
        if decisive in values:
            return decisive
        if all(value is not None for value in values):
            return not decisive
    return None


def conditions_possible(context, value) -> bool:
    """Prune only a recorded branch contradicted by matching constant source syntax."""

    for condition in value.get('conditions', ()):
        branch = condition.get('branch')
        witness = condition.get('test', {})
        if type(branch) is not bool or not isinstance(witness, dict):
            continue
        path = Path(witness.get('file_path', ''))
        if path not in context._constant_tests:
            tests = {}
            roots = [function.node for function in context.index.functions
                     if function.identity.file_path == path]
            roots.extend(context.index.condition_nodes.get(path, ()))
            for root in roots:
                for node in ast.walk(root):
                    if not isinstance(node, (ast.Constant, ast.UnaryOp, ast.BoolOp)):
                        continue
                    truth = _constant_truth(node)
                    if truth is not None:
                        tests[_node_location(node)] = (truth, ast.dump(node))
            context._constant_tests[path] = tests
        test = context._constant_tests[path].get(_location(witness))
        if test is None or test[0] == branch:
            continue
        node = _expression(witness.get('source_text'))
        if node is not None and ast.dump(node) == test[1]:
            return False
    return True


def identity_from_target(target: Any) -> FunctionIdentity:
    def value(name: str, default: Any) -> Any:
        if isinstance(target, dict):
            return target.get(name, default)
        return getattr(target, name, default)

    path = value("file_path", "")
    return FunctionIdentity(
        module=value("module", ""),
        qualname=value("qualname", ""),
        file_path=Path(path) if path else None,
        lineno=value("lineno", 0) or None,
    )


def candidate_identities(call: Any) -> tuple[FunctionIdentity, ...]:
    result = []
    for candidate in getattr(call, "target_candidates", ()):
        identity = identity_from_target(candidate)
        if identity not in result:
            result.append(identity)
    return tuple(result)


def direct_calls(analysis: Any, caller: FunctionIdentity) -> Iterable[Any]:
    for call in analysis.calls:
        owner = identity_from_target(call.caller)
        if (
            owner.module == caller.module
            and owner.qualname == caller.qualname
            and (not caller.lineno or owner.lineno == caller.lineno)
            and (not caller.file_path or owner.file_path == caller.file_path)
        ):
            yield call


def call_span(call: Any) -> SourceSpan:
    return SourceSpan(
        file_path=Path(call.caller.file_path or ""),
        lineno=call.lineno,
        col_offset=call.col_offset,
        end_lineno=call.end_lineno or call.lineno,
        end_col_offset=call.end_col_offset or call.col_offset,
    )


def target_status(analysis: Any, call: Any) -> str:
    if getattr(call, 'conditional_source_bindings', ()):
        return 'conditional_source_candidate'
    if call.target_status != "resolved":
        return call.target_status
    if any(
        boundary.get("call_id") == call.id
        and boundary.get("reason", "").startswith("dynamic_")
        and boundary.get("reason") != "dynamic_argument_expansion"
        for boundary in analysis.boundaries
    ):
        return "source_candidate"
    return "resolved"


def _class_name_premise(analysis: Any, effect: dict) -> bool:
    basis = effect.get("name_basis")
    if basis is None:
        return "name_metadata" not in effect and "name_evidence" not in effect
    metadata = effect.get("name_metadata")
    if basis != "source_class_metadata" or not isinstance(metadata, dict):
        return False
    receiver, literal = metadata.get("receiver_class"), metadata.get("literal")
    hashes, assumptions = metadata.get("source_hashes"), metadata.get("assumptions")
    required = {"source_snapshot_bindings_hold", "builtin_type_name_metadata",
                "source_snapshot_class_name_binding_holds",
                "no_external_monkeypatch_or_import_hook",
                "no_unmodeled_indirect_class_mutation"}
    evidence = effect.get("name_evidence")
    return (
        metadata.get("kind") == "class_name_literal" and metadata.get("status") == "source_bound"
        and metadata.get("basis") == "source_snapshot" and metadata.get("attribute") == "__name__"
        and metadata.get("value_phase") == "call_entry"
        and metadata.get("runtime_value_confirmed") is False
        and metadata.get("source_scope") == "analysis_source_snapshot"
        and isinstance(metadata.get("issues"), (list, tuple)) and not metadata["issues"]
        and isinstance(receiver, dict) and receiver == effect.get("receiver_class")
        and isinstance(receiver.get("qualname"), str) and bool(receiver["qualname"])
        and isinstance(literal, dict) and literal.get("type") == "str"
        and type(literal.get("value")) is str
        and literal["value"] == receiver["qualname"].rsplit(".", 1)[-1]
        and metadata.get("target") == effect.get("target")
        and metadata.get("parameter") == effect.get("parameter")
        and isinstance(metadata.get("call_id"), str) and bool(metadata["call_id"])
        and metadata["call_id"] == effect.get("call_id")
        and isinstance(assumptions, (list, tuple))
        and all(isinstance(item, str) for item in assumptions) and required.issubset(assumptions)
        and isinstance(hashes, dict) and bool(hashes)
        and hashes == analysis.inputs.get("sha256")
        and all(effect["source_hashes"].get(path) == digest for path, digest in hashes.items())
        and isinstance(evidence, (list, tuple)) and bool(evidence)
        and all(isinstance(item, dict)
                and item.get("file_path") == effect["target"].get("file_path")
                for item in evidence)
    )


def _class_read_premises(analysis: Any, effect: dict) -> bool:
    basis = effect.get("read_basis")
    if basis is None:
        return "read_premises" not in effect and "read_evidence" not in effect
    premises, evidence = effect.get("read_premises"), effect.get("read_evidence")
    if (basis != "source_class_attribute_invariant"
            or not isinstance(premises, (list, tuple)) or not 1 <= len(premises) <= 2000
            or not isinstance(evidence, (list, tuple)) or not 1 <= len(evidence) <= 2000):
        return False
    required = {"source_snapshot_bindings_hold", "builtin_type_attribute_reads",
                "source_snapshot_class_attribute_invariant",
                "no_external_monkeypatch_or_import_hook",
                "no_unmodeled_indirect_class_mutation"}
    attributes = set()
    for premise in premises:
        if not isinstance(premise, dict):
            return False
        name, hashes, claims = (premise.get("attribute"), premise.get("source_hashes"),
                               premise.get("assumptions"))
        if (premise.get("kind") != "class_attribute_read_invariant"
                or premise.get("status") != "source_bound"
                or premise.get("basis") != "source_snapshot"
                or premise.get("state") != "absent_or_builtin_literal"
                or premise.get("value_phase") != "call_entry"
                or premise.get("runtime_value_confirmed") is not False
                or premise.get("source_scope") != "analysis_source_snapshot"
                or not isinstance(premise.get("issues"), (list, tuple)) or premise["issues"]
                or not isinstance(name, str) or not name or len(name) > 2000
                or name == "mro" or name.startswith("__") and name.endswith("__")
                or name in attributes
                or any(premise.get(key) != effect.get(key)
                       for key in ("receiver_class", "target", "parameter",
                                   "call_id", "call_evidence"))
                or not isinstance(premise.get("call_id"), str) or not premise["call_id"]
                or not isinstance(claims, (list, tuple))
                or not all(isinstance(claim, str) for claim in claims)
                or not required.issubset(claims)
                or not isinstance(hashes, dict) or not hashes
                or hashes != analysis.inputs.get("sha256")
                or any(effect["source_hashes"].get(path) != digest
                       for path, digest in hashes.items())
                or not isinstance(premise.get("evidence"), (list, tuple)) or not premise["evidence"]
                or any(not isinstance(source, dict) or source.get("file_path") not in hashes
                       for source in premise["evidence"])):
            return False
        attributes.add(name)
    witnessed = set()
    for item in evidence:
        if (not isinstance(item, dict) or item.get("operation") != "hasattr"
                or not isinstance(item.get("attribute"), str) or item["attribute"] not in attributes
                or not isinstance(item.get("evidence"), dict)
                or item["evidence"].get("file_path") != effect["target"].get("file_path")):
            return False
        witnessed.add(item["attribute"])
    return witnessed == attributes


def _class_lookup_preserved(analysis: Any, call: Any, binding: dict) -> bool:
    observed = []
    for value in call.receiver_sources:
        effects = value.get("class_lookup_mutations", ())
        if not isinstance(effects, (list, tuple)):
            return False
        for effect in effects:
            if effect not in observed:
                observed.append(effect)
    preserved = binding.get("lookup_preservation", ())
    if not isinstance(preserved, (list, tuple)) or list(preserved) != observed:
        return False
    if not observed:
        return True
    hierarchy = binding.get("lookup_hierarchy")
    if (not isinstance(hierarchy, (list, tuple)) or not 1 <= len(hierarchy) <= 64
            or hierarchy[0] != binding.get("receiver_class")
            or any(not isinstance(owner, dict) or owner.get("file_path") not in
                   binding["source_hashes"] for owner in hierarchy)):
        return False
    assumptions = {"source_snapshot_bindings_hold", "builtin_type_attribute_writes",
                   "no_external_monkeypatch_or_import_hook",
                   "no_unmodeled_indirect_class_mutation"}
    attribute = call.callee_name.rsplit(".", 1)[-1]
    for effect in observed:
        if not isinstance(effect, dict):
            return False
        names, hashes, claims = (effect.get("attributes"), effect.get("source_hashes"),
                                  effect.get("assumptions"))
        if (effect.get("kind") != "class_attribute_write_set" or effect.get("status") != "bounded"
                or effect.get("preserved_scope") != "other_class_attributes"
                or effect.get("completion") != "normal_return"
                or effect.get("value_completeness") != "unmodeled"
                or effect.get("receiver_class") not in hierarchy
                or not isinstance(names, (list, tuple)) or len(names) > 2000
                or any(not isinstance(name, str) or name in (attribute, "mro")
                       or name.startswith("__") and name.endswith("__") for name in names)
                or not isinstance(hashes, dict) or not hashes
                or not isinstance(effect.get("target"), dict)
                or effect["target"].get("file_path") not in hashes
                or not isinstance(claims, (list, tuple))
                or not all(isinstance(claim, str) for claim in claims)
                or not assumptions.issubset(claims)
                or any(binding["source_hashes"].get(path) != digest
                       or analysis.inputs.get("sha256", {}).get(path) != digest
                       for path, digest in hashes.items())):
            return False
        if not _class_name_premise(analysis, effect) or not _class_read_premises(analysis, effect):
            return False
    return True


def source_classmethod_binding(analysis: Any, call: Any) -> Optional[dict]:
    """Read a source binding proof tied to this call and every incoming context."""

    if (analysis.inputs.get('conditional_source_state')
            or getattr(call, 'conditional_source_bindings', ())):
        return None
    bindings = getattr(call, "class_method_bindings", ())
    if (not isinstance(bindings, (list, tuple)) or call.target_status != "classmethod"
            or call.target is None or len(bindings) != 1):
        return None
    binding = bindings[0]
    if (not isinstance(binding, dict)
            or not isinstance(binding.get("descriptor"), dict)
            or not isinstance(binding.get("implicit_binding"), dict)
            or not isinstance(binding.get("source_hashes"), dict)):
        return None
    receiver_boundaries = [boundary for boundary in analysis.boundaries
        if boundary.get("call_id") == call.id
        and boundary.get("reason") == "dynamic_class_receiver_override_possible"]
    hashes = binding.get("source_hashes", {})
    valid = (
        binding.get("status") == "source_bound"
        and binding.get("basis") == "source_snapshot"
        and not binding.get("issues")
        and binding.get("runtime_target_confirmed") is False
        and binding.get("target") is not None
        and identity_from_target(binding["target"]) == identity_from_target(call.target)
        and binding.get("descriptor", {}).get("kind") == "builtin_classmethod"
        and binding.get("implicit_binding", {}).get("status") == "static_bound"
        and binding.get("implicit_binding", {}).get("receiver_class")
        == binding.get("receiver_class")
        and bool(hashes)
        and all(analysis.inputs.get("sha256", {}).get(path) == digest
                for path, digest in hashes.items())
        and _class_lookup_preserved(analysis, call, binding)
        and bool(receiver_boundaries)
        and all(boundary.get("boundary_kind") == "assumption"
                and boundary.get("binding_status") == "source_bound"
                for boundary in receiver_boundaries)
        and all(isinstance(incoming, dict) and incoming.get("target") == binding["target"]
                and incoming.get("class_method_bindings") == bindings
                for incoming in getattr(call, "analysis_contexts", ())))
    return binding if valid else None


def conditional_source_binding(analysis: Any, call: Any) -> Optional[dict]:
    """Read an explicit lookup requirement without promoting it to a binding proof."""
    facts = getattr(call, 'conditional_source_bindings', ())
    if (analysis.inputs.get('conditional_source_state') is not True
            or call.target is None or call.analysis_status != 'analyzed'
            or not isinstance(facts, (list, tuple)) or len(facts) != 1
            or call.target_status not in ('super_new', 'super_method', 'classmethod')):
        return None
    fact = facts[0]
    expected = []
    for value in call.receiver_sources:
        identity = value.get('class_type')
        if identity and identity not in expected:
            expected.append(identity)
    if (not isinstance(fact, dict) or fact.get('kind') != 'conditional_source_lookup'
            or fact.get('status') != 'required' or fact.get('runtime_target_confirmed') is not False
            or fact.get('feasibility') != 'not_proven' or fact.get('call_id') != call.id
            or identity_from_target(fact.get('target')) != identity_from_target(call.target)
            or fact.get('source_hashes') != analysis.inputs.get('sha256')
            or not isinstance(fact.get('call_evidence'), dict)
            or _location(fact['call_evidence']) != (call.lineno, call.col_offset,
                                                   call.end_lineno, call.end_col_offset)
            or fact['call_evidence'].get('file_path') != call.caller.file_path
            or fact.get('conditions') != getattr(call, 'conditions', ())
            or fact.get('receiver_classes') != expected or not expected):
        return None
    conditions = fact.get('conditions', ())
    if (not isinstance(conditions, (list, tuple)) or not 1 <= len(conditions) <= 128
            or any(not isinstance(condition, dict) for condition in conditions)
            or any(incoming.get('conditional_source_bindings') != facts
                   for incoming in getattr(call, 'analysis_contexts', ()))):
        return None
    required = [condition for condition in conditions
                if condition.get('kind') == 'source_state_preserved']
    if not required:
        return None
    for condition in required:
        evidence = condition.get('evidence')
        if (condition.get('status') != 'required' or condition.get('runtime_confirmed') is not False
                or condition.get('scope') != 'subsequent_source_lookup'
                or condition.get('feasibility') != 'not_proven'
                or condition.get('receiver_class') not in fact['receiver_classes']
                or not isinstance(condition.get('effect_target'), dict)
                or condition['effect_target'].get('file_path') not in fact['source_hashes']
                or not isinstance(evidence, dict)
                or evidence.get('file_path') not in fact['source_hashes']
                or not all(type(value) is int for value in _location(evidence))
                or condition.get('effect_call') != '{}:{}:{}:{}:{}'.format(
                    evidence['file_path'], *_location(evidence))):
            return None
    return fact


def conditional_constructor_signature(analysis: Any, call: Any) -> Optional[dict]:
    """Read a conditional signature reference; it never authorizes body execution."""
    facts = getattr(call, 'conditional_source_bindings', ())
    ordinary = getattr(call, 'constructor_bindings', ())
    if (analysis.inputs.get('conditional_source_state') is not True
            or call.target_status != 'constructor' or call.target is None
            or call.binding_status == 'invalid'
            or not isinstance(facts, (list, tuple)) or len(facts) != 1
            or not isinstance(ordinary, (list, tuple)) or len(ordinary) != 1):
        return None
    fact, binding = facts[0], ordinary[0]
    if not isinstance(fact, dict) or not isinstance(binding, dict):
        return None
    target, receiver = fact.get('target'), fact.get('receiver_class')
    conditions, assumptions = fact.get('conditions'), fact.get('assumptions')
    issues, evidence = fact.get('unconfirmed_binding_issues'), fact.get('call_evidence')
    required = {'source_snapshot_bindings_hold', 'builtin_type_call_and_new_binding',
                'no_external_monkeypatch_or_import_hook', 'no_unmodeled_indirect_class_mutation'}
    if (fact.get('kind') != 'conditional_constructor_signature'
            or fact.get('status') != 'required' or fact.get('scope') != 'signature_only'
            or fact.get('runtime_target_confirmed') is not False
            or fact.get('feasibility') != 'not_proven' or fact.get('call_id') != call.id
            or not isinstance(target, dict) or target != binding.get('target')
            or identity_from_target(target) != identity_from_target(call.target)
            or not isinstance(receiver, dict) or receiver != binding.get('receiver_class')
            or binding.get('status') != 'unconfirmed' or binding.get('phase') != '__init__'
            or not call.target.qualname.endswith('.__init__')
            or not isinstance(issues, (list, tuple)) or not issues
            or issues != binding.get('issues')
            or any(not isinstance(issue, dict) or issue.get('reason') not in (
                'constructor_class_origin_unconfirmed', 'constructor_namespace_unconfirmed',
                'constructor_definition_evaluation_unconfirmed') for issue in issues)
            or not isinstance(assumptions, (list, tuple))
            or not all(isinstance(value, str) for value in assumptions)
            or not required.issubset(assumptions) or assumptions != binding.get('assumptions')
            or not fact.get('source_hashes')
            or fact['source_hashes'] != analysis.inputs.get('sha256')
            or target.get('file_path') not in fact['source_hashes']
            or receiver.get('file_path') not in fact['source_hashes']
            or not isinstance(evidence, dict) or evidence.get('file_path') != call.caller.file_path
            or _location(evidence) != (call.lineno, call.col_offset,
                                       call.end_lineno, call.end_col_offset)
            or not isinstance(conditions, (list, tuple)) or not 1 <= len(conditions) <= 128
            or any(not isinstance(condition, dict) for condition in conditions)
            or conditions != getattr(call, 'conditions', ())):
        return None
    predicates = [c for c in conditions if c.get('kind') == 'source_constructor_lookup']
    if len(predicates) != 1:
        return None
    predicate = predicates[0]
    probes = predicate.get('preceding_type_checks')
    if (predicate.get('status') != 'required' or predicate.get('scope') != 'signature_only'
            or predicate.get('runtime_confirmed') is not False
            or predicate.get('feasibility') != 'not_proven'
            or predicate.get('target') != target or predicate.get('receiver_class') != receiver
            or not isinstance(probes, (list, tuple)) or not 1 <= len(probes) <= 128
            or not all(isinstance(probe, str) for probe in probes)
            or not consistent_conditions(conditions)):
        return None
    for probe_id in probes:
        matching = [prior for prior in analysis.calls if prior.id == probe_id]
        if len(matching) != 1:
            return None
        prior = matching[0]
        if (prior.caller != call.caller or prior.callee_name != 'isinstance'
                or prior.target_status != 'builtin_boundary' or prior.target is not None
                or (prior.lineno, prior.col_offset) >= (call.lineno, call.col_offset)
                or not any(arg.get('argument') == {'position': 1}
                           and any(v.get('class_type') == receiver for v in arg.get('sources', ()))
                           for arg in prior.argument_sources)):
            return None
    if (not any(b.get('reason') == 'conditional_constructor_signature'
                and b.get('call_id') == call.id and b.get('boundary_kind') == 'required_condition'
                and b.get('condition') == predicate for b in analysis.boundaries)
            or any(not isinstance(item, dict) or item.get('target') != target
                   or item.get('conditional_source_bindings') != facts
                   or item.get('constructor_bindings') != ordinary
                   for item in getattr(call, 'analysis_contexts', ()))):
        return None
    return fact


def consistent_conditions(conditions) -> bool:
    """Reject opposite outcomes of the same recorded source test."""
    seen = {}
    for condition in conditions:
        if not isinstance(condition, dict):
            return False
        test, branch = condition.get('test'), condition.get('branch')
        if not isinstance(test, dict) or type(branch) is not bool:
            continue
        key = test.get('file_path'), _location(test), test.get('source_text')
        if key in seen and seen[key] != branch:
            return False
        seen[key] = branch
    return True


def conditional_path_conditions(analysis, call, target, flow):
    """Keep one candidate's predicates separate from other receiver alternatives."""
    if analysis.inputs.get('conditional_source_state') is not True:
        return ()
    conditions = list(getattr(call, 'conditions', ())) + list(flow.get('conditions', ()))
    paths = getattr(call, 'candidate_paths', ())
    if not isinstance(paths, (list, tuple)) or len(paths) > 128:
        return None
    if (any(value.get('instance_candidate_contexts') for value in call.receiver_sources)
            and not paths):
        return None
    if paths:
        if any(not isinstance(path, dict) or not isinstance(path.get('conditions'), (list, tuple))
               or len(path['conditions']) > 128 for path in paths):
            return None
        compatible = [path for path in paths if path.get('call_id') == call.id
                      and identity_from_target(path.get('target')) == target
                      and consistent_conditions(conditions + list(path.get('conditions', ())))]
        if not compatible:
            return None
        conditions += list(compatible[0].get('conditions', ()))
    result = []
    for condition in conditions:
        if condition not in result:
            result.append(condition)
    return tuple(result) if consistent_conditions(result) else None


def _creation_method_premises(hook: dict, binding: dict) -> bool:
    calls = hook.get('method_calls')
    claimed = 'source_class_creation_call_graph' in hook.get('assumptions', ())
    if calls is None:
        return not claimed
    if not claimed or not isinstance(calls, (list, tuple)) or not 1 <= len(calls) <= 256:
        return False

    def identity(value):
        if (not isinstance(value, dict)
                or any(not isinstance(value.get(key), str) or not value[key]
                       for key in ('module', 'qualname', 'file_path'))
                or type(value.get('lineno')) is not int or value['lineno'] < 1
                or value['file_path'] not in hook['source_hashes']):
            return None
        return tuple(value[key] for key in ('module', 'qualname', 'file_path', 'lineno'))

    def witness(value, owner, declaration=False):
        return (isinstance(value, dict) and value.get('file_path') == owner[2]
                and all(type(value.get(key)) is int and value[key] >= 0
                        for key in ('lineno', 'col_offset', 'end_lineno', 'end_col_offset'))
                and value['lineno'] >= owner[3]
                and (not declaration or value['lineno'] == owner[3])
                and (value['lineno'], value['col_offset'])
                    < (value['end_lineno'], value['end_col_offset']))

    root = identity(hook['target'])
    if root is None:
        return False
    hierarchy = {(owner.get('module'), owner.get('qualname'), owner.get('file_path'))
                 for owner in binding.get('hierarchy', ()) if isinstance(owner, dict)}
    if (root[0], root[1].rpartition('.')[0], root[2]) not in hierarchy:
        return False
    graph, sites = {}, set()
    for call in calls:
        if not isinstance(call, dict):
            return False
        caller, target = identity(call.get('caller')), identity(call.get('target'))
        name = call.get('attribute')
        if (caller is None or target is None or not isinstance(name, str) or not name
                or name.startswith('__') or name == 'mro' or name in hook['attributes']
                or target[1].rsplit('.', 1)[-1] != name
                or (target[0], target[1].rpartition('.')[0], target[2]) not in hierarchy
                or call.get('receiver_class') != hook['receiver_class']
                or call.get('binding') != 'builtin_classmethod'
                or call.get('completion') != 'normal_return_only'
                or call.get('argument_binding') != 'implicit_receiver_only'
                or not witness(call.get('call_evidence'), caller)
                or not witness(call.get('target_evidence'), target, declaration=True)):
            return False
        site = (caller, tuple(call['call_evidence'][key] for key in (
            'lineno', 'col_offset', 'end_lineno', 'end_col_offset')))
        if site in sites:
            return False
        sites.add(site)
        graph.setdefault(caller, set()).add(target)
    vertices = set(graph) | {target for targets in graph.values() for target in targets}
    if len(vertices) > 16 or root not in graph:
        return False
    visited, active = set(), set()

    def visit(vertex):
        if vertex in active:
            return False
        if vertex in visited:
            return True
        active.add(vertex)
        if any(not visit(target) for target in graph.get(vertex, ())):
            return False
        active.remove(vertex)
        visited.add(vertex)
        return True

    return visit(root) and visited == vertices


def _creation_query_premises(hook: dict, supporting: dict) -> bool:
    queries = hook.get('native_type_queries')
    claimed = 'source_class_creation_native_queries' in hook.get('assumptions', ())
    if queries is None:
        return not claimed
    if not claimed or not isinstance(queries, (list, tuple)) or not 1 <= len(queries) <= 256:
        return False
    primary = hook['source_hashes']
    if (not isinstance(supporting, dict)
            or any(not isinstance(path, str) or not isinstance(digest, str)
                   or len(digest) != 64 or any(char not in '0123456789abcdef' for char in digest)
                   or path in primary for path, digest in supporting.items())):
        return False
    hashes = {**primary, **supporting}
    callers = [hook['target']] + [call['target'] for call in hook.get('method_calls', ())]
    required = {'source_snapshot_bindings_hold', 'standard_builtin_namespace_preserved',
        'builtin_type_iteration_raises_typeerror', 'source_function_execution_binding_preserved',
        'no_external_frame_or_gc_observation', 'no_external_monkeypatch_or_import_hook',
        'no_unmodeled_indirect_function_mutation', 'no_unmodeled_indirect_module_mutation'}
    seen = set()

    def identity(value):
        return (isinstance(value, dict)
                and all(isinstance(value.get(key), str) and value[key]
                        for key in ('module', 'qualname', 'file_path'))
                and type(value.get('lineno')) is int and value['lineno'] >= 1
                and value['file_path'] in hashes)

    def witness(value, owner=None):
        return (isinstance(value, dict) and isinstance(value.get('file_path'), str)
                and value['file_path'] in hashes
                and (owner is None or value.get('file_path') == owner.get('file_path'))
                and all(type(value.get(key)) is int and value[key] >= 0 for key in (
                    'lineno', 'col_offset', 'end_lineno', 'end_col_offset'))
                and value['lineno'] >= (owner.get('lineno', 1) if owner else 1)
                and _location(value)[:2] < _location(value)[2:])

    for query in queries:
        if not isinstance(query, dict):
            return False
        protocol, caller = query.get('source_protocol'), query.get('caller')
        if (not isinstance(protocol, dict) or not identity(caller) or caller not in callers
                or query.get('receiver_class') != hook['receiver_class']
                or query.get('argument_binding') != 'implicit_classmethod_receiver'
                or query.get('phase') != 'before_class_decorators'
                or not isinstance(query.get('parameter'), str) or not query['parameter']
                or caller == hook['target'] and query['parameter'] != hook['parameter']
                or not witness(query.get('call_evidence'), caller)
                or type(query.get('result')) is not bool
                or protocol.get('kind') != 'source_native_type_iterability_predicate'
                or protocol.get('status') != 'requires_native_type_input'
                or protocol.get('basis') != 'source_snapshot'
                or protocol.get('precondition') != {
                    'argument': {'position': 0}, 'exact_metaclass': 'type'}
                or type(protocol.get('result')) is not bool or protocol['result'] != query['result']
                or protocol.get('runtime_input_confirmed') is not False
                or protocol.get('effects') != 'none_if_precondition'
                or protocol.get('completion') != 'normal_return_if_precondition_and_lookup_succeeds'
                or protocol.get('primitive_bindings') != {
                    'iter': 'confirmed_builtin', 'TypeError': 'confirmed_builtin'}
                or not isinstance(protocol.get('source_hashes'), dict)
                or any(protocol['source_hashes'].get(path) != digest
                       for path, digest in primary.items())
                or any(hashes.get(path) != digest
                       for path, digest in protocol['source_hashes'].items())
                or not isinstance(protocol.get('assumptions'), (list, tuple))
                or any(not isinstance(value, str) for value in protocol['assumptions'])
                or not required.issubset(protocol['assumptions'])
                or not set(protocol['assumptions']).issubset(hook['assumptions'])):
            return False
        reference = protocol.get('source_binding')
        if not isinstance(reference, dict):
            return False
        target, requested = reference.get('target'), reference.get('requested')
        supporting = reference.get('source_hashes')
        if (not isinstance(target, dict) or not isinstance(requested, dict)
                or any(not isinstance(target.get(key), str) or not target[key]
                       for key in ('module', 'qualname', 'file_path'))
                or type(target.get('lineno')) is not int or target['lineno'] < 1
                or target['file_path'] not in protocol['source_hashes']
                or not isinstance(requested.get('module'), str)
                or not isinstance(requested.get('name'), str)
                or query.get('callee') != requested['module'] + '.' + requested['name']
                or reference.get('kind') != 'source_module_binding_reference'
                or reference.get('status') != 'unique_declaration_when_lookup_succeeds'
                or reference.get('basis') != 'source_snapshot'
                or reference.get('completion') != 'normal_module_return_and_attribute_lookup_only'
                or type(reference.get('may_be_unbound')) is not bool
                or reference.get('runtime_target_confirmed') is not False
                or reference.get('callable_identity_proven') is not False
                or reference.get('body_binding_proven') is not False
                or not isinstance(supporting, dict) or not supporting
                or target['file_path'] not in supporting
                or any(protocol['source_hashes'].get(path) != digest
                       for path, digest in supporting.items())
                or not isinstance(reference.get('paths'), (list, tuple))
                or not 1 <= len(reference['paths']) <= 64
                or any(not isinstance(path, dict) for path in reference['paths'])
                or not isinstance(reference.get('assumptions'), (list, tuple))
                or any(not isinstance(value, str) for value in reference['assumptions'])
                or not {'source_snapshot_bindings_hold', 'standard_source_import_protocol',
                    'standard_module_attribute_lookup', 'no_external_monkeypatch_or_import_hook',
                    'no_unmodeled_indirect_module_mutation'}.issubset(reference['assumptions'])
                or not set(reference['assumptions']).issubset(protocol['assumptions'])):
            return False
        for path in reference['paths']:
            conditions, imports = path.get('conditions'), path.get('imports')
            if (type(path.get('fallback')) is not bool
                    or not isinstance(conditions, (list, tuple)) or len(conditions) > 128
                    or not isinstance(imports, (list, tuple)) or len(imports) > 64
                    or any(not isinstance(condition, dict)
                           or condition.get('branch') not in ('if', 'else')
                           or not witness(condition.get('evidence')) for condition in conditions)):
                return False
            previous = target['module'], target['qualname']
            for imported in imports:
                if (not isinstance(imported, dict)
                        or any(not isinstance(imported.get(key), str) or not imported[key]
                               for key in ('module', 'imported_module',
                                           'imported_name', 'binding_name'))
                        or (imported['imported_module'], imported['imported_name']) != previous
                        or type(imported.get('wildcard')) is not bool
                        or imported.get('completion') != 'normal_import_return_only'
                        or not witness(imported.get('evidence'))):
                    return False
                previous = imported['module'], imported['binding_name']
            if previous != (requested['module'], requested['name']):
                return False
        definition = protocol.get('function_evidence')
        if (not witness(definition, target) or definition['lineno'] != target['lineno']
                or any(not witness(protocol.get(key), target)
                       or _location(protocol[key])[:2] < _location(definition)[:2]
                       or _location(protocol[key])[2:] > _location(definition)[2:]
                       for key in ('iteration_evidence', 'handler_evidence'))
                or _location(protocol['iteration_evidence'])[2:]
                    > _location(protocol['handler_evidence'])[:2]):
            return False
        decorations = protocol.get('decorator_effects')
        if (not isinstance(decorations, (list, tuple)) or len(decorations) > 1
                or any(not isinstance(fact, dict)
                       or fact.get('identity_status') != 'preserved'
                       or fact.get('body_binding_status') != 'preserved'
                       or fact.get('boundaries') != []
                       or not identity(fact.get('function'))
                       or identity_from_target(fact.get('function')) != identity_from_target(target)
                       or not isinstance(fact.get('source_hashes'), dict)
                       or target['file_path'] not in fact['source_hashes']
                       or any(protocol['source_hashes'].get(path) != digest
                              for path, digest in fact['source_hashes'].items())
                       or not isinstance(fact.get('assumptions'), (list, tuple))
                       or any(not isinstance(value, str) for value in fact['assumptions'])
                       or not set(fact['assumptions']).issubset(protocol['assumptions'])
                       for fact in decorations)):
            return False
        site = (tuple(caller.get(key) for key in ('module', 'qualname', 'file_path', 'lineno')),
                _location(query['call_evidence']))
        if site in seen:
            return False
        seen.add(site)
    return True


def _class_creation_metadata_queries_premises(
    analysis: Any, binding: dict, hook: dict, hook_index: int,
) -> bool:
    """Consume only the bounded class metadata pipeline used to form ``set``.

    General class observers can project arbitrary source-derived values into a
    new class namespace.  Those remain unsupported.  This reader accepts the
    narrower metadata-only chain emitted for a fresh ``set`` wrapper: presence
    checks, metadata writes, a setter-name query used to form its signature,
    and the documentation helper.  Every nested fact stays tied to this source
    snapshot and to the active creation hook.
    """
    records = hook.get('class_metadata_queries')
    claims = hook.get('assumptions', ())
    if records is None:
        return 'source_creation_phase_class_metadata_input' not in claims
    required = {
        'source_snapshot_bindings_hold', 'builtin_type_class_creation_protocol',
        'source_class_creation_effects', 'source_creation_phase_class_metadata_input',
        'no_external_monkeypatch_or_import_hook', 'no_unmodeled_indirect_class_mutation',
    }
    if (not isinstance(records, (list, tuple)) or not 1 <= len(records) <= 256
            or not isinstance(claims, (list, tuple)) or not required.issubset(claims)
            or hook.get('attributes') != ['set']):
        return False
    source_hashes = analysis.inputs.get('sha256', {})
    supporting = analysis.inputs.get('supporting_source_sha256', {})
    if not isinstance(source_hashes, dict) or not isinstance(supporting, dict):
        return False
    available = {**source_hashes, **supporting}
    hook_hashes = hook.get('source_hashes')
    if hook_hashes != source_hashes:
        return False
    callers = [hook.get('target')]
    callers.extend(call.get('target') for call in hook.get('method_calls', ())
                   if isinstance(call, dict))
    writes, presences, setter_queries, documentation, matplotlib_updates = [], [], [], [], []

    def identity(value):
        return (isinstance(value, dict)
                and all(isinstance(value.get(key), str) and value[key]
                        for key in ('module', 'qualname', 'file_path'))
                and type(value.get('lineno')) is int and value['lineno'] >= 1
                and value['file_path'] in available)

    def source_reference(value):
        return (isinstance(value, dict)
                and all(isinstance(value.get(key), str) and value[key]
                        for key in ('module', 'qualname', 'file_path'))
                and type(value.get('lineno')) is int and value['lineno'] >= 0
                and value['file_path'] in available)

    def hashes_match(value):
        hashes = value.get('source_hashes') if isinstance(value, dict) else None
        return (isinstance(hashes, dict) and bool(hashes)
                and all(isinstance(path, str) and available.get(path) == digest
                        for path, digest in hashes.items()))

    def witness(value, owner=None):
        return (isinstance(value, dict) and value.get('file_path') in available
                and (owner is None or value.get('file_path') == owner.get('file_path'))
                and all(type(item) is int and item >= 0 for item in _location(value))
                and value['lineno'] >= (owner.get('lineno', 1) if owner else 1)
                and _location(value)[:2] < _location(value)[2:])

    def assumptions_match(value):
        assumptions = value.get('assumptions') if isinstance(value, dict) else None
        return (isinstance(assumptions, (list, tuple))
                and all(isinstance(item, str) for item in assumptions)
                and set(assumptions).issubset(claims))

    def matplotlib_set_marker(fact, target=None, attribute=None):
        if (not isinstance(fact, dict)
                or fact.get('kind') != 'source_matplotlib_artist_autogenerated_set_signature'
                or fact.get('status') != 'source_bound'
                or fact.get('runtime_metadata_confirmed') is not False
                or fact.get('completion') != 'normal_module_initialization_only'
                or fact.get('attribute') != '_autogenerated_signature'
                or fact.get('value') is not True
                or attribute not in (None, '_autogenerated_signature')
                or not identity(fact.get('target'))
                or not identity(fact.get('updater'))
                or fact['target'].get('module') != 'matplotlib.artist'
                or fact['target'].get('qualname') != 'Artist.set'
                or fact['updater'].get('module') != 'matplotlib.artist'
                or fact['updater'].get('qualname') !=
                    'Artist._update_set_signature_and_docstring'
                or target is not None and fact.get('target') != target
                or not witness(fact.get('write_evidence'), fact['updater'])
                or not witness(fact.get('module_call_evidence'),
                               {'file_path': fact['updater']['file_path'],
                                'lineno': fact['target']['lineno']})
                or not hashes_match(fact) or not assumptions_match(fact)):
            return False
        return True

    def private_projections_match(entry, parent_assumptions):
        projections = entry.get('private_query_results')
        if (not isinstance(projections, (list, tuple)) or not 1 <= len(projections) <= 256
                or 'source_private_observer_result_projection' not in parent_assumptions):
            return False
        for projection in projections:
            query = projection.get('query') if isinstance(projection, dict) else None
            guard = projection.get('observation_guard') if isinstance(projection, dict) else None
            assumptions = projection.get('assumptions') if isinstance(projection, dict) else None
            if (not isinstance(projection, dict)
                    or projection.get('kind') != 'private_observer_data_result'
                    or projection.get('basis') != 'source_snapshot'
                    or projection.get('scope') != 'observer_class_identity_only'
                    or projection.get('runtime_execution_confirmed') is not False
                    or not identity(projection.get('owner_class'))
                    or not source_reference(projection.get('caller'))
                    or not witness(projection.get('call_evidence'), projection.get('caller'))
                    or not isinstance(assumptions, (list, tuple))
                    or 'source_private_observer_result_projection' not in assumptions
                    or not set(assumptions).issubset(parent_assumptions)
                    or not isinstance(query, dict)
                    or query.get('kind') != 'source_private_class_metadata_observer'
                    or query.get('status') != 'requires_native_class_metadata'
                    or query.get('runtime_execution_confirmed') is not False
                    or query.get('completion') != 'normal_return_only'
                    or 'result' in query
                    or query.get('result_shape') not in ('native_string_list',
                                                         'native_string_set_mapping')
                    or not hashes_match(query)
                    or not isinstance(query.get('owner_binding'), dict)
                    or query['owner_binding'].get('status') != 'requires_source_member_bindings'
                    or query.get('owner_class') != projection.get('owner_class')
                    or not isinstance(guard, dict)
                    or not _observer({'observation_guard': guard,
                                      'assumptions': assumptions}, source_hashes)):
                return False
        return True

    for record in records:
        if (not isinstance(record, dict) or record.get('status') != 'source_bound'
                or record.get('completion') != 'normal_return_only'
                or record.get('runtime_execution_confirmed') is not False
                or record.get('receiver_class') != hook.get('receiver_class')
                or record.get('caller') not in callers
                or not identity(record.get('caller'))
                or not hashes_match(record) or not assumptions_match(record)
                or not witness(record.get('call_evidence'), record.get('caller'))):
            return False
        kind = record.get('kind')
        if kind == 'source_bound_callable_metadata_presence':
            fact = record.get('metadata_fact')
            if (record.get('operation') != 'builtin_hasattr'
                    or record.get('result') is not True
                    or not isinstance(record.get('method_name'), str)
                    or record.get('metadata_attribute') not in (
                        '_supports_rasterization', '_autogenerated_signature')
                    or not isinstance(fact, dict) or fact.get('status') != 'source_bound'
                    or fact.get('runtime_metadata_confirmed') is not False
                    or not hashes_match(fact) or not assumptions_match(fact)
                    or fact.get('attribute') != record['metadata_attribute']):
                return False
            fact_kind = fact.get('kind')
            if fact_kind == 'source_wrapper_custom_function_metadata':
                if (fact.get('formation_phase') != 'class_body_function_decoration'
                        or type(fact.get('value')) not in (str, int, bool, float, type(None))
                        or not identity(fact.get('decorator'))
                        or not identity(fact.get('decorated_function'))
                        or not witness(fact.get('evidence'))):
                    return False
            elif fact_kind == 'source_matplotlib_rasterization_wrapper_metadata':
                protocol = fact.get('wrapper_metadata_protocol')
                if (fact.get('formation_phase') != 'class_body_function_decoration'
                        or fact.get('attribute') != '_supports_rasterization'
                        or fact.get('value') is not True
                        or fact.get('wrapper_name') != 'draw_wrapper'
                        or not identity(fact.get('decorator'))
                        or fact['decorator'].get('module') != 'matplotlib.artist'
                        or fact['decorator'].get('qualname') != 'allow_rasterization'
                        or not identity(fact.get('decorated_function'))
                        or fact.get('decorated_function') != record.get('target')
                        or not witness(fact.get('evidence'), fact['decorator'])
                        or not isinstance(protocol, dict)
                        or protocol.get('kind') != 'standard_functools_wraps'
                        or protocol.get('status') != 'source_bound'
                        or not hashes_match(protocol)
                        or not assumptions_match(protocol)
                        or not hashes_match(fact)):
                    return False
            elif fact_kind == 'source_matplotlib_artist_autogenerated_set_signature':
                if not matplotlib_set_marker(fact, record.get('target'),
                                             record.get('metadata_attribute')):
                    return False
            elif fact_kind in ('source_module_initialization_method_metadata',
                               'source_ancestor_class_creation_method_metadata'):
                nested = (fact.get('metadata_write') if fact_kind ==
                          'source_module_initialization_method_metadata'
                          else fact.get('creation_fact'))
                if (not isinstance(nested, dict)
                        or nested.get('kind') != 'source_bound_method_metadata_write'
                        or nested.get('status') != 'source_bound'
                        or nested.get('attribute') != record['metadata_attribute']
                        or nested.get('runtime_execution_confirmed') is not False
                        or not hashes_match(nested) or not assumptions_match(nested)
                        or not identity(nested.get('target'))
                        or not witness(nested.get('call_evidence'), nested.get('caller'))):
                    return False
                if fact_kind == 'source_ancestor_class_creation_method_metadata':
                    ancestors = fact.get('ancestor_creation_hooks')
                    previous = binding.get('class_creation_hooks', ())[:hook_index]
                    if (not isinstance(ancestors, (list, tuple))
                            or list(ancestors) != list(previous)
                            or not any(
                                nested == query for prior in previous
                                for query in prior.get('class_metadata_queries', ())
                                if isinstance(prior, dict))):
                        return False
                else:
                    effect = fact.get('module_effect')
                    if (not isinstance(effect, dict) or effect.get('status') != 'source_bound'
                            or fact.get('metadata_write') != nested
                            or not hashes_match(effect)):
                        return False
            else:
                return False
            presences.append(record)
        elif kind == 'source_bound_method_metadata_write':
            generated = record.get('generated_member_binding')
            if (record.get('attribute') not in (
                    '__name__', '__qualname__', '__signature__',
                    '_autogenerated_signature', '__doc__')
                    or record.get('value_shape') not in (
                        'str', 'bool', 'native_inspect_signature', 'source_class_qualname_suffix')
                    or record.get('runtime_execution_confirmed') is not False
                    or not identity(record.get('target'))
                    or not isinstance(generated, dict)
                    or generated.get('kind') != 'source_class_creation_lambda_member'
                    or generated.get('status') != 'source_bound'
                    or generated.get('attribute') != 'set'
                    or generated.get('receiver_class') != hook.get('receiver_class')
                    or record.get('definition_evidence') != generated.get('binding_evidence')
                    or not hashes_match(generated)
                    or not witness(generated.get('binding_evidence'), hook.get('target'))):
                return False
            writes.append(record)
        elif kind == 'source_matplotlib_set_function_metadata_write':
            if (record.get('attribute') not in ('__name__', '__qualname__')
                    or record.get('effect_scope') != 'function_metadata_only'
                    or record.get('target') != record.get('caller')
                    or not identity(record.get('target'))
                    or record['target'].get('module') != 'matplotlib.artist'
                    or record['target'].get('qualname') != 'Artist.__init_subclass__'
                    or not hashes_match(record)):
                return False
            writes.append(record)
        elif kind == 'source_matplotlib_class_creation_metadata_only':
            marker = record.get('metadata_update')
            if (record.get('effect_scope') != 'set_function_metadata_only'
                    or not identity(record.get('target'))
                    or record['target'].get('module') != 'matplotlib.artist'
                    or record['target'].get('qualname') !=
                        'Artist._update_set_signature_and_docstring'
                    or not matplotlib_set_marker(marker, attribute='_autogenerated_signature')
                    or marker.get('updater') != record.get('target')
                    or not hashes_match(record)):
                return False
            matplotlib_updates.append(record)
        elif kind == 'source_bound_class_metadata_query':
            entry, input_binding = record.get('entry_binding'), record.get('input_binding')
            query = record.get('query')
            projection_claimed = (isinstance(entry, dict) and
                'source_private_observer_result_projection' in entry.get('assumptions', ()))
            if (record.get('result_shape') != 'native_string_list'
                    or not isinstance(query, dict)
                    or query.get('status') != 'requires_native_class_metadata'
                    or query.get('runtime_execution_confirmed') is not False
                    or 'result' in query or not hashes_match(query)
                    or not isinstance(entry, dict)
                    or entry.get('kind') != 'source_native_class_member_query'
                    or entry.get('status') != 'source_bound'
                    or entry.get('runtime_target_confirmed') is not False
                    or not hashes_match(entry)
                    or not isinstance(input_binding, dict)
                    or input_binding.get('kind') != 'fresh_source_class_metadata'
                    or input_binding.get('phase') != 'class_creation_entry'
                    or input_binding.get('creation_dependency') != 'source_class_creation_prefix'
                    or not isinstance(input_binding.get('matching_members'), (list, tuple))
                    or not input_binding['matching_members']
                    or ('private_query_results' in entry) != projection_claimed
                    or projection_claimed and not private_projections_match(
                        entry, record.get('assumptions', ()))):
                return False
            setter_queries.append(record)
        elif kind == 'source_bound_class_documentation_helper':
            if (record.get('output_shape') != 'str'
                    or not isinstance(record.get('observer_methods'), (list, tuple))
                    or not record['observer_methods']
                    or not isinstance(record.get('observer_queries'), (list, tuple))
                    or not hashes_match(record)):
                return False
            documentation.append(record)
        else:
            return False
    if matplotlib_updates:
        presence_attributes = {record.get('metadata_attribute') for record in presences}
        return (len(matplotlib_updates) == 1
                and presence_attributes in ({'_autogenerated_signature'},
                    {'_supports_rasterization', '_autogenerated_signature'})
                and len(presences) == len(presence_attributes)
                and {record.get('attribute') for record in writes} == {
                    '__name__', '__qualname__'}
                and len(writes) == 2
                and not setter_queries and not documentation)
    return bool(presences and writes and setter_queries and documentation)


def _creation_hook_premises(analysis: Any, binding: dict) -> bool:
    hooks = binding.get('class_creation_hooks')
    claims = binding.get('assumptions', ())
    if not isinstance(claims, (list, tuple)) or any(not isinstance(value, str) for value in claims):
        return False
    if hooks is None:
        return not {'source_class_creation_effects',
                    'source_class_creation_call_graph',
                    'source_class_creation_native_queries',
                    'source_class_creation_callable_metadata_queries'} & set(claims)
    if not isinstance(hooks, (list, tuple)) or not 1 <= len(hooks) <= 64:
        return False
    required = {'source_snapshot_bindings_hold', 'builtin_type_class_creation_protocol',
                'source_class_creation_effects', 'builtin_type_attribute_writes',
                'standard_builtin_namespace_preserved', 'no_unmodeled_indirect_builtin_mutation',
                'no_external_monkeypatch_or_import_hook', 'no_unmodeled_indirect_class_mutation',
                'no_external_frame_introspection'}
    seen = set()
    for hook_index, hook in enumerate(hooks):
        if not isinstance(hook, dict):
            return False
        if not _class_creation_metadata_queries_premises(
                analysis, binding, hook, hook_index):
            return False
        attributes, assumptions = hook.get('attributes'), hook.get('assumptions')
        receiver, target = hook.get('receiver_class'), hook.get('target')
        if (not isinstance(receiver, dict) or not isinstance(target, dict)
                or any(not isinstance(identity.get(field), str) or not identity[field]
                       for identity in (receiver, target)
                       for field in ('module', 'qualname', 'file_path'))
                or not isinstance(target.get('qualname'), str)
                or not target['qualname'].endswith('.__init_subclass__')
                or hook.get('kind') != 'source_class_creation_hook'
                or hook.get('status') != 'source_bound'
                or hook.get('basis') != 'source_snapshot'
                or hook.get('phase') != 'before_class_decorators'
                or hook.get('binding') != 'implicit_classmethod'
                or hook.get('completion') != 'normal_return_only'
                or hook.get('preserved_scope') != 'other_class_attributes'
                or hook.get('runtime_hook_confirmed') is not False
                or not isinstance(hook.get('parameter'), str) or not hook['parameter']
                or not isinstance(attributes, (list, tuple)) or len(attributes) > 2000
                or any(not isinstance(name, str) or not name or name == 'mro'
                       or name.startswith('__') and name.endswith('__') for name in attributes)
                or len(set(attributes)) != len(attributes)
                or not isinstance(assumptions, (list, tuple))
                or any(not isinstance(value, str) for value in assumptions)
                or not required.issubset(assumptions) or not set(assumptions).issubset(claims)
                or not isinstance(hook.get('source_hashes'), dict) or not hook['source_hashes']
                or not isinstance(binding.get('source_hashes'), dict)
                or hook.get('source_hashes') != analysis.inputs.get('sha256')
                or not all(binding.get('source_hashes', {}).get(path) == digest
                           for path, digest in hook.get('source_hashes', {}).items())):
            return False
        if (not _creation_method_premises(hook, binding)
                or not _creation_query_premises(
                    hook, analysis.inputs.get('supporting_source_sha256', {}))
                or not creation_metadata_premises(
                    hook, analysis.inputs.get('supporting_source_sha256', {}))):
            return False
        for field, identity in (('class_evidence', receiver), ('hook_evidence', target)):
            witness = hook.get(field)
            if (not isinstance(witness, dict)
                    or witness.get('file_path') != identity.get('file_path')
                    or witness.get('lineno') != identity.get('lineno')):
                return False
        key = (receiver.get('module'), receiver.get('qualname'),
               target.get('module'), target['qualname'])
        if key in seen:
            return False
        seen.add(key)
    return (('source_class_creation_call_graph' in claims) == any(
        'method_calls' in hook for hook in hooks)
        and ('source_class_creation_native_queries' in claims) == any(
            'native_type_queries' in hook for hook in hooks)
        and ('source_class_creation_callable_metadata_queries' in claims) == any(
            'callable_metadata_queries' in hook for hook in hooks))


def source_constructor_entry_binding(analysis: Any, requested: FunctionIdentity) -> Optional[dict]:
    """Validate a class-query binding separately from an actual call-site proof."""

    fact = analysis.inputs.get("entry_binding")
    if not isinstance(fact, dict):
        return None
    implicit = fact.get("implicit_binding")
    hashes = fact.get("source_hashes")
    evidence = fact.get("definition_evidence")
    hierarchy = fact.get("hierarchy")
    if (not isinstance(implicit, dict) or not isinstance(hashes, dict)
            or not isinstance(evidence, dict)
            or not isinstance(hierarchy, (list, tuple)) or not 1 <= len(hierarchy) <= 64
            or not isinstance(fact.get("assumptions"), (list, tuple))
            or not all(isinstance(item, str) for item in fact["assumptions"])):
        return None
    try:
        receiver = identity_from_target(fact["receiver_class"])
        target = identity_from_target(fact["target"])
        owners = tuple(identity_from_target(item) for item in hierarchy)
    except (AttributeError, KeyError, TypeError, ValueError):
        return None
    if receiver is None or target is None or any(owner is None for owner in owners):
        return None
    phase = fact.get("phase")
    assumptions = {"source_snapshot_bindings_hold", "builtin_type_call_and_new_binding",
                   "no_external_monkeypatch_or_import_hook", "no_unmodeled_indirect_class_mutation"}
    source_hashes = {**analysis.inputs.get("sha256", {}),
                     **analysis.inputs.get("supporting_source_sha256", {})}
    valid = (
        fact.get("query_kind") == "source_class_call" and fact.get("basis") == "source_snapshot"
        and fact.get("status") == "source_bound" and not fact.get("issues")
        and fact.get("runtime_target_confirmed") is False
        and fact.get("instance_state") == "unmodeled"
        and receiver == requested and target == identity_from_target(analysis.entry)
        and owners[0] == receiver and len(set(owners)) == len(owners)
        and phase in ("__new__", "__init__") and target.qualname.endswith("." + phase)
        and fact.get("execution_scope") == ("new_invocation_only" if phase == "__new__"
                                            else "init_invocation_only")
        and fact.get("body_execution") == "synchronous" and implicit.get("status") == "static_bound"
        and isinstance(implicit.get("parameter"), str)
        and implicit.get("value_kind") == ("class" if phase == "__new__" else "instance")
        and bool(hashes) and str(receiver.file_path) in hashes and str(target.file_path) in hashes
        and all(str(owner.file_path) in hashes for owner in owners)
        and all(isinstance(path, str) and isinstance(digest, str)
                for path, digest in hashes.items())
        and all(source_hashes.get(path) == digest for path, digest in hashes.items())
        and Path(evidence.get("file_path", "")) == receiver.file_path
        and evidence.get("lineno") == receiver.lineno
        and assumptions.issubset(fact["assumptions"])
        and _creation_hook_premises(analysis, fact)
        and any(b.get("reason") == "source_constructor_entry_binding"
                and b.get("boundary_kind") == "assumption"
                and b.get("function") == fact["target"] for b in analysis.boundaries)
    )
    return fact if valid else None


def source_constructor_binding(analysis: Any, call: Any) -> Optional[dict]:
    """Read one source constructor invocation proof, never initialized state."""

    if analysis.inputs.get('conditional_source_state'):
        return None
    bindings = getattr(call, "constructor_bindings", ())
    if (not isinstance(bindings, (list, tuple))
            or call.target_status != "constructor" or call.target is None
            or call.binding_status == "invalid" or len(bindings) != 1):
        return None
    binding = bindings[0]
    if (not isinstance(binding, dict)
            or not isinstance(binding.get("implicit_binding"), dict)
            or not isinstance(binding.get("source_hashes"), dict)
            or not isinstance(binding.get("receiver_class"), dict)
            or not isinstance(binding.get("assumptions"), (list, tuple))
            or not isinstance(binding.get("call_evidence"), dict)):
        return None
    implicit = binding["implicit_binding"]
    phase = binding.get("phase")
    if phase not in ("__new__", "__init__") or not all(
            isinstance(item, str) for item in binding["assumptions"]):
        return None
    initializer = phase == "__init__"
    scope = "init_invocation_only" if initializer else "new_invocation_only"
    slot = {"constructor_instance" if initializer else "constructor_class": True}
    receiver_kind = "instance_type" if initializer else "class_type"
    arguments = [a for a in call.argument_sources if a.get("argument") == slot
                 and a.get("parameter") == implicit.get("parameter")]
    records = [r for r in call.parameter_bindings if r.get("argument") == slot]
    values = [v for argument in arguments for v in argument.get("sources", ())]
    witness = binding["call_evidence"]
    assumptions = {"source_snapshot_bindings_hold", "builtin_type_call_and_new_binding",
                   "no_external_monkeypatch_or_import_hook",
                   "no_unmodeled_indirect_class_mutation"}
    valid = (
        binding.get("status") == "source_bound" and binding.get("basis") == "source_snapshot"
        and not binding.get("issues") and binding.get("runtime_target_confirmed") is False
        and call.target.qualname.endswith("." + phase)
        and binding.get("execution_scope") == scope
        and binding.get("instance_state") == "unmodeled"
        and binding.get("body_execution") in ("synchronous", "deferred")
        and binding.get("target") is not None
        and identity_from_target(binding["target"]) == identity_from_target(call.target)
        and implicit.get("status") == "static_bound" and implicit.get("argument") == slot
        and implicit.get("receiver_class") == binding.get("receiver_class")
        and len(records) == len(arguments) == 1 and records[0].get("status") == "exact"
        and records[0].get("parameter") == implicit.get("parameter")
        and bool(values) and all(v.get(receiver_kind) == binding.get("receiver_class")
            and v.get("relation") == "direct" and not any(v.get(flag) for flag in (
                "projection", "output_path", "value_incomplete", "import_modified",
                "import_incomplete")) for v in values)
        and Path(witness.get("file_path", "")) == Path(call.caller.file_path)
        and _location(witness) == (call.lineno, call.col_offset,
                                  call.end_lineno, call.end_col_offset)
        and bool(binding["source_hashes"])
        and all(analysis.inputs.get("sha256", {}).get(path) == digest
                for path, digest in binding["source_hashes"].items())
        and assumptions.issubset(binding.get("assumptions", ()))
        and _creation_hook_premises(analysis, binding)
        and any(b.get("call_id") == call.id
                and b.get("reason") == "source_constructor_" + phase.strip("_") + "_binding"
                and b.get("boundary_kind") == "assumption"
                and b.get("execution_scope") == scope for b in analysis.boundaries)
        and all(item.get("target") == binding["target"]
                and item.get("constructor_bindings") == bindings
                for item in call.analysis_contexts))
    return binding if valid else None



@dataclass(frozen=True)
class CallFacts:
    """A neutral view of one producer edge; optional semantics stay unproved."""

    analysis: Any
    call: Any

    @property
    def complete_binding(self):
        return self.call.binding_status == "complete" and not self.call.binding_issues

    @property
    def status(self):
        return target_status(self.analysis, self.call)

    @property
    def boundaries(self):
        return tuple(b for b in self.analysis.boundaries if b.get("call_id") == self.call.id)


def preserved_mapping_remainder(analysis, call, value):
    """Admit only current sources outside a producer's finite affected keys."""

    if (call.analysis_status != 'analyzed' or target_status(analysis, call) != 'resolved'
            or call.target is None or not CallFacts(analysis, call).complete_binding
            or len(call.effects) != 1):
        return False
    effect = call.effects[0]
    if (effect.get('kind') != 'mapping_remainder'
            or effect.get('operation') != 'preserve_unaffected_keys'
            or effect.get('completion') != 'normal_return'
            or effect.get('status') != 'bounded'
            or effect.get('value_completeness') != 'unaffected_keys_only'
            or effect.get('call_id') != call.id
            or identity_from_target(effect.get('function')) != identity_from_target(call.target)
            or not effect.get('evidence')
            or effect.get('assumptions') != [
                'fresh_unescaped_builtin_dict', 'source_snapshot_bindings_hold',
                'no_external_monkeypatch_or_import_hook', 'no_reflective_frame_access']
            or any(b.get('reason') in ('mapping_effect_unproven', 'mapping_remainder_budget',
                                       'mapping_effect_budget', 'container_effect_unknown')
                   for b in CallFacts(analysis, call).boundaries)):
        return False
    binding = effect.get('binding', {})
    arguments = [a for a in call.argument_sources if a.get('parameter') == effect.get('parameter')]
    witness = effect.get('call_evidence', {})
    if (binding.get('status') != 'exact' or binding not in call.parameter_bindings
            or binding.get('parameter') != effect.get('parameter')
            or len(arguments) != 1
            or arguments[0].get('container_binding', {}).get('source')
            != effect.get('object_source')
            or arguments[0].get('container_binding', {}).get('shape') != 'dict'
            or Path(witness.get('file_path', '')) != Path(call.caller.file_path)
            or _location(witness) != (call.lineno, call.col_offset,
                                      call.end_lineno, call.end_col_offset)):
        return False
    paths = effect.get('excluded_paths')
    if (not isinstance(paths, list) or len(paths) > 64
            or not all(isinstance(path, list) and len(path) == 1 and isinstance(path[0], str)
                       for path in paths)):
        return False
    returned = effect.get('return_object', {})
    route = effect.get('return_path')
    if (returned.get('identity') != 'argument_alias'
            or returned.get('source') != effect.get('object_source')
            or returned.get('parameter') != effect.get('parameter')
            or returned.get('value_completeness') != 'unaffected_keys_only'
            or identity_from_target(returned.get('function')) != identity_from_target(call.target)
            or not (route is None or route == [] or isinstance(route, list) and len(route) == 1
                    and type(route[0]) is int and route[0] >= 0)):
        return False
    if value.get('object_only'):
        return value.get('container_object', {}).get('source') == effect.get('object_source')
    return (value.get('kind') in ('parameter', 'capture')
            and any(root.get('name') == value.get('source') for root in effect.get('mapping', []))
            and all(path in value.get('excluded_paths', []) for path in paths))
