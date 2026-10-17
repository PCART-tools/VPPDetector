"""Validate execution evidence against neutral source-predicate obligations."""

from __future__ import annotations

import ast
import hashlib
import operator
from pathlib import Path

from ._fact_adapter import ResolutionError
from ._observed_checks import _call
from ._program_facts import identity_from_target
from .models import FunctionIdentity, SourceSpan


def _descriptor(node):
    negated = False
    while isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        negated = not negated
        node = node.operand
    if isinstance(node, ast.Name):
        return 'truth', node.id, negated, {}
    if not isinstance(node, ast.Compare) or len(node.ops) != 1:
        return None
    if isinstance(node.ops[0], (ast.In, ast.NotIn)) and isinstance(node.comparators[0], ast.Name):
        if isinstance(node.left, ast.Name):
            key = {'kind': 'name', 'name': node.left.id}
        elif isinstance(node.left, ast.Constant) and type(node.left.value) is str:
            key = {'kind': 'literal', 'value': node.left.value}
        else:
            return None
        return ('contains', node.comparators[0].id, negated,
                {'key': key, 'operator': 'in' if isinstance(node.ops[0], ast.In) else 'not_in'})
    if (isinstance(node.left, ast.Call) and isinstance(node.left.func, ast.Name)
            and node.left.func.id == 'len' and not node.left.keywords
            and len(node.left.args) == 1 and isinstance(node.left.args[0], ast.Name)
            and isinstance(node.comparators[0], ast.Constant)
            and type(node.comparators[0].value) is int
            and type(node.ops[0]) in (ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE)):
        return ('length', node.left.args[0].id, negated,
                {'operator': type(node.ops[0]).__name__, 'constant': node.comparators[0].value})
    return None


def container_predicate(context, entry, call, change):
    """Require call scope, original-element provenance, completion and source agreement."""
    if len(call.observed_container_predicates) != 1:
        return None
    observed = call.observed_container_predicates[0]
    if (not isinstance(observed.entry, FunctionIdentity) or observed.entry != entry.identity
            or not isinstance(observed.checker, FunctionIdentity)
            or observed.parameter_name != change.old_name
            or type(observed.old_position) is not type(change.old_position)
            or observed.old_position != change.old_position
            or _call(observed.call_text) is None
            or _call(observed.call_text) != _call(call.expression)
            or observed.origin_confirmed is not True or observed.predicate_completed is not True
            or observed.completed_normally is not True or type(observed.predicate_value) is not bool
            or type(observed.container_size) is not int or observed.container_size < 1
            or observed.container_kind not in ('dict', 'tuple')
            or not isinstance(observed.predicate_span, SourceSpan)):
        return None
    if observed.container_kind == 'dict':
        if type(observed.selection) is not str or observed.selection != change.old_name:
            return None
    elif (type(observed.selection) is not int
          or not 0 <= observed.selection < observed.container_size):
        return None
    if observed.container_kind == 'tuple':
        bound = entry.is_bound_method if call.bound_receiver is None else call.bound_receiver
        fixed = len(entry.node.args.posonlyargs + entry.node.args.args)
        fixed -= int(bound and fixed > 0)
        if change.old_position is None or observed.selection != change.old_position - fixed:
            return None
    checker = context.index.find(observed.checker)
    if checker is None or checker.identity != observed.checker:
        return None
    if (not isinstance(observed.source_hashes, tuple)
            or not 1 <= len(observed.source_hashes) <= 2000):
        return None
    try:
        hashes = dict(observed.source_hashes)
        if (len(hashes) != len(observed.source_hashes) or entry.identity.file_path not in hashes
                or checker.identity.file_path not in hashes):
            return None
        for path, digest in hashes.items():
            if (not isinstance(path, Path) or path not in context.index.files
                    or type(digest) is not str
                    or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
                return None
        analysis = context.adapter.analyze(checker.identity)
    except (OSError, TypeError, ValueError, ResolutionError):
        return None
    summaries = [f for f in analysis.functions
                 if identity_from_target(f.get('function')) == checker.identity]
    if len(summaries) != 1:
        return None
    facts = summaries[0].get('container_predicates', ())
    if not isinstance(facts, (tuple, list)) or len(facts) > 128:
        return None
    span = observed.predicate_span
    if (span.file_path != checker.identity.file_path or any(type(getattr(span, field)) is not int
            for field in ('lineno', 'col_offset', 'end_lineno', 'end_col_offset'))):
        return None
    expected_span = {'file_path': str(checker.identity.file_path), 'lineno': span.lineno,
                     'col_offset': span.col_offset, 'end_lineno': span.end_lineno,
                     'end_col_offset': span.end_col_offset}
    candidates = []
    for node in ast.walk(checker.node):
        if not isinstance(node, ast.If):
            continue
        selected = node.test
        while isinstance(selected, ast.BoolOp):
            selected = selected.values[0]
        if (selected.lineno, selected.col_offset, selected.end_lineno, selected.end_col_offset) == (
                span.lineno, span.col_offset, span.end_lineno, span.end_col_offset):
            candidates.append((selected, node.test))
    if len(candidates) != 1:
        return None
    selected, guard = candidates[0]
    guard_span = {'file_path': str(checker.identity.file_path), 'lineno': guard.lineno,
                  'col_offset': guard.col_offset, 'end_lineno': guard.end_lineno,
                  'end_col_offset': guard.end_col_offset}
    descriptor = _descriptor(selected)
    parameters = set(checker.signature.positional_only + checker.signature.positional_or_keyword
                     + checker.signature.keyword_only)
    parameters.update(name for name in (checker.signature.kwarg, checker.signature.vararg) if name)
    matched = []
    for fact in facts:
        if (not isinstance(fact, dict) or fact.get('kind') != 'container_predicate'
                or fact.get('status') != 'requires_observation'
                or fact.get('function') != summaries[0]['function']
                or fact.get('parameter') != observed.container_parameter
                or observed.container_parameter not in parameters
                or fact.get('predicate_evidence') != expected_span
                or fact.get('guard_evidence') != guard_span
                or fact.get('source_hash') != analysis.inputs.get('sha256', {}).get(
                    str(checker.identity.file_path))
                or not fact.get('source_hash') or fact.get('predicate_completed') is not False
                or fact.get('container_type_proven') is not False
                or type(fact.get('negated')) is not bool
                or descriptor != (fact.get('operation'), fact.get('parameter'),
                                  fact.get('negated'), fact.get('detail'))):
            continue
        matched.append(fact)
    if descriptor is None or len(matched) != 1:
        return None
    operation, _, negated, detail = descriptor
    if operation == 'contains':
        key = detail['key']
        if observed.container_kind != 'dict':
            return None
        if key['kind'] == 'literal':
            if key['value'] != observed.selection or observed.key_variable is not None:
                return None
        elif observed.key_variable != key['name']:
            return None
        value = detail['operator'] == 'in'
    else:
        if observed.key_variable is not None:
            return None
        value = bool(observed.container_size)
        if operation == 'length':
            comparisons = {'Eq': operator.eq, 'NotEq': operator.ne, 'Lt': operator.lt,
                           'LtE': operator.le, 'Gt': operator.gt, 'GtE': operator.ge}
            compare = comparisons[detail['operator']]
            value = compare(observed.container_size, detail['constant'])
    value = not value if negated else value
    return matched[0] if value is observed.predicate_value else None
