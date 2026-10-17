"""Validate explicit runtime checkpoints against neutral PCResolve guard facts."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path

from ._fact_adapter import ResolutionError
from ._program_facts import _node_location, identity_from_target
from .models import FunctionIdentity, SourceSpan


def _call(text):
    try:
        node = text if isinstance(text, ast.Call) else ast.parse(text, mode='eval').body
        return ast.dump(node) if isinstance(node, ast.Call) else None
    except (SyntaxError, ValueError, TypeError):
        return None


def keyword_check(context, entry, call, change, original):
    """Require a trusted original-call checkpoint and the exact source rejection guard."""
    observations = call.observed_keyword_checks
    if len(observations) != 1:
        return None
    observed = observations[0]
    if (not isinstance(observed.entry, FunctionIdentity)
            or not isinstance(observed.checker, FunctionIdentity)
            or not isinstance(observed.raise_span, SourceSpan)
            or not all(isinstance(value, str) for value in (
                observed.keyword, observed.mapping_parameter, observed.key_variable,
                observed.lookup_variable, observed.attribute_name))
            or change.old_position is not None
            or observed.entry != entry.identity or observed.keyword != change.old_name
            or type(observed.value) not in (str, bytes, int, float, bool, type(None))
            or type(observed.value) is not type(original) or observed.value != original
            or _call(observed.call_text) is None
            or _call(observed.call_text) != _call(call.expression)
            or observed.lookup_value is not None or observed.exception != 'AttributeError'
            or observed.uncaught is not True
            or not isinstance(observed.source_hashes, tuple)
            or not 1 <= len(observed.source_hashes) <= 2000):
        return None
    checker = context.index.find(observed.checker)
    if checker is None or checker.identity != observed.checker:
        return None
    try:
        hashes = dict(observed.source_hashes)
    except (TypeError, ValueError):
        return None
    if (len(hashes) != len(observed.source_hashes)
            or entry.identity.file_path not in hashes or checker.identity.file_path not in hashes):
        return None
    try:
        for path, digest in hashes.items():
            if (not isinstance(path, Path) or path not in context.index.files
                    or not isinstance(digest, str)
                    or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
                return None
        analysis = context.adapter.analyze(checker.identity)
    except (OSError, ResolutionError):
        return None
    summaries = [f for f in analysis.functions
                 if identity_from_target(f.get('function')) == checker.identity]
    if len(summaries) != 1:
        return None
    span = observed.raise_span
    if not hasattr(span, 'file_path'):
        return None
    expected_span = {'file_path': str(span.file_path), 'lineno': span.lineno,
                     'col_offset': span.col_offset, 'end_lineno': span.end_lineno,
                     'end_col_offset': span.end_col_offset}
    facts = summaries[0].get('keyword_checks', ())
    if not isinstance(facts, (list, tuple)) or len(facts) > 128:
        return None
    for fact in facts:
        if not isinstance(fact, dict) or not isinstance(fact.get('attribute_template'), dict):
            return None
        template = fact.get('attribute_template', {})
        witnesses = (
            ('lookup_evidence', ast.Assign), ('guard_evidence', ast.UnaryOp),
            ('iteration_evidence', ast.For),
        )
        if any(not isinstance(fact.get(name), dict)
               or fact[name].get('file_path') != str(checker.identity.file_path)
               or not any(isinstance(node, kind) and _node_location(node) == tuple(
                   fact[name].get(field) for field in (
                       'lineno', 'col_offset', 'end_lineno', 'end_col_offset'))
                   for node in ast.walk(checker.node)) for name, kind in witnesses):
            continue
        if (fact.get('kind') != 'mapping_member_validation'
                or fact.get('status') != 'requires_observation'
                or fact.get('runtime_rejection_confirmed') is not False
                or fact.get('function') != summaries[0]['function']
                or fact.get('raise_evidence') != expected_span
                or fact.get('source_hash') != analysis.inputs.get('sha256', {}).get(
                    str(checker.identity.file_path))
                or fact.get('mapping_parameter') != observed.mapping_parameter
                or fact.get('key_variable') != observed.key_variable
                or fact.get('lookup_variable') != observed.lookup_variable
                or 'lookup_missing_value' not in fact or fact['lookup_missing_value'] is not None
                or fact.get('exception') != observed.exception
                or not isinstance(template.get('prefix'), str)
                or not isinstance(template.get('suffix'), str)
                or template['prefix'] + observed.keyword + template['suffix']
                   != observed.attribute_name):
            continue
        return observed
    return None
