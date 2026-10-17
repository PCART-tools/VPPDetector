"""Validate actual nonempty-dictionary rejection against neutral source guards."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path

from ._fact_adapter import ResolutionError
from ._observed_checks import _call
from ._program_facts import identity_from_target
from .models import FunctionIdentity, SourceSpan


def _span(path, node):
    return dict(file_path=str(path), lineno=node.lineno, col_offset=node.col_offset,
                end_lineno=node.end_lineno, end_col_offset=node.end_col_offset)


def capture_rejection(context, entry, call, change, original):
    """Require a reached guard, original-key provenance and the actual escaping exception."""
    if len(call.observed_capture_rejections) != 1:
        return None
    observed = call.observed_capture_rejections[0]
    if (not isinstance(observed.entry, FunctionIdentity) or observed.entry != entry.identity
            or not isinstance(observed.checker, FunctionIdentity)
            or change.old_position is not None or observed.keyword != change.old_name
            or type(observed.value) not in (str, bytes, int, float, bool, type(None))
            or type(original) is not type(observed.value) or original != observed.value
            or _call(observed.call_text) is None
            or _call(observed.call_text) != _call(call.expression)
            or observed.received_builtin_dict is not True or observed.origin_confirmed is not True
            or observed.guard_value is not True or observed.guard_completed is not True
            or observed.uncaught is not True
            or observed.exception not in ('TypeError', 'ValueError')
            or not isinstance(observed.guard_span, SourceSpan)
            or not isinstance(observed.raise_span, SourceSpan)
            or not isinstance(observed.source_hashes, tuple)
            or not 1 <= len(observed.source_hashes) <= 2000):
        return None
    checker = context.index.find(observed.checker)
    if checker is None or checker.identity != observed.checker:
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
    facts = summaries[0].get('capture_rejection_guards', ())
    if not isinstance(facts, (tuple, list)) or len(facts) > 128:
        return None
    for span in (observed.guard_span, observed.raise_span):
        if (span.file_path != checker.identity.file_path
                or any(type(getattr(span, field)) is not int for field in (
                    'lineno', 'col_offset', 'end_lineno', 'end_col_offset'))):
            return None
    guard_span = _span(checker.identity.file_path, observed.guard_span)
    raise_span = _span(checker.identity.file_path, observed.raise_span)
    candidates = [n for n in ast.walk(checker.node) if isinstance(n, ast.If)
                  and _span(checker.identity.file_path, n.test) == guard_span
                  and len(n.body) == 1 and isinstance(n.body[0], ast.Raise)
                  and _span(checker.identity.file_path, n.body[0]) == raise_span]
    if len(candidates) != 1:
        return None
    branch = candidates[0]
    presence = branch.test
    while isinstance(presence, ast.BoolOp) and isinstance(presence.op, ast.And):
        presence = presence.values[-1]
    parameters = set(checker.signature.positional_only + checker.signature.positional_or_keyword
                     + checker.signature.keyword_only)
    parameters.update(p for p in (checker.signature.kwarg, checker.signature.vararg) if p)
    if (not isinstance(presence, ast.Name) or presence.id != observed.mapping_parameter
            or presence.id not in parameters):
        return None
    raised = branch.body[0]
    if (raised.cause is not None or not isinstance(raised.exc, ast.Call)
            or not isinstance(raised.exc.func, ast.Name)
            or raised.exc.func.id != observed.exception or raised.exc.keywords
            or len(raised.exc.args) > 1 or any(not isinstance(a, ast.Constant)
                or type(a.value) is not str for a in raised.exc.args)):
        return None
    matching = [f for f in facts if isinstance(f, dict)
                and f.get('kind') == 'capture_truth_rejection'
                and f.get('status') == 'requires_observation'
                and f.get('function') == summaries[0]['function']
                and f.get('parameter') == presence.id and f.get('exception') == observed.exception
                and f.get('guard_evidence') == guard_span and f.get('raise_evidence') == raise_span
                and f.get('presence_evidence') == _span(checker.identity.file_path, presence)
                and f.get('guard_completed') is False
                and f.get('runtime_rejection_confirmed') is False
                and f.get('source_hash')
                and f['source_hash'] == analysis.inputs.get('sha256', {}).get(
                    str(checker.identity.file_path))]
    return matching[0] if len(matching) == 1 else None
