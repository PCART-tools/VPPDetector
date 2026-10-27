## @package vppdetector._normal_returns
#  Validate normal completion and mapping-retention evidence.
#  校验正常完成及映射保留证据。

"""Require actual completion and a producer-proven mapping retention path."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path

from ._fact_adapter import ResolutionError
from ._observed_checks import _call
from ._program_facts import identity_from_target
from .models import FunctionIdentity, SourceSpan


## Validate one call-specific observation and its conditional source transfer
## 验证一次特定调用的运行观测及其条件性源码转移
#
#  @param context Reusable analysis context for the selected source snapshot.
#  @param entry Resolved source entry for the requested API.
#  @param call Original client call or its call-specific evidence.
#  @param change Description of the removed or renamed parameter.
#  @param original Value named `original` supplied by the enclosing analysis.
#  @return Result of the `mapping_return` operation.
def mapping_return(context, entry, call, change, original):
    if len(call.observed_normal_returns) != 1:
        return None
    observed = call.observed_normal_returns[0]
    span = observed.return_span
    if (not isinstance(observed.entry, FunctionIdentity)
            or observed.entry != entry.identity or change.old_position is not None
            or observed.keyword != change.old_name
            or type(observed.value) not in (str, bytes, int, float, bool, type(None))
            or type(observed.value) is not type(original) or observed.value != original
            or not isinstance(observed.return_span, SourceSpan)
            or observed.returned_builtin_dict is not True
            or _call(observed.call_text) is None
            or _call(observed.call_text) != _call(call.expression)
            or not isinstance(observed.source_hashes, tuple)
            or not 1 <= len(observed.source_hashes) <= 2000):
        return None
    if (not isinstance(span.file_path, Path) or any(type(getattr(span, name)) is not int
            for name in ('lineno', 'col_offset', 'end_lineno', 'end_col_offset'))):
        return None
    try:

        hashes = dict(observed.source_hashes)
        if len(hashes) != len(observed.source_hashes) or entry.identity.file_path not in hashes:
            return None
        for path, digest in hashes.items():
            if (not isinstance(path, Path) or path not in context.index.files
                    or type(digest) is not str
                    or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
                return None
        analysis = context.adapter.analyze(entry.identity)
    except (OSError, TypeError, ValueError, ResolutionError):
        return None

    summaries = [f for f in analysis.functions
                 if identity_from_target(f.get('function')) == entry.identity]
    if len(summaries) != 1:
        return None
    facts = summaries[0].get('mapping_return_transfers', ())
    if not isinstance(facts, (list, tuple)) or len(facts) != 1 or not isinstance(facts[0], dict):
        return None

    fact = facts[0]
    expected = {'file_path': str(span.file_path), 'lineno': span.lineno,
                'col_offset': span.col_offset, 'end_lineno': span.end_lineno,
                'end_col_offset': span.end_col_offset}
    path, excluded = fact.get('return_path'), fact.get('excluded_keys')
    if (fact.get('kind') != 'normal_return_mapping_transfer' or fact.get('status') != 'conditional'
            or fact.get('function') != summaries[0]['function']
            or fact.get('parameter') != entry.signature.kwarg
            or fact.get('return_evidence') != expected
            or fact.get('normal_completion_proven') is not False
            or fact.get('source_hash') != analysis.inputs.get('sha256', {}).get(
                str(entry.identity.file_path))
            or not fact.get('source_hash') or not isinstance(path, list) or len(path) > 4
            or not all(type(key) is str for key in path)
            or not isinstance(excluded, list) or not all(type(key) is str for key in excluded)
            or observed.keyword in excluded
            or fact.get('assumptions') != [
                'standard_builtin_dict', 'no_external_frame_introspection']):
        return None

    witnesses = []
    for evidence, kind in ((fact.get('update_evidence'), ast.Call), (expected, ast.Return)):
        if (not isinstance(evidence, dict)
                or evidence.get('file_path') != str(entry.identity.file_path)
                or any(type(evidence.get(field)) is not int for field in (
                    'lineno', 'col_offset', 'end_lineno', 'end_col_offset'))):
            return None
        matches = [node for node in ast.walk(entry.node) if isinstance(node, kind)
                   and tuple(evidence[field] for field in (
                       'lineno', 'col_offset', 'end_lineno', 'end_col_offset')) == (
                           node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)]
        if len(matches) != 1:
            return None
        witnesses.append(matches[0])
    update, returned = witnesses
    if (not isinstance(returned.value, ast.Name)
            or returned.value.id != fact.get('return_root')
            or not isinstance(update.func, ast.Attribute) or update.func.attr != 'update'
            or update.keywords or len(update.args) != 1
            or not isinstance(update.args[0], ast.Name)
            or update.args[0].id != fact['parameter']):
        return None

    receiver, actual_path = update.func.value, []
    while isinstance(receiver, ast.Subscript):
        if not isinstance(receiver.slice, ast.Constant) or type(receiver.slice.value) is not str:
            return None
        actual_path.insert(0, receiver.slice.value)
        receiver = receiver.value
    if (not isinstance(receiver, ast.Name) or receiver.id != returned.value.id
            or actual_path != path):
        return None
    return fact
