## @package vppdetector._fixed_binding
#  Validate observed binding against source calls and signatures.
#  根据源码调用与签名校验运行时绑定观测。

"""Validate actual method binding using neutral PCResolve source calls and signatures."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path

from ._fact_adapter import ResolutionError
from ._observed_checks import _call
from ._program_facts import call_span, identity_from_target
from .models import FunctionIdentity, SourceSpan


## Require an original captured element actually binding a fixed formal at a source call
## 证明原始捕获元素在源码调用处实际绑定到固定形参
#
#  @param context Reusable analysis context for the selected source snapshot.
#  @param entry Resolved source entry for the requested API.
#  @param call Original client call or its call-specific evidence.
#  @param change Description of the removed or renamed parameter.
#  @param original Value named `original` supplied by the enclosing analysis.
#  @return Result of the `fixed_binding` operation.
def fixed_binding(context, entry, call, change, original):
    if len(call.observed_fixed_bindings) != 1:
        return None
    observed = call.observed_fixed_bindings[0]
    if (not all(isinstance(value, FunctionIdentity) for value in (
                observed.entry, observed.caller, observed.target))
            or observed.entry != entry.identity or change.old_position is not None
            or observed.keyword != change.old_name or observed.parameter != change.old_name
            or type(observed.mapping_variable) is not str
            or type(observed.value) not in (str, bytes, int, float, bool, type(None))
            or type(original) is not type(observed.value) or original != observed.value
            or _call(observed.call_text) is None
            or _call(observed.call_text) != _call(call.expression)
            or observed.target_bound_receiver is not True
            or observed.received_builtin_dict is not True or observed.origin_confirmed is not True
            or observed.target_entered is not True or observed.completed_normally is not True
            or not isinstance(observed.call_span, SourceSpan)
            or not isinstance(observed.source_hashes, tuple)
            or not 1 <= len(observed.source_hashes) <= 2000):
        return None

    caller = context.index.find(observed.caller)
    target = context.index.find(observed.target)
    if (caller is None or target is None or caller.identity != observed.caller
            or target.identity != observed.target or not target.is_bound_method
            or not isinstance(target.node, ast.FunctionDef) or target.node.decorator_list):
        return None

    # 排除隐式接收者，只接受目标签名中的固定关键字参数
    fixed = set(target.signature.positional_or_keyword + target.signature.keyword_only)
    positional = target.node.args.posonlyargs + target.node.args.args
    if not positional:
        return None
    fixed.discard(positional[0].arg)
    if observed.parameter not in fixed:
        return None

    span = observed.call_span
    if (span.file_path != caller.identity.file_path
            or any(type(getattr(span, field)) is not int for field in (
                'lineno', 'col_offset', 'end_lineno', 'end_col_offset'))):
        return None

    # 调用方和目标源码均须与观察记录及PCResolve分析快照一致
    try:
        hashes = dict(observed.source_hashes)
        if (len(hashes) != len(observed.source_hashes) or any(identity.file_path not in hashes
                for identity in (entry.identity, caller.identity, target.identity))):
            return None
        for path, digest in hashes.items():
            if (not isinstance(path, Path) or path not in context.index.files
                    or type(digest) is not str
                    or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
                return None
        caller_analysis = context.adapter.analyze(caller.identity)
        target_analysis = context.adapter.analyze(target.identity)
        for analysis, definition in ((caller_analysis, caller), (target_analysis, target)):
            path = definition.identity.file_path
            text = path.read_text(encoding='utf-8-sig')
            digest = hashlib.sha256(text.encode('utf-8')).hexdigest()
            if analysis.inputs.get('sha256', {}).get(str(path)) != digest:
                return None
    except (OSError, UnicodeError, TypeError, ValueError, ResolutionError):
        return None

    nodes = [n for n in ast.walk(caller.node) if isinstance(n, ast.Call)
             and (n.lineno, n.col_offset, n.end_lineno, n.end_col_offset) == (
                 span.lineno, span.col_offset, span.end_lineno, span.end_col_offset)]
    if len(nodes) != 1:
        return None
    node = nodes[0]
    if (node.args or len(node.keywords) != 1 or node.keywords[0].arg is not None
            or not isinstance(node.keywords[0].value, ast.Name)
            or node.keywords[0].value.id != observed.mapping_variable
            or not isinstance(node.func, ast.Attribute) or not isinstance(node.func.value, ast.Name)
            or node.func.attr != target.node.name):
        return None

    calls = [c for c in caller_analysis.calls if c.caller.qualname == caller.identity.qualname
             and c.caller.module == caller.identity.module
             and call_span(c) == span and c.callee_name == ast.unparse(node.func)]
    summaries = [s for s in target_analysis.functions
                 if identity_from_target(s.get('function')) == target.identity]
    parameters = target.node.args.posonlyargs + target.node.args.args + target.node.args.kwonlyargs
    parameters += [a for a in (target.node.args.vararg, target.node.args.kwarg) if a]
    if (len(calls) != 1 or len(summaries) != 1
            or summaries[0].get('parameters') != [a.arg for a in parameters]
            or not caller_analysis.inputs.get('sha256', {}).get(str(caller.identity.file_path))
            or not target_analysis.inputs.get('sha256', {}).get(str(target.identity.file_path))):
        return None
    return target
