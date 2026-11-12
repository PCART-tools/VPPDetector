## @package vppdetector._attribute_retention
#  Validate observed instance-attribute retention facts.
#  校验实例属性保留相关的运行观测事实。

"""Validate independent instance-retention observations against source stores."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path

from ._fact_adapter import ResolutionError
from ._observed_checks import _call
from ._program_facts import identity_from_target
from .models import FunctionIdentity, SourceSpan


## Require actual construction, original-capture retention and a matching source store
## 确认实际构造、原始捕获值保留及源码存储见证一致
#
#  @param context Reusable analysis context for the selected source snapshot
#  @param entry Resolved source entry for the requested API
#  @param call Original client call or its call-specific evidence
#  @param change Description of the removed or renamed parameter
#  @param original Value named `original` supplied by the enclosing analysis
#  @return Result of the `attribute_retention` operation
def attribute_retention(context, entry, call, change, original):
    if len(call.observed_attribute_retentions) != 1:
        return None
    observed = call.observed_attribute_retentions[0]
    bound = entry.is_bound_method if call.bound_receiver is None else call.bound_receiver
    if (entry.node.name != '__init__' or not bound
            or not entry.node.args.posonlyargs + entry.node.args.args
            or change.old_position is not None
            or not isinstance(observed.entry, FunctionIdentity) or observed.entry != entry.identity
            or observed.keyword != change.old_name or type(observed.attribute) is not str
            or type(observed.value) not in (str, bytes, int, float, bool, type(None))
            or type(original) is not type(observed.value) or original != observed.value
            or _call(observed.call_text) is None
            or _call(observed.call_text) != _call(call.expression)
            or observed.retained_builtin_dict is not True
            or observed.construction_confirmed is not True or observed.store_completed is not True
            or observed.completed_normally is not True
            or not isinstance(observed.store_span, SourceSpan)
            or not isinstance(observed.source_hashes, tuple)
            or not 1 <= len(observed.source_hashes) <= 2000):
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
    facts = summaries[0].get('mapping_attribute_transfers', ())
    if not isinstance(facts, (tuple, list)) or len(facts) != 1 or not isinstance(facts[0], dict):
        return None
    fact = facts[0]
    span = observed.store_span
    if (span.file_path != entry.identity.file_path or any(type(getattr(span, field)) is not int
            for field in ('lineno', 'col_offset', 'end_lineno', 'end_col_offset'))):
        return None
    expected = dict(file_path=str(span.file_path), lineno=span.lineno, col_offset=span.col_offset,
                    end_lineno=span.end_lineno, end_col_offset=span.end_col_offset)
    receiver = (entry.node.args.posonlyargs + entry.node.args.args)[0].arg
    if (fact.get('kind') != 'mapping_attribute_transfer'
            or fact.get('status') != 'requires_observation'
            or fact.get('function') != summaries[0]['function']
            or fact.get('parameter') != entry.signature.kwarg
            or fact.get('receiver') != receiver or fact.get('attribute') != observed.attribute
            or fact.get('store_evidence') != expected or fact.get('store_completed') is not False
            or fact.get('returned_instance_retention_proven') is not False
            or not fact.get('source_hash')
            or fact['source_hash'] != analysis.inputs.get('sha256', {}).get(
                str(entry.identity.file_path))):
        return None
    stores = [node for node in entry.node.body if isinstance(node, ast.Assign)
              and (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset) == (
                  span.lineno, span.col_offset, span.end_lineno, span.end_col_offset)]
    if len(stores) != 1:
        return None
    store = stores[0]
    if (len(store.targets) != 1 or not isinstance(store.value, ast.Name)
            or store.value.id != entry.signature.kwarg
            or not isinstance(store.targets[0], ast.Attribute)
            or not isinstance(store.targets[0].value, ast.Name)
            or store.targets[0].value.id != receiver
            or store.targets[0].attr != observed.attribute):
        return None
    return fact
