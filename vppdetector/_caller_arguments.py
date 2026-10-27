## @package vppdetector._caller_arguments
#  Read exact caller argument syntax without evaluating expressions.
#  读取精确的调用实参语法，不执行调用表达式。

"""Validate source-bound caller arguments without evaluating caller expressions."""

from __future__ import annotations

import ast
import hashlib
import math
import tokenize

from .models import SourceSpan


_FIELDS = ('lineno', 'col_offset', 'end_lineno', 'end_col_offset')
_ASSUMPTIONS = {'source_snapshot_bindings_hold', 'standard_module_global_lookup',
                'no_external_module_global_mutation'}


## Convert source coordinates into a validated source span
## 将源码坐标转换为经过校验的源码范围
#
#  @param record Producer record whose fields are validated.
#  @param path Filesystem path of the source being read or checked.
#  @return Result of the `_span` operation.
def _span(record, path):
    return (isinstance(record, dict) and record.get('file_path') == path
            and all(type(record.get(key)) is int for key in _FIELDS)
            and record['lineno'] > 0 and record['col_offset'] >= 0
            and record['end_col_offset'] >= 0
            and (record['end_lineno'], record['end_col_offset'])
            > (record['lineno'], record['col_offset']))


## Build a bounded abstract value from caller-provided literal input
## 根据调用方提供的字面量输入构建有界抽象值
#
#  @param value Value or producer record being interpreted.
#  @param budget Maximum amount of literal or container state to model.
#  @param depth Current recursive or structural analysis depth.
#  @return Result of the `_state` operation.
def _state(value, budget, depth=0):
    budget[0] -= 1
    if budget[0] < 0 or depth > 16 or not isinstance(value, dict):
        raise ValueError('Unbounded caller literal')
    kind = value.get('kind')
    if kind == 'scalar':
        name = value.get('type')
        item = value.get('value')
        if name == 'bytes':
            raw = value.get('value_hex')
            if not isinstance(raw, str) or len(raw) % 2:
                raise ValueError('Invalid bytes')
            item = bytes.fromhex(raw)
            if item.hex() != raw:
                raise ValueError('Invalid bytes encoding')
        elif (type(item) not in (str, int, float, bool, type(None))
              or type(item).__name__ != name
              or 'value' not in value or type(item) is float and not math.isfinite(item)):
            raise ValueError('Invalid scalar')
        return {'kind': 'literal', 'value': item}
    if kind in ('list', 'tuple') and isinstance(value.get('items'), list):
        return {'kind': kind, 'items': [_state(item, budget, depth + 1)
                                       for item in value['items']]}
    raise ValueError('Unsupported caller value')


## Return typed slot values and the target for this exact source call
## 返回此精确源码调用的类型化参数槽位和目标
#
#  @param adapter Value named `adapter` supplied by the enclosing analysis.
#  @param call Original client call or its call-specific evidence.
#  @param node AST node or source expression being analyzed.
#  @param target Producer target record or selected source target.
#  @param entry Resolved source entry for the requested API.
#  @return Result of the `caller_arguments` operation.
def caller_arguments(adapter, call, node, target, entry):
    if (not isinstance(call.callsite, SourceSpan)
            or not all(type(getattr(call.callsite, key)) is int for key in _FIELDS)):
        return None
    site = call.callsite
    path = str(site.file_path)
    try:
        fact = adapter.caller_inputs(site)
        identities = (target, entry.identity, entry.query_class, entry.query_alias)
        names = {f'{identity.module}.{identity.qualname}' for identity in identities
                 if identity is not None}
        if (entry.identity.qualname.endswith('.__init__')
                and entry.identity.module == target.module):
            class_name = entry.identity.qualname.rpartition('.')[0]
            if class_name:
                names.add(f'{entry.identity.module}.{class_name}')
        receiver_bound = (isinstance(fact, dict)
            and fact.get('target') is None
            and fact.get('target_status') == 'receiver_expression_only'
            and fact.get('target_expression') == ast.dump(node.func, include_attributes=False))

        # 只消费与当前目标、调用语法和证据范围一致的调用方事实
        if (not isinstance(fact, dict) or fact.get('kind') != 'source_callsite_inputs'
                or fact.get('status') != 'source_bound'
                or fact.get('scope') != 'argument_reads_on_normal_module_prefix'
                or fact.get('runtime_values_observed') is not False
                or fact.get('boundaries') != []
                or not (fact.get('target') in names or receiver_bound)
                or fact.get('call_syntax') != ast.dump(node, include_attributes=False)
                or not isinstance(fact.get('assumptions'), list)
                or not all(isinstance(item, str) for item in fact['assumptions'])
                or not _ASSUMPTIONS.issubset(fact['assumptions'])
                or not _span(fact.get('call_evidence'), path)
                or any(fact['call_evidence'][key] != getattr(site, key) for key in _FIELDS)):
            return None


        # 先校验支持源码及调用文件的哈希，避免复用过期事实
        supporting = fact.get('supporting_source_sha256', {})
        if not isinstance(supporting, dict):
            return None
        for support_path, support_digest in supporting.items():
            if not isinstance(support_path, str) or not isinstance(support_digest, str):
                return None
            with tokenize.open(support_path) as stream:
                support_text = stream.read()
            if hashlib.sha256(support_text.encode('utf-8')).hexdigest() != support_digest:
                return None

        with tokenize.open(path) as stream:
            source_text = stream.read()
        digest = hashlib.sha256(source_text.encode('utf-8')).hexdigest()
        if fact.get('source_hashes') != {path: digest}:
            return None


        # 完整位置和语法树都匹配时才将事实绑定到当前调用
        source_tree = ast.parse(source_text, filename=path)
        source_calls = [item for item in ast.walk(source_tree) if isinstance(item, ast.Call)
            and (item.lineno, item.col_offset, item.end_lineno, item.end_col_offset)
            == tuple(getattr(site, key) for key in _FIELDS)]
        if (len(source_calls) != 1
                or ast.dump(source_calls[0], include_attributes=False)
                != ast.dump(node, include_attributes=False)):
            return None
        source_node = source_calls[0]

        binding = fact.get('target_binding_evidence')
        receiver_binding_exact = (receiver_bound and isinstance(binding, list)
            and len(binding) == 1 and _span(binding[0], path)
            and all(binding[0][key] == getattr(node.func, key) for key in _FIELDS))
        if (not isinstance(binding, list) or not binding
                or receiver_bound and not receiver_binding_exact
                or not receiver_bound and any(
                    not _span(item, path) or (item['end_lineno'], item['end_col_offset'])
                    > (site.lineno, site.col_offset) for item in binding)):
            return None
        if any(isinstance(arg, ast.Starred) for arg in source_node.args) or any(
                kw.arg is None for kw in source_node.keywords):
            return None

        slots = [(('position', i), arg) for i, arg in enumerate(source_node.args)]
        slots.extend((('keyword', kw.arg), kw.value) for kw in source_node.keywords)
        records = fact.get('arguments')
        if not isinstance(records, list) or len(records) != len(slots):
            return None
        result, budget = {}, [2000]
        for record, (slot, argument) in zip(records, slots):
            if (not isinstance(record, dict) or record.get('argument') != dict([slot])
                    or record.get('status') not in (
                        'source_literal', 'source_protocol', 'unproven')):
                return None
            evidence = record.get('evidence')
            if (not isinstance(evidence, list) or not evidence
                    or any(not _span(item, path) for item in evidence)
                    or any(evidence[0][key] != getattr(argument, key) for key in _FIELDS)):
                return None
            if record['status'] == 'source_literal':
                result[slot] = _state(record.get('value'), budget)
            elif record['status'] == 'source_protocol':
                protocol = record.get('protocol')
                if (not isinstance(protocol, dict) or protocol.get('kind') != 'iterable'
                        or protocol.get('basis') != 'bounded_stub_return_protocol'
                        or not isinstance(protocol.get('call_target'), str)
                        or protocol.get('supporting_source_sha256') != supporting
                        or not supporting):
                    return None
                result[slot] = {'kind': 'iterable', 'basis': protocol['basis'],
                                'call_target': protocol['call_target']}
            elif 'value' in record:
                return None
        return result, tuple(fact['assumptions']), fact['target']
    except (AttributeError, OSError, UnicodeError, ValueError, TypeError, KeyError):
        return None
