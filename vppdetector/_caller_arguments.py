## @package vppdetector._caller_arguments
#  Read exact caller argument syntax without evaluating expressions.
#  读取精确的调用实参语法，不执行调用表达式。

"""Validate source-bound caller arguments without evaluating caller expressions."""

from __future__ import annotations

import ast
import hashlib
import math
import tokenize
from pathlib import Path

from .models import SourceSpan

_FIELDS = ('lineno', 'col_offset', 'end_lineno', 'end_col_offset')
_ASSUMPTIONS = {'source_snapshot_bindings_hold', 'standard_module_global_lookup',
                'no_external_module_global_mutation'}
_MAX_CALLER_FILE_SIZE = 1024 * 1024


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
    if (kind == 'caller_file_text' and isinstance(value.get('text'), str)
            and isinstance(value.get('path'), str)
            and isinstance(value.get('sha256'), str)
            and hashlib.sha256(value['text'].encode('utf-8')).hexdigest() == value['sha256']):
        return {'kind': kind, 'text': value['text'], 'path': value['path'],
                'sha256': value['sha256'],
                'context_evidence': value.get('context_evidence')}
    raise ValueError('Unsupported caller value')


## Identify abstract caller values whose contents may be mutated
## 识别内容可能被修改的调用方抽象值
#
#  @param value Abstract caller value.
#  @return Whether the value contains a mutable list.
def _mutable_state(value):
    if value.get('kind') == 'list':
        return True
    return (value.get('kind') == 'tuple'
            and any(_mutable_state(item) for item in value.get('items', [])))


## Resolve a bounded string assigned before a module-level context manager
## 解析模块级上下文管理器之前赋值的有界字符串
#
#  @param node String expression whose source value is requested.
#  @param tree Parsed caller source tree.
#  @param before_line Line before which the assignment must occur.
#  @return Static string value or `None` when the binding is unconfirmed.
def _module_string(node, tree, before_line):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if not isinstance(node, ast.Name):
        return None
    value = None
    for statement in tree.body:
        if getattr(statement, 'lineno', before_line) >= before_line:
            break
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            if any(isinstance(target, ast.Name) and target.id == node.id for target in targets):
                value = (statement.value.value if isinstance(statement.value, ast.Constant)
                         and isinstance(statement.value.value, str) else None)
        elif isinstance(statement, (ast.Import, ast.ImportFrom)):
            if any(alias.asname == node.id or alias.asname is None
                   and alias.name.split('.')[0] == node.id for alias in statement.names):
                value = None
    return value


## Collect names that bind a value through its validated assignment evidence
## 收集经已验证赋值证据绑定该值的名称
#
#  @param record Caller argument fact with validated source evidence.
#  @param tree Parsed caller source tree.
#  @return Names that may refer to the fact value.
def _fact_binding_names(record, tree):
    names = set()
    evidence = record.get('evidence', [])
    for index, location in enumerate(evidence):
        if index == 0:
            matches = [node for node in ast.walk(tree) if isinstance(node, ast.expr)
                       and all(getattr(node, key) == location[key] for key in _FIELDS)]
            if len(matches) == 1 and isinstance(matches[0], ast.Name):
                names.add(matches[0].id)
            continue
        matches = [node for node in tree.body
                   if isinstance(node, (ast.Assign, ast.AnnAssign))
                   and all(getattr(node, key) == location[key] for key in _FIELDS)]
        if len(matches) != 1:
            continue
        statement = matches[0]
        targets = (statement.targets if isinstance(statement, ast.Assign)
                   else [statement.target])
        names.update(target.id for target in targets if isinstance(target, ast.Name))
        if isinstance(statement.value, ast.Name):
            names.add(statement.value.id)
    return names


## Check whether a preceding call can receive or replace a source fact
## 检查前置调用是否可能接收或替换源码事实
#
#  @param boundary Validated call boundary record.
#  @param call_node Call expression recorded at the boundary.
#  @param fact_names Names bound to the caller argument fact.
#  @param source_origin First assignment that establishes the fact.
#  @param protocol_module Module that provides the bounded return protocol.
#  @param protocol_origin Assignment that invokes the protocol factory.
#  @return Whether the boundary can invalidate the fact.
def _boundary_affects_fact(boundary, call_node, fact_names, source_origin,
                           protocol_module=None, protocol_origin=None):
    location = boundary['evidence']
    boundary_position = (location['lineno'], location['col_offset'])
    if protocol_module is not None:
        if (protocol_origin is not None
                and all(location[key] == protocol_origin[key] for key in _FIELDS)):
            return False
        if boundary['target'].rpartition('.')[0] == protocol_module:
            return True
    if (source_origin is not None and boundary_position
            <= (source_origin['lineno'], source_origin['col_offset'])):
        return False
    call_arguments = list(call_node.args)
    call_arguments.extend(keyword.value for keyword in call_node.keywords)
    argument_names = {node.id for argument in call_arguments for node in ast.walk(argument)
                      if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)}
    return bool(fact_names & argument_names)


## Recover file text only from the exact open resource bound to this call
## 仅从与当前调用精确绑定的open资源中恢复文件文本
#
#  @param fact Validated PCResolve caller input record.
#  @param source_node Exact call node in the caller source.
#  @param tree Parsed caller source tree.
#  @param path Absolute caller source path.
#  @param execution_directory Absolute project execution directory.
#  @return File text record by argument slot, or an empty mapping.
def _caller_file_values(fact, source_node, tree, path, execution_directory):
    if execution_directory is None:
        return {}
    contexts = fact.get('context_managers')
    bindings = fact.get('context_argument_bindings')
    if not isinstance(contexts, list) or not isinstance(bindings, list):
        return {}
    call_record = fact.get('call_evidence')
    if not _span(call_record, path):
        return {}
    fields = ('lineno', 'col_offset', 'end_lineno', 'end_col_offset')
    if any(call_record[field] != getattr(source_node, field) for field in fields):
        return {}
    arguments = [({'position': index}, value)
                 for index, value in enumerate(source_node.args)]
    arguments.extend(({'keyword': keyword.arg}, keyword.value)
                     for keyword in source_node.keywords)
    result = {}
    for binding in bindings:
        if not isinstance(binding, dict):
            continue
        slot, name = binding.get('argument'), binding.get('name')
        manager_index = binding.get('manager_index')
        if (not isinstance(slot, dict) or not isinstance(name, str)
                or type(manager_index) is not int or not 0 <= manager_index < len(contexts)):
            continue
        argument = next((value for candidate, value in arguments if candidate == slot), None)
        if not isinstance(argument, ast.Name) or argument.id != name:
            continue
        context = contexts[manager_index]
        if (not isinstance(context, dict) or context.get('kind') != 'context_manager'
                or context.get('runtime_value_observed') is not False):
            continue
        manager = context.get('manager')
        binding_record = context.get('binding')
        if (not isinstance(manager, dict) or not isinstance(binding_record, dict)
                or binding_record.get('name') != name):
            continue
        binding_span = binding_record.get('evidence')
        if not _span(binding_span, path):
            continue
        manager_span = manager.get('evidence')
        if not _span(manager_span, path):
            continue
        manager_nodes = [item for item in ast.walk(tree) if isinstance(item, ast.Call)
                         and all(getattr(item, key) == manager_span[key] for key in fields)]
        if len(manager_nodes) != 1:
            continue
        manager_call = manager_nodes[0]
        if (not isinstance(manager_call.func, ast.Name) or manager_call.func.id != 'open'
                or manager.get('target') != 'builtins.open'
                or manager.get('call_syntax') != ast.dump(manager_call, include_attributes=False)
                or manager.get('source_text') != ast.unparse(manager_call)):
            continue
        manager_statement = next((item for item in ast.walk(tree)
                                  if isinstance(item, (ast.With, ast.AsyncWith))
                                  and any(candidate.context_expr is manager_call
                                          and isinstance(candidate.optional_vars, ast.Name)
                                          and candidate.optional_vars.id == name
                                          for candidate in item.items)), None)
        with_span = context.get('with_evidence')
        if (manager_statement is None
                or not _span(with_span, path)
                or any(getattr(manager_statement, key) != with_span.get(key)
                       for key in fields)):
            continue
        item = next(candidate for candidate in manager_statement.items
                    if candidate.context_expr is manager_call)
        if any(getattr(item.optional_vars, key) != binding_span.get(key)
               for key in fields):
            continue
        parents = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[id(child)] = parent
        current, enclosed = source_node, False
        while id(current) in parents:
            current = parents[id(current)]
            if current is manager_statement:
                enclosed = True
                break
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                break
        if not enclosed:
            continue
        shadowed_open = False
        for statement in tree.body:
            if statement.lineno >= manager_statement.lineno:
                break
            if any(isinstance(child, ast.Name) and child.id == 'open'
                   and isinstance(child.ctx, ast.Store) for child in ast.walk(statement)):
                shadowed_open = True
                break
            if isinstance(statement, (ast.Import, ast.ImportFrom)) and any(
                    (alias.asname or alias.name.split('.')[0]) == 'open'
                    for alias in statement.names):
                shadowed_open = True
                break
            if (isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                    and statement.name == 'open'):
                shadowed_open = True
                break
        if shadowed_open or not manager_call.args or len(manager_call.args) > 2:
            continue
        path_value = _module_string(manager_call.args[0], tree, manager_statement.lineno)
        mode_node = (manager_call.args[1] if len(manager_call.args) == 2 else
                     next((item.value for item in manager_call.keywords
                           if item.arg == 'mode'), None))
        mode = _module_string(mode_node, tree, manager_statement.lineno) if mode_node else 'r'
        encoding_node = next((item.value for item in manager_call.keywords
                              if item.arg == 'encoding'), None)
        encoding = (_module_string(encoding_node, tree, manager_statement.lineno)
                    if encoding_node is not None else None)
        errors_node = next((item.value for item in manager_call.keywords
                            if item.arg == 'errors'), None)
        errors = (_module_string(errors_node, tree, manager_statement.lineno)
                  if errors_node is not None else 'strict')
        newline_node = next((item.value for item in manager_call.keywords
                             if item.arg == 'newline'), None)
        if (path_value is None or mode not in ('r', 'rt') or encoding is None
                or encoding.lower().replace('_', '-') not in ('utf-8', 'utf8', 'utf-8-sig')
                or errors != 'strict'
                or newline_node is not None and not (
                    isinstance(newline_node, ast.Constant) and newline_node.value is None)
                or any(item.arg not in ('mode', 'encoding', 'errors', 'newline')
                       for item in manager_call.keywords)):
            continue
        file_path = Path(path_value)
        if not file_path.is_absolute():
            file_path = Path(execution_directory) / file_path
        try:
            file_path = file_path.resolve(strict=True)
            if not file_path.is_file() or file_path.stat().st_size > _MAX_CALLER_FILE_SIZE:
                continue
            with open(file_path, 'r', encoding=encoding, errors='strict', newline=None) as stream:
                text = stream.read(_MAX_CALLER_FILE_SIZE + 1)
            if len(text) > _MAX_CALLER_FILE_SIZE:
                continue
            digest = hashlib.sha256(text.encode('utf-8')).hexdigest()
        except (OSError, UnicodeError, ValueError):
            continue
        result[('position' if 'position' in slot else 'keyword',
                slot.get('position', slot.get('keyword')))] = {
            'kind': 'caller_file_text', 'text': text,
            'path': str(file_path), 'sha256': digest,
            'context_evidence': context.get('with_evidence'),
        }
    return result


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
                or not isinstance(fact.get('boundaries'), list)
                or any(not isinstance(item, dict)
                       or item.get('reason') != 'caller_prefix_call_effect_unconfirmed'
                       or not _span(item.get('evidence'), path)
                       for item in fact['boundaries'])
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

        # 检查每条调用边界是否可能改写协议事实所依赖的工厂模块
        boundaries = fact['boundaries']
        boundary_calls = []
        for boundary in boundaries:
            location = boundary['evidence']
            matching = [item for item in source_tree.body
                        if isinstance(item, (ast.Assign, ast.AnnAssign))
                        and all(getattr(item, key) == location[key] for key in _FIELDS)]
            if (not isinstance(boundary.get('target'), str)
                    or len(matching) != 1
                    or not isinstance(matching[0].value, ast.Call)):
                return None
            boundary_calls.append((boundary, matching[0].value))

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
                value = _state(record.get('value'), budget)
                if _mutable_state(value):
                    assignments = record.get('evidence', [])[1:]
                    source_origin = min(assignments,
                        key=lambda item: (item['lineno'], item['col_offset']),
                        default=None)
                    names = _fact_binding_names(record, source_tree)
                    if any(_boundary_affects_fact(boundary, boundary_call, names,
                            source_origin) for boundary, boundary_call in boundary_calls):
                        continue
                result[slot] = value
            elif record['status'] == 'source_protocol':
                protocol = record.get('protocol')
                if (not isinstance(protocol, dict) or protocol.get('kind') != 'iterable'
                        or protocol.get('basis') != 'bounded_stub_return_protocol'
                        or not isinstance(protocol.get('call_target'), str)
                        or protocol.get('supporting_source_sha256') != supporting
                        or not supporting):
                    return None
                factory_module = protocol['call_target'].rpartition('.')[0]
                protocol_origin = next((boundary['evidence']
                    for boundary, _ in boundary_calls
                    if boundary['target'] == protocol['call_target']
                    and any(all(boundary['evidence'][key] == item[key]
                                for key in _FIELDS) for item in evidence[1:])), None)
                source_origin = min(evidence[1:],
                    key=lambda item: (item['lineno'], item['col_offset']),
                    default=None)
                names = _fact_binding_names(record, source_tree)
                affected = any(_boundary_affects_fact(boundary, boundary_call,
                    names, source_origin, factory_module, protocol_origin)
                    for boundary, boundary_call in boundary_calls)
                if affected:
                    continue
                result[slot] = {'kind': 'iterable', 'basis': protocol['basis'],
                                'call_target': protocol['call_target']}
            elif 'value' in record:
                return None
        file_values = (_caller_file_values(
            fact, source_node, source_tree, path, call.execution_directory)
            if not boundaries else {})
        for slot, value in file_values.items():
            if slot not in result:
                result[slot] = _state(value, budget)
        return result, tuple(fact['assumptions']), fact['target']
    except (AttributeError, OSError, UnicodeError, ValueError, TypeError, KeyError):
        return None
