## @package vppdetector._fresh_member_checks
#  Read member checks for statically bound fresh receivers.
#  读取静态绑定的新接收者上的成员检查。

from __future__ import annotations

import ast
from pathlib import Path

from ._fresh_receiver import _changed, origin_binding
from ._program_facts import identity_from_target


_FIELDS = ('lineno', 'col_offset', 'end_lineno', 'end_col_offset')
_ASSUMPTIONS = {'source_snapshot_bindings_hold', 'standard_builtin_namespace_preserved',
    'builtin_dictionary_items_order', 'no_unmodeled_indirect_builtin_mutation',
    'builtin_object_allocation_empty_dictionary', 'builtin_instance_method_descriptor',
    'no_external_monkeypatch_or_import_hook', 'no_unmodeled_indirect_instance_mutation'}
_TEMPORARY_ASSUMPTIONS = {'standard_library_contextmanager_protocol',
    'source_snapshot_bindings_hold', 'no_external_monkeypatch_or_import_hook',
    'builtin_instance_data_attribute_operations'}


## Check whether a function has the recognized context-manager decorator
## 检查函数是否带有受支持的上下文管理器装饰器
#
#  @param identity Source-level identity used for lookup
#  @param function Function AST node whose decorators are checked
#  @return Whether the function has the supported contextmanager decorator
def _contextmanager_decorator(identity, function):
    if len(function.decorator_list) != 1:
        return False
    expression = function.decorator_list[0]

    ## Render a dotted source expression without evaluating it
    ## 不执行表达式地生成点分隔源码名称
    #
    #  @param node Name or attribute expression AST to render
    #  @return Dotted name, or None if the expression is not a simple name or attribute
    def dotted(node):
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            prefix = dotted(node.value)
            return prefix + '.' + node.attr if prefix else None
        return None
    selected = dotted(expression)
    if not selected:
        return False
    try:
        tree = ast.parse(Path(identity.file_path).read_text(encoding='utf-8-sig'))
    except (OSError, UnicodeError, SyntaxError):
        return False
    aliases = {}
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            for item in statement.names:
                if item.name == 'contextlib':
                    aliases[item.asname or item.name] = 'contextlib'
        elif isinstance(statement, ast.ImportFrom) and statement.level == 0 \
                and statement.module == 'contextlib':
            for item in statement.names:
                if item.name == 'contextmanager':
                    aliases[item.asname or item.name] = 'contextlib.contextmanager'
    head, dot, tail = selected.partition('.')
    canonical = aliases.get(head, head) + (dot + tail if dot else '')
    return canonical == 'contextlib.contextmanager'


## Validate temporary receiver effects against the closed source proof
## 根据封闭源码证明校验临时接收者副作用
#
#  @param effects Producer effect records attached to the proof
#  @param fact Producer fact being validated or interpreted
#  @param origin Proven allocation origin of the receiver
#  @param analysis PCResolve analysis result being validated or consumed
#  @param context Reusable analysis context for the selected source snapshot
#  @param function Indexed source function under analysis
#  @return Set of temporary attribute names, or False if an effect is unproven
def _temporary_effects_valid(effects, fact, origin, analysis, context, function):
    if not isinstance(effects, (list, tuple)) or len(effects) > 8:
        return False
    names = set()
    for effect in effects:
        if not isinstance(effect, dict):
            return False
        manager = identity_from_target(effect.get('manager'))
        selected = context.index.find(manager) if manager is not None else None
        attributes = effect.get('attributes')
        assumptions = effect.get('assumptions')
        evidence = effect.get('evidence')
        hashes = effect.get('source_hashes')
        if (effect.get('kind') != 'bounded_temporary_receiver_attributes'
                or manager is None or selected is None or selected.is_overload
                or not _contextmanager_decorator(manager, selected.node)
                or effect.get('receiver_parameter') != fact.get('receiver_parameter')
                or effect.get('receiver_class') != fact.get('receiver_class')
                or effect.get('receiver_origin') != origin
                or effect.get('restored_on_all_exits') is not True
                or effect.get('runtime_protocol_confirmed') is not False
                or hashes != analysis.inputs.get('sha256')
                or not isinstance(attributes, (list, tuple)) or not attributes
                or any(not isinstance(name, str) or not name or name.startswith('__')
                       for name in attributes)
                or len(set(attributes)) != len(attributes)
                or not isinstance(assumptions, (list, tuple))
                or not _TEMPORARY_ASSUMPTIONS.issubset(assumptions)
                or not isinstance(evidence, dict)):
            return False
        function_evidence = evidence.get('function', {})
        decorator_evidence = evidence.get('decorator', {})
        yield_evidence = evidence.get('yield', {})
        invocation = evidence.get('invocation', {})
        nodes = list(ast.walk(selected.node))
        if (function_evidence.get('file_path') != str(manager.file_path)
                or function_evidence.get('lineno') != selected.node.lineno
                or function_evidence.get('end_lineno') != selected.node.end_lineno
                or decorator_evidence.get('file_path') != str(manager.file_path)
                or not any(item in selected.node.decorator_list
                           and decorator_evidence.get('lineno') == item.lineno
                           and decorator_evidence.get('end_lineno') == item.end_lineno
                           for item in selected.node.decorator_list)
                or yield_evidence.get('file_path') != str(manager.file_path)
                or not any(isinstance(item, ast.Yield)
                           and yield_evidence.get('lineno') == item.lineno
                           and yield_evidence.get('end_lineno') == item.end_lineno
                           for item in nodes)
                or invocation.get('file_path') != str(function.identity.file_path)
                or not any(isinstance(item, ast.Call)
                           and invocation.get('lineno') == item.lineno
                           and invocation.get('col_offset') == item.col_offset
                           and invocation.get('end_lineno') == item.end_lineno
                           and invocation.get('end_col_offset') == item.end_col_offset
                           for item in ast.walk(function.node))):
            return False
        names.update(attributes)
    return names


## Determine whether a proven key condition applies to the selected argument
## 判断已证明的键条件是否适用于选定实参
#
#  @param check Producer member-check fact containing the key condition
#  @param key Mapping key being tracked
#  @param function Indexed source function under analysis
#  @return Whether the condition applies, or None if it cannot be established
def key_condition_applies(check, key, function):
    conditions = check.get('key_conditions', ())
    if not conditions:
        return True if check.get('status') == 'requires_single_exact_mapping_item' else None
    if check.get('status') != 'requires_bounded_mapping_member' or len(conditions) != 1:
        return None
    condition = conditions[0]
    evidence = condition.get('evidence', {})
    if (condition.get('operator') not in ('Eq', 'NotEq')
            or condition.get('branch') not in ('body', 'orelse')
            or type(condition.get('value')) is not str
            or not isinstance(evidence, dict)
            or evidence.get('file_path') != str(function.identity.file_path)):
        return None
    tests = [node for node in ast.walk(function.node) if isinstance(node, ast.Compare)
             and all(evidence.get(field) == getattr(node, field)
                     for field in _FIELDS)]
    if len(tests) != 1:
        return None
    test = tests[0]
    parent = next((node for node in ast.walk(function.node)
                   if isinstance(node, ast.If) and node.test is test), None)
    if (parent is None or len(test.ops) != 1
            or type(test.ops[0]).__name__ != condition['operator']
            or len(test.comparators) != 1 or not isinstance(test.left, ast.Name)
            or test.left.id != check.get('key_variable')
            or not isinstance(test.comparators[0], ast.Constant)
            or test.comparators[0].value != condition['value']):
        return None

    # The producer's branch marker must correspond to the selected dynamic call
    # suite, verified by the lookup witness checked below.
    # 生产者的分支标记必须对应选中的动态调用分支，并由下方检查的查找见证确认。
    selected_suite = parent.body if condition['branch'] == 'body' else parent.orelse
    lookup = check.get('lookup_evidence', {})
    contains_lookup = any(isinstance(node, ast.Assign)
        and all(lookup.get(field) == getattr(node, field) for field in _FIELDS)
        for child in selected_suite for node in ast.walk(child))
    if not contains_lookup:
        return None
    same = key == condition['value']
    matched = same if condition['operator'] == 'Eq' else not same
    return matched if condition['branch'] == 'body' else not matched


## Validate a member check against its call, receiver and source witnesses
## 根据调用、接收者及源码见证校验成员检查
#
#  @param context Reusable analysis context for the selected source snapshot
#  @param analysis PCResolve analysis result being validated or consumed
#  @param function Indexed source function under analysis
#  @param summary Producer summary for the current function
#  @param fact Producer fact being validated or interpreted
#  @return Whether the member-check fact satisfies all required source premises
def _member_check_valid(context, analysis, function, summary, fact):
    if not isinstance(fact, dict):
        return False
    origin, names, stores = fact.get('origin'), fact.get('member_names'), fact.get('value_stores')
    effects = fact.get('temporary_context_effects', ())
    temporary_names = _temporary_effects_valid(
        effects, fact, origin, analysis, context, function)
    if temporary_names is False:
        return False
    expected_own_attributes = (sorted(set(origin.get('own_attributes', ())) | temporary_names)
                               if isinstance(origin, dict) else [])
    if (fact.get('kind') != 'fresh_mapping_member_check'
            or fact.get('status') not in ('requires_single_exact_mapping_item',
                                          'requires_bounded_mapping_member')
            or fact.get('attribute_requires_nondunder') is not True
            or fact.get('runtime_lookup_confirmed') is not False
            or fact.get('runtime_rejection_confirmed') is not False
            or identity_from_target(fact.get('function')) != function.identity
            or fact.get('source_hashes') != analysis.inputs.get('sha256')
            or fact.get('source_hash') != analysis.inputs.get('sha256', {}).get(
                str(function.identity.file_path))
            or not isinstance(origin, dict) or not origin_binding(analysis, origin, context)
            or identity_from_target(origin.get('current_function')) != function.identity
            or origin.get('parameter') != fact.get('receiver_parameter')
            or origin['allocation'].get('receiver_class') != fact.get('receiver_class')
            or fact.get('own_attributes') != expected_own_attributes
            or not isinstance(fact.get('assumptions'), (list, tuple))
            or not _ASSUMPTIONS.issubset(fact['assumptions'])
            or not isinstance(names, (list, tuple)) or len(names) > 2000
            or any(not isinstance(name, str) for name in names)
            or not isinstance(stores, dict) or not set(stores).issubset(names)):
        return False
    if key_condition_applies(fact, '', function) is None:
        return False
    ordinary = [{**item, 'kind': fact['kind'], 'status': fact['status']}
                for item in summary.get('keyword_checks', ()) if isinstance(item, dict)]
    if not any(all(fact.get(key) == value for key, value in item.items()) for item in ordinary):
        return False
    changed = _changed(origin['allocation'])
    if not changed.issubset(names) or changed & set(stores):
        return False
    nodes = list(ast.walk(function.node))
    for field, kind in (('iteration_evidence', ast.For), ('lookup_evidence', ast.Assign),
                        ('guard_evidence', ast.UnaryOp), ('raise_evidence', ast.Raise)):
        witness = fact.get(field)
        if (not isinstance(witness, dict)
                or witness.get('file_path') != str(function.identity.file_path)
                or not any(isinstance(node, kind) and all(witness.get(key) == getattr(node, key)
                           for key in _FIELDS) for node in nodes)):
            return False
    for name, store in stores.items():
        if not isinstance(store, dict):
            return []
        target = identity_from_target(store.get('target'))
        selected = context.index.find(target) if target is not None else None
        witness = store.get('evidence')
        if (selected is None or selected.is_overload or selected.node.decorator_list
                or target.qualname.rsplit('.', 1)[-1] != name
                or store.get('operation') != 'fresh_dictionary_value_store'
                or store.get('completion') != 'normal_return'
                or not isinstance(store.get('attribute'), str)
                or store['attribute'] in set(names) | set(fact['own_attributes'])
                or not isinstance(witness, dict)
                or witness.get('file_path') != str(target.file_path)
                or not any(isinstance(node, ast.Assign) and len(node.targets) == 1
                           and isinstance(node.targets[0], ast.Attribute)
                           and node.targets[0].attr == store['attribute']
                           and isinstance(node.value, ast.Name)
                           and node.value.id == store.get('parameter')
                           and all(witness.get(key) == getattr(node, key) for key in _FIELDS)
                           for node in ast.walk(selected.node))):
            return False
    return True


## Return validated static obligations, never runtime lookup observations
## 返回已验证的静态成员约束，不将其当作运行时查找观测
#
#  @param context Reusable analysis context for the selected source snapshot
#  @param analysis PCResolve analysis result being validated or consumed
#  @param function Indexed source function under analysis
#  @return List of validated member-check facts, or an empty list if unavailable
def member_checks(context, analysis, function):
    summaries = [item for item in analysis.functions
                 if identity_from_target(item.get('function')) == function.identity]
    if len(summaries) != 1:
        return []
    summary = summaries[0]
    records = summary.get('fresh_mapping_member_checks', ())
    if not isinstance(records, (list, tuple)) or not records or len(records) > 8:
        return []
    if not all(_member_check_valid(context, analysis, function, summary, fact)
               for fact in records):
        return []
    return list(records)
