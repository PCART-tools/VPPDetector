## @package vppdetector._fresh_decoration
#  Validate metadata isolation for freshly decorated functions.
#  校验新装饰函数的元数据隔离条件。

"""Validate fresh function metadata isolation, without assuming callback purity."""

import ast

from ._program_facts import identity_from_target


_ASSUMPTIONS = {'source_snapshot_bindings_hold', 'fresh_source_function_before_name_binding',
    'fresh_function_metadata_noninterference', 'standard_builtin_namespace_preserved',
    'no_unmodeled_indirect_builtin_mutation', 'standard_sys_frame_metadata_protocol',
    'source_frame_metadata_non_escape', 'no_unmodeled_indirect_frame_or_gc_observation',
    'no_external_frame_or_gc_observation', 'no_external_monkeypatch_or_import_hook',
    'source_module_initialization_completed_before_query',
    'no_unmodeled_indirect_module_mutation', 'no_unmodeled_indirect_function_mutation'}
_COORDINATES = ('lineno', 'col_offset', 'end_lineno', 'end_col_offset')
## Return one independently guarded body-binding fact or no fallback
## 返回一条独立校验的函数体绑定事实；无法证明时不回退
#
#  @param context Reusable analysis context for the selected source snapshot.
#  @param analysis PCResolve analysis result being validated or consumed.
#  @param function Indexed source function under analysis.
#  @param summary Producer summary for the current function.
#  @return Result of the `binding` operation.
def binding(context, analysis, function, summary):
    records = summary.get('fresh_function_decorations')
    if not isinstance(records, (list, tuple)) or len(records) != 1:
        return None
    fact = records[0]
    if not isinstance(fact, dict):
        return None
    fresh, observer = fact.get('freshness'), fact.get('observation_guard')
    if (fact.get('kind') != 'source_fresh_function_decoration'
            or identity_from_target(fact.get('function')) != function.identity
            or fact.get('source_hashes') != analysis.inputs.get('sha256')
            or not isinstance(fact.get('assumptions'), (list, tuple))
            or any(not isinstance(value, str) for value in fact['assumptions'])
            or not _ASSUMPTIONS.issubset(fact['assumptions'])
            or not isinstance(fresh, dict) or not isinstance(observer, dict)
            or fresh.get('kind') != 'source_function_creation'
            or fresh.get('phase') != 'before_name_binding'
            or fresh.get('input_function_unescaped') is not True
            or fresh.get('runtime_allocation_confirmed') is not False
            or identity_from_target(fresh.get('function')) != function.identity
            or observer.get('source_hashes') != fact['source_hashes']
            or not isinstance(observer.get('assumptions'), (list, tuple))
            or any(not isinstance(value, str) for value in observer['assumptions'])
            or not set(observer['assumptions']).issubset(fact['assumptions'])
            or not (_ASSUMPTIONS - {'fresh_source_function_before_name_binding',
                'fresh_function_metadata_noninterference', 'standard_builtin_namespace_preserved',
                'no_unmodeled_indirect_builtin_mutation'}).issubset(observer['assumptions'])):
        return None

    ## Validate the producer witness required by the enclosing proof
    ## 校验所属证明所需的生产者见证
    #
    #  @param value Value or producer record being interpreted.
    #  @param owner Source identity that owns the queried behavior.
    #  @param node AST node or source expression being analyzed.
    #  @return Result of the `witness` operation.
    def witness(value, owner, node):
        return (isinstance(value, dict) and value.get('file_path') == str(owner.file_path)
                and all(value.get(field) == getattr(node, field) for field in _COORDINATES))

    if not witness(fresh.get('definition_evidence'), function.identity, function.node):
        return None
    return observation_guard(context, analysis, fact)


## Validate the source observation premises shared by fresh callable proofs
## 校验新可调用对象证明共用的源码观测前提
#
#  @param context Reusable analysis context for the selected source snapshot.
#  @param analysis PCResolve analysis result being validated or consumed.
#  @param fact Producer fact being validated or interpreted.
#  @return Result of the `observation_guard` operation.
def observation_guard(context, analysis, fact):
    observer = fact.get('observation_guard')
    required = _ASSUMPTIONS - {'fresh_source_function_before_name_binding',
        'fresh_function_metadata_noninterference', 'standard_builtin_namespace_preserved',
        'no_unmodeled_indirect_builtin_mutation'}
    assumptions = fact.get('assumptions')
    if (not isinstance(observer, dict)
            or fact.get('source_hashes') != analysis.inputs.get('sha256')
            or not isinstance(assumptions, (list, tuple))
            or any(not isinstance(value, str) for value in assumptions)
            or observer.get('source_hashes') != fact.get('source_hashes')
            or not isinstance(observer.get('assumptions'), (list, tuple))
            or any(not isinstance(value, str) for value in observer['assumptions'])
            or not required.issubset(observer['assumptions'])
            or not set(observer['assumptions']).issubset(assumptions)):
        return None

    ## Validate the producer witness required by the enclosing proof
    ## 校验所属证明所需的生产者见证
    #
    #  @param value Value or producer record being interpreted.
    #  @param owner Source identity that owns the queried behavior.
    #  @param node AST node or source expression being analyzed.
    #  @return Result of the `witness` operation.
    def witness(value, owner, node):
        return (isinstance(value, dict) and value.get('file_path') == str(owner.file_path)
                and all(value.get(field) == getattr(node, field) for field in _COORDINATES))

    namespace = observer.get('namespace_guard')
    if (not isinstance(namespace, dict)
            or namespace.get('scope') != 'bounded_source_callable_namespaces'
            or namespace.get('runtime_reflective_writes') != []
            or namespace.get('execution_field_writes') != []
            or not isinstance(namespace.get('module_initializers'), (list, tuple))):
        return None
    for record in namespace['module_initializers']:
        if (not isinstance(record, dict) or not isinstance(record.get('module'), str)
                or record.get('phase') not in ('module_initialization', 'new_export_only')
                or record.get('file_path') not in fact['source_hashes']
                or any(type(record.get(field)) is not int or record[field] < 0
                       for field in _COORDINATES)):
            return None
    metadata = observer.get('frame_metadata')
    if not isinstance(metadata, (list, tuple)) or len(metadata) > 1000:
        return None
    for record in metadata:
        if not isinstance(record, dict):
            return None
        identity = identity_from_target(record.get('function'))
        selected = context.index.find(identity) if identity is not None else None
        fields = record.get('fields')
        if (selected is None or record.get('kind') != 'source_frame_metadata_use'
                or record.get('status') != 'source_bound'
                or record.get('scope') != 'native_frame_metadata_only'
                or record.get('factory') not in ('sys._getframe', 'sys._current_frames',
                                                'traceback.walk_stack')
                or record.get('factory') == 'traceback.walk_stack'
                and 'standard_traceback_frame_iteration_protocol' not in assumptions
                or record.get('runtime_observation_confirmed') is not False
                or not isinstance(record.get('variable'), str) or not record['variable']
                or not isinstance(fields, (list, tuple))
                or any(not isinstance(value, str) for value in fields)
                or not set(fields).issubset(
                    {'f_back', 'f_code', 'f_globals', 'f_lineno', 'f_lasti'})
                or record.get('global_keys') != (['__name__'] if 'f_globals' in fields else [])
                or not any(isinstance(node, ast.Call)
                           and witness(record.get('evidence'), identity, node)
                           for node in ast.walk(selected.node))):
            return None
    return fact


## Accept only the isolated native string/cache formatting obligation
## 仅接受隔离的内建字符串及缓存格式化操作
#
#  @param fact Producer fact being validated or interpreted.
#  @param effect Value named `effect` supplied by the enclosing analysis.
#  @return Result of the `documentation_format` operation.
def documentation_format(fact, effect):
    proof = effect.get('method_binding')
    callback = effect.get('callback_guard')
    callback_target = (identity_from_target(callback.get('target'))
                       if isinstance(callback, dict) else None)
    callback_evidence = callback.get('evidence') if isinstance(callback, dict) else None
    source = effect.get('object_source')
    constructions = [item for item in fact.get('effects', ()) if isinstance(item, dict)
                     and item.get('operation') == 'construction'
                     and item.get('target') == 'documentation_cache'
                     and item.get('object_source') == source]
    return (fact.get('kind') == 'source_fresh_function_decoration'
            and effect.get('operation') == 'isolated_documentation_format'
            and effect.get('impact') == 'fresh_function_unreachable'
            and effect.get('protocol') == 'native_string_mapping_format'
            and effect.get('input_shape') == 'str' and effect.get('output_shape') == 'str'
            and effect.get('input_function_passed') is False
            and effect.get('completion') == 'normal_return_only'
            and isinstance(source, str) and bool(source) and len(constructions) == 1
            and isinstance(proof, dict) and proof.get('status') == 'source_bound'
            and proof.get('kind') == 'builtin_method_binding'
            and proof.get('builtin') == 'dict.__getitem__'
            and proof.get('basis') == 'source_snapshot'
            and proof.get('runtime_target_confirmed') is False
            and proof.get('receiver_class') == constructions[0].get('class')
            and isinstance(proof.get('assumptions'), (list, tuple))
            and all(isinstance(value, str) for value in proof['assumptions'])
            and {'source_snapshot_bindings_hold',
                 'source_class_receiver_without_instance_shadowing',
                 'no_external_monkeypatch_or_import_hook'}.issubset(proof['assumptions'])
            and set(proof['assumptions']).issubset(fact.get('assumptions', ()))
            and isinstance(callback, dict)
            and callback.get('kind') == 'source_metadata_callback_structure'
            and callback.get('status') == 'source_bound'
            and callback.get('scope') == 'no_known_invalid_slice_or_unbound_raise'
            and callback.get('normal_completion_proven') is False
            and callback_target is not None and callback_target.qualname.endswith('.__missing__')
            and str(callback_target.file_path) in fact['source_hashes']
            and isinstance(callback_evidence, dict)
            and callback_evidence.get('file_path') == str(callback_target.file_path)
            and callback_evidence.get('lineno') == callback_target.lineno)
