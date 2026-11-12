## @package vppdetector._fresh_receiver
#  Validate source proofs for fresh-instance lookup.
#  校验新实例属性查找所需的源码证明。

"""Validate producer proofs for a fresh source instance's lookup prefix."""

from __future__ import annotations

from ._fresh_decoration import observation_guard
from ._program_facts import _creation_hook_premises, identity_from_target


_ASSUMPTIONS = {'source_snapshot_bindings_hold', 'builtin_type_call_and_new_binding',
    'builtin_object_allocation_empty_dictionary', 'builtin_instance_method_descriptor',
    'no_external_monkeypatch_or_import_hook', 'no_unmodeled_indirect_class_mutation',
    'no_unmodeled_indirect_instance_mutation', 'no_external_frame_or_gc_observation',
    'python_method_lookup_precedes_argument_evaluation'}
_FIELDS = ('lineno', 'col_offset', 'end_lineno', 'end_col_offset')


## Check the source premises required for a fresh decorated receiver
## 检查新装饰接收者所需的源码前提
#
#  @param analysis PCResolve analysis result being validated or consumed
#  @param entry Resolved source entry for the requested API
#  @param allocation Producer facts describing object allocation
#  @return Result of the `_decoration_premises` operation
def _decoration_premises(analysis, entry, allocation):
    records = entry.get('class_decorations')
    if allocation.get('class_decorations') != records:
        return False
    if records is None:
        return True
    if not isinstance(records, (list, tuple)) or not 1 <= len(records) <= 512:
        return False
    hashes = analysis.inputs.get('sha256', {})
    for fact in records:
        if not isinstance(fact, dict):
            return False
        names, claims = fact.get('attributes'), fact.get('assumptions')
        sources = fact.get('source_hashes')
        if fact.get('kind') == 'source_class_alias_decoration':
            required = {'source_snapshot_bindings_hold', 'source_module_fresh_class_prefix',
                'source_literal_alias_map', 'source_direct_accessor_bindings',
                'standard_functools_wraps_protocol', 'standard_builtin_namespace_preserved',
                'no_external_monkeypatch_or_import_hook', 'no_unmodeled_indirect_class_mutation'}
            generated = fact.get('generated_class_members')
            generated_names = (
                [item.get('attribute') for item in generated if isinstance(item, dict)]
                if isinstance(generated, (list, tuple)) else [])
            if (not isinstance(generated, (list, tuple)) or not generated
                    or len(generated_names) != len(generated)
                    or any(item.get('kind') != 'source_alias_method'
                           or item.get('wrapper_body') != 'forward_same_arguments_to_target_method'
                           or not isinstance(item.get('target_method'), str)
                           or item.get('function_metadata')
                           != 'functools_wraps_then_alias_name_and_doc'
                           for item in generated)
                    or len(set(generated_names)) != len(generated_names)
                    or not isinstance(names, (list, tuple))
                    or set(names) != set(generated_names) | {'_alias_map'}):
                return False
        elif fact.get('kind') == 'source_metadata_instance_class_decoration':
            required = {'source_snapshot_bindings_hold', 'source_metadata_instance_decorator',
                        'no_external_monkeypatch_or_import_hook',
                        'no_unmodeled_indirect_class_mutation'}
            if names != [] or fact.get('metadata_attributes') != ['__doc__']:
                return False
        elif fact.get('kind') == 'source_class_decoration':
            required = {'source_snapshot_bindings_hold', 'builtin_type_attribute_writes',
                'no_external_monkeypatch_or_import_hook', 'no_unmodeled_indirect_class_mutation',
                'no_external_frame_introspection'}
        else:
            return False
        if (fact.get('kind') not in {'source_class_decoration',
                                    'source_class_alias_decoration',
                                    'source_metadata_instance_class_decoration'}
                or fact.get('status') != 'source_bound'
                or fact.get('basis') != 'source_snapshot'
                or fact.get('identity_status') != 'preserved'
                or fact.get('completion') != 'normal_return_only'
                or fact.get('preserved_scope') != 'other_class_attributes'
                or fact.get('runtime_identity_confirmed') is not False
                or fact.get('receiver_class') not in entry.get('hierarchy', ())
                or not isinstance(names, (list, tuple)) or len(names) > 2000
                or any(not isinstance(name, str) or not name or name == 'mro'
                       or name.startswith('__') and name.endswith('__') for name in names)
                or len(set(names)) != len(names)
                or not isinstance(claims, (list, tuple))
                or any(not isinstance(claim, str) for claim in claims)
                or not required.issubset(claims)
                or not set(claims).issubset(entry.get('assumptions', ()))
                or not set(claims).issubset(allocation.get('assumptions', ()))
                or not isinstance(sources, dict) or not sources
                or any(not isinstance(path, str) or path not in hashes
                       or hashes[path] != digest for path, digest in sources.items())):
            return False
    return True


## Determine whether allocation facts show a changed receiver state
## 判断分配事实是否表明接收者状态发生变化
#
#  @param allocation Producer facts describing object allocation
#  @return Result of the `_changed` operation
def _changed(allocation):
    return {name for field in ('class_creation_hooks', 'class_decorations')
            for record in allocation.get(field) or () for name in record['attributes']}


## Match a finite sequence of producer-bound invocations to a fresh class entry
## 将有限的生产者调用序列匹配到新类入口
#
#  @param analysis PCResolve analysis result being validated or consumed
#  @param origin Value named `origin` supplied by the enclosing analysis
#  @param context Reusable analysis context for the selected source snapshot
#  @return Result of the `origin_binding` operation
def origin_binding(analysis, origin, context=None):
    root = analysis.inputs.get('entry_binding', {}).get('fresh_receiver_origin')
    if not isinstance(root, dict) or not isinstance(origin, dict):
        return False
    entry = analysis.inputs.get('entry_binding', {})
    allocation = root.get('allocation')
    if (not isinstance(allocation, dict) or not _creation_hook_premises(analysis, entry)
            or allocation.get('class_creation_hooks') != entry.get('class_creation_hooks')
            or not _decoration_premises(analysis, entry, allocation)):
        return False
    observation = allocation.get('frame_observation', 'no_visible_frame_or_gc_hooks')
    if observation == 'native_metadata_only':
        if context is None or observation_guard(context, analysis, allocation) is None:
            return False
    elif observation != 'no_visible_frame_or_gc_hooks' or 'observation_guard' in allocation:
        return False
    changed = _changed(allocation)
    path = origin.get('path')
    if not isinstance(path, (list, tuple)) or len(path) > 32:
        return False
    expected = dict(root)
    for call_id in path:
        edges = [edge for edge in analysis.calls if edge.id == call_id]
        if len(edges) != 1:
            return False
        edge = edges[0]
        if edge.callee_name.rsplit('.', 1)[-1] in changed:
            return False
        records = getattr(edge, 'instance_method_bindings', ())
        if len(records) != 1 or records[0].get('origin') != expected:
            return False
        binding = records[0]
        receivers = [item for item in edge.parameter_bindings
                     if item.get('argument') == {'receiver': True}
                     and item.get('status') == 'exact']
        if (len(receivers) != 1 or binding.get('status') != 'source_bound'
                or identity_from_target(binding.get('target')) != identity_from_target(edge.target)
                or binding.get('source_hashes') != analysis.inputs.get('sha256')):
            return False
        expected = {**expected, 'current_function': binding['target'],
                    'parameter': receivers[0]['parameter'],
                    'own_attributes': binding['own_attributes'],
                    'path': [*expected['path'], call_id]}
    return origin == expected


## Consume one complete ordinary source binding and its allocation origin
## 消费完整的普通源码绑定及其对象分配来源
#
#  @param analysis PCResolve analysis result being validated or consumed
#  @param call Original client call or its call-specific evidence
#  @param context Reusable analysis context for the selected source snapshot
#  @return Result of the `method_binding` operation
def method_binding(analysis, call, context=None):
    bindings = getattr(call, 'instance_method_bindings', ())
    if (analysis.inputs.get('conditional_source_state') or call.target is None
            or call.target_status not in ('instance_method', 'receiver_type_evidence',
                                          'lexical_method_candidate')
            or not isinstance(bindings, (list, tuple)) or len(bindings) != 1):
        return None
    fact = bindings[0]
    if not isinstance(fact, dict):
        return None
    origin = fact.get('origin')
    if not isinstance(origin, dict) or not isinstance(origin.get('allocation'), dict):
        return None
    allocation = origin['allocation']
    root = analysis.inputs.get('entry_binding', {})
    source = fact.get('call_evidence')
    hashes = analysis.inputs.get('sha256')
    claims = fact.get('assumptions')
    if (fact.get('kind') != 'fresh_source_instance_method' or fact.get('status') != 'source_bound'
            or fact.get('basis') != 'source_snapshot'
            or fact.get('runtime_target_confirmed') is not False
            or fact.get('issues') != [] or fact.get('instance_state') != 'lookup_prefix_only'
            or fact.get('descriptor') != 'plain_source_function'
            or identity_from_target(fact.get('target')) != identity_from_target(call.target)
            or fact.get('call_id') != call.id or not isinstance(hashes, dict) or not hashes
            or fact.get('source_hashes') != hashes or allocation.get('source_hashes') != hashes
            or not isinstance(claims, (list, tuple)) or not _ASSUMPTIONS.issubset(claims)
            or not _ASSUMPTIONS.issubset(allocation.get('assumptions', ()))
            or allocation.get('kind') != 'builtin_object_new'
            or allocation.get('basis') != 'source_snapshot'
            or allocation.get('runtime_allocation_confirmed') is not False
            or fact.get('receiver_class') != allocation.get('receiver_class')
            or root.get('status') != 'source_bound' or root.get('phase') != '__init__'
            or root.get('fresh_receiver_origin', {}).get('allocation') != allocation
            or not origin_binding(analysis, origin, context)
            or identity_from_target(origin.get('current_function'))
               != identity_from_target(call.caller)
            or not isinstance(origin.get('parameter'), str)
            or not call.callee_name.startswith(origin['parameter'] + '.')
            or not isinstance(source, dict) or source.get('file_path') != call.caller.file_path
            or any(source.get(key) != getattr(call, key) for key in _FIELDS)
            or not isinstance(fact.get('own_attributes'), (list, tuple))
            or any(not isinstance(name, str) for name in fact['own_attributes'])
            or call.callee_name.rsplit('.', 1)[-1] in fact['own_attributes']
            or not call.receiver_sources
            or any(value.get('fresh_receiver_origin') != origin for value in call.receiver_sources)
            or any(incoming.get('instance_method_bindings') != bindings
                   or incoming.get('target') != fact['target']
                   for incoming in getattr(call, 'analysis_contexts', ()))):
        return None
    changed = _changed(allocation)
    if call.callee_name.rsplit('.', 1)[-1] in changed:
        return None
    boundaries = [item for item in analysis.boundaries if item.get('call_id') == call.id
                  and item.get('reason') == 'dynamic_method_override_possible']
    if not boundaries or any(item.get('boundary_kind') != 'assumption'
                             or item.get('binding_status') != 'source_bound'
                             for item in boundaries):
        return None
    return fact
