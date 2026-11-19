## @package vppdetector.facts.conditional_bindings
#  Conditional source lookup and signature facts.
#
#
#  Admit source-state-dependent lookup and constructor signature facts under their recorded
#  conditions.
#  依据记录的条件接纳依赖源码状态的查找及构造器签名事实。



from .calls import identity_from_target
from .conditions import consistent_conditions
from .locations import _location


## Validate conditional source lookup evidence for a call.
## 校验调用的条件源码查找证据。
#
#  @param analysis Producer analysis containing conditional lookup facts
#  @param call Call fact being validated
#  @return Validated binding fact, or None when provenance is incomplete
def conditional_source_binding(analysis, call):
    facts = getattr(call, 'conditional_source_bindings', ())
    if (analysis.inputs.get('conditional_source_state') is not True
            or call.target is None or call.analysis_status != 'analyzed'
            or not isinstance(facts, (list, tuple)) or len(facts) != 1
            or call.target_status not in ('super_new', 'super_method', 'classmethod')):
        return None
    fact = facts[0]
    expected = []
    for value in call.receiver_sources:
        identity = value.get('class_type')
        if identity and identity not in expected:
            expected.append(identity)
    if (not isinstance(fact, dict) or fact.get('kind') != 'conditional_source_lookup'
            or fact.get('status') != 'required' or fact.get('runtime_target_confirmed') is not False
            or fact.get('feasibility') != 'not_proven' or fact.get('call_id') != call.id
            or identity_from_target(fact.get('target')) != identity_from_target(call.target)
            or fact.get('source_hashes') != analysis.inputs.get('sha256')
            or not isinstance(fact.get('call_evidence'), dict)
            or _location(fact['call_evidence']) != (call.lineno, call.col_offset,
                                                   call.end_lineno, call.end_col_offset)
            or fact['call_evidence'].get('file_path') != call.caller.file_path
            or fact.get('conditions') != getattr(call, 'conditions', ())
            or fact.get('receiver_classes') != expected or not expected):
        return None

    # A conditional lookup must identify the required branch conditions for this receiver.
    # 条件查找须给出当前接收者对应的必要分支条件。
    conditions = fact.get('conditions', ())
    if (not isinstance(conditions, (list, tuple)) or not 1 <= len(conditions) <= 128
            or any(not isinstance(condition, dict) for condition in conditions)
            or any(incoming.get('conditional_source_bindings') != facts
                   for incoming in getattr(call, 'analysis_contexts', ()))):
        return None
    required = [condition for condition in conditions
                if condition.get('kind') == 'source_state_preserved']
    if not required:
        return None
    for condition in required:
        evidence = condition.get('evidence')
        if (condition.get('status') != 'required' or condition.get('runtime_confirmed') is not False
                or condition.get('scope') != 'subsequent_source_lookup'
                or condition.get('feasibility') != 'not_proven'
                or condition.get('receiver_class') not in fact['receiver_classes']
                or not isinstance(condition.get('effect_target'), dict)
                or condition['effect_target'].get('file_path') not in fact['source_hashes']
                or not isinstance(evidence, dict)
                or evidence.get('file_path') not in fact['source_hashes']
                or not all(type(value) is int for value in _location(evidence))
                or condition.get('effect_call') != '{}:{}:{}:{}:{}'.format(
                    evidence['file_path'], *_location(evidence))):
            return None
    return fact


## Validate a conditional constructor signature without claiming body execution.
## 校验条件构造器签名，但不据此认定构造器函数体已执行。
#
#  @param analysis Producer analysis containing constructor binding facts
#  @param call Constructor call fact being validated
#  @return Validated signature fact, or None when evidence is incomplete
def conditional_constructor_signature(analysis, call):
    facts = getattr(call, 'conditional_source_bindings', ())
    ordinary = getattr(call, 'constructor_bindings', ())
    if (analysis.inputs.get('conditional_source_state') is not True
            or call.target_status != 'constructor' or call.target is None
            or call.binding_status == 'invalid'
            or not isinstance(facts, (list, tuple)) or len(facts) != 1
            or not isinstance(ordinary, (list, tuple)) or len(ordinary) != 1):
        return None

    fact, binding = facts[0], ordinary[0]
    if not isinstance(fact, dict) or not isinstance(binding, dict):
        return None
    target_identity = identity_from_target(call.target)
    if target_identity is None:
        return None
    target, receiver = fact.get('target'), fact.get('receiver_class')
    conditions, assumptions = fact.get('conditions'), fact.get('assumptions')
    issues, evidence = fact.get('unconfirmed_binding_issues'), fact.get('call_evidence')
    required = {'source_snapshot_bindings_hold', 'builtin_type_call_and_new_binding',
                'no_external_monkeypatch_or_import_hook', 'no_unmodeled_indirect_class_mutation'}
    if (fact.get('kind') != 'conditional_constructor_signature'
            or fact.get('status') != 'required' or fact.get('scope') != 'signature_only'
            or fact.get('runtime_target_confirmed') is not False
            or fact.get('feasibility') != 'not_proven' or fact.get('call_id') != call.id
            or not isinstance(target, dict) or target != binding.get('target')
            or identity_from_target(target) != identity_from_target(call.target)
            or not isinstance(receiver, dict) or receiver != binding.get('receiver_class')
            or binding.get('status') != 'unconfirmed' or binding.get('phase') != '__init__'
            or not target_identity.qualname.endswith('.__init__')
            or not isinstance(issues, (list, tuple)) or not issues
            or issues != binding.get('issues')
            or any(not isinstance(issue, dict) or issue.get('reason') not in (
                'constructor_class_origin_unconfirmed', 'constructor_namespace_unconfirmed',
                'constructor_definition_evaluation_unconfirmed') for issue in issues)
            or not isinstance(assumptions, (list, tuple))
            or not all(isinstance(value, str) for value in assumptions)
            or not required.issubset(assumptions) or assumptions != binding.get('assumptions')
            or not fact.get('source_hashes')
            or fact['source_hashes'] != analysis.inputs.get('sha256')
            or target.get('file_path') not in fact['source_hashes']
            or receiver.get('file_path') not in fact['source_hashes']
            or not isinstance(evidence, dict) or evidence.get('file_path') != call.caller.file_path
            or _location(evidence) != (call.lineno, call.col_offset,
                                       call.end_lineno, call.end_col_offset)
            or not isinstance(conditions, (list, tuple)) or not 1 <= len(conditions) <= 128
            or any(not isinstance(condition, dict) for condition in conditions)
            or conditions != getattr(call, 'conditions', ())):
        return None

    predicates = [c for c in conditions if c.get('kind') == 'source_constructor_lookup']
    if len(predicates) != 1:
        return None
    predicate = predicates[0]
    probes = predicate.get('preceding_type_checks')
    if (predicate.get('status') != 'required' or predicate.get('scope') != 'signature_only'
            or predicate.get('runtime_confirmed') is not False
            or predicate.get('feasibility') != 'not_proven'
            or predicate.get('target') != target or predicate.get('receiver_class') != receiver
            or not isinstance(probes, (list, tuple)) or not 1 <= len(probes) <= 128
            or not all(isinstance(probe, str) for probe in probes)
            or not consistent_conditions(conditions)):
        return None

    # Verify the probes preceding the predicate so a possible early failure is preserved.
    # 校验谓词之前的探测调用，保留它们可能提前失败的边界。
    for probe_id in probes:
        matching = [prior for prior in analysis.calls if prior.id == probe_id]
        if len(matching) != 1:
            return None
        prior = matching[0]
        if (prior.caller != call.caller or prior.callee_name != 'isinstance'
                or prior.target_status != 'builtin_boundary' or prior.target is not None
                or (prior.lineno, prior.col_offset) >= (call.lineno, call.col_offset)
                or not any(arg.get('argument') == {'position': 1}
                           and any(v.get('class_type') == receiver for v in arg.get('sources', ()))
                           for arg in prior.argument_sources)):
            return None

    if (not any(b.get('reason') == 'conditional_constructor_signature'
                and b.get('call_id') == call.id and b.get('boundary_kind') == 'required_condition'
                and b.get('condition') == predicate for b in analysis.boundaries)
            or any(not isinstance(item, dict) or item.get('target') != target
                   or item.get('conditional_source_bindings') != facts
                   or item.get('constructor_bindings') != ordinary
                   for item in getattr(call, 'analysis_contexts', ()))):
        return None
    return fact
