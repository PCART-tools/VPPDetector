## @package vppdetector.facts.builtin_protocols
#  Validate builtin protocol obligations without deciding consumer policy.
#
#
#  Admit exact builtin callability, length and truth facts only when their source and protocol
#  premises match.
#  仅在源码及协议前提一致时接纳精确内置对象的可调用性、长度和真值事实。



from .locations import _location


## Validate the producer's bool model, whose exact input is a query obligation
## 校验生产者提供的bool模型及其精确输入义务
#
#  @param analysis PCResolve analysis result being validated or consumed
#  @param call PCResolve producer call record being analyzed
#  @return Validated bool protocol fact, or None if the evidence does not match
def scalar_truth_protocol(analysis, call):
    fact = getattr(call, 'implicit_protocol', {})

    # A truth obligation applies only if the consumer later establishes an exact scalar type.
    # 仅当消费方随后确认输入为精确的标量类型时，才可使用该真值条件。
    if (not isinstance(fact, dict) or fact.get('kind') != 'builtin_scalar_truth'
            or fact.get('builtin') != 'bool' or call.callee_name != 'bool'
            or call.target is not None or call.target_status != 'python_protocol'
            or call.binding_status != 'complete' or call.binding_issues or call.effects
            or fact.get('status') != 'requires_exact_input'
            or fact.get('runtime_input_confirmed') is not False
            or fact.get('precondition') != {'argument': {'position': 0},
                'exact_types': ['NoneType', 'bool', 'int', 'float', 'str', 'bytes']}
            or fact.get('completion') != 'normal_return_if_precondition'
            or fact.get('effects') != 'none_if_precondition'
            or fact.get('call_id') != call.id
            or fact.get('source_hash') != analysis.inputs.get('sha256', {}).get(
                call.caller.file_path)
            or not isinstance(fact.get('evidence'), dict)
            or fact['evidence'].get('file_path') != call.caller.file_path
            or _location(fact['evidence']) != (call.lineno, call.col_offset,
                                              call.end_lineno, call.end_col_offset)
            or any(item.get('implicit_protocol') != fact
                   for item in getattr(call, 'analysis_contexts', ()))):
        return None
    return fact


## Read callability only for exact noncallable builtin input types
## 仅对精确的非可调用内建输入读取callable事实
#
#  @param analysis PCResolve analysis result being validated or consumed
#  @param call PCResolve producer call record being analyzed
#  @return Validated callable protocol fact, or None if the evidence does not match
def exact_callability_protocol(analysis, call):
    fact = getattr(call, 'implicit_protocol', {})

    # The false result concerns the exact input object type, independent of its contents.
    # 假值结论取决于输入对象的精确类型，与对象内容无关。
    if (not isinstance(fact, dict) or fact.get('kind') != 'builtin_exact_callability'
            or fact.get('builtin') != 'callable' or call.callee_name != 'callable'
            or call.target is not None or call.target_status != 'python_protocol'
            or call.binding_status != 'complete' or call.binding_issues or call.effects
            or fact.get('status') != 'requires_exact_input'
            or fact.get('runtime_input_confirmed') is not False
            or fact.get('precondition') != {'argument': {'position': 0}, 'exact_types': [
                'NoneType', 'bool', 'int', 'float', 'str', 'bytes',
                'dict', 'list', 'tuple', 'set', 'frozenset']}
            or fact.get('result') is not False
            or fact.get('dependency') != 'input_object_type_only'
            or fact.get('completion') != 'normal_return_if_precondition'
            or fact.get('effects') != 'none_if_precondition'
            or fact.get('call_id') != call.id
            or fact.get('source_hash') != analysis.inputs.get('sha256', {}).get(
                call.caller.file_path)
            or not isinstance(fact.get('evidence'), dict)
            or fact['evidence'].get('file_path') != call.caller.file_path
            or _location(fact['evidence']) != (call.lineno, call.col_offset,
                                              call.end_lineno, call.end_col_offset)
            or any(item.get('implicit_protocol') != fact
                   for item in getattr(call, 'analysis_contexts', ()))):
        return None
    return fact


## Read a length obligation; the consumer must establish the exact input type
## 读取长度检查义务，并要求消费者确认精确输入类型
#
#  @param analysis PCResolve analysis result being validated or consumed
#  @param call PCResolve producer call record being analyzed
#  @return Validated len protocol fact, or None if the evidence does not match
def container_length_protocol(analysis, call):
    fact = getattr(call, 'implicit_protocol', {})

    # Exact built-in length rules cannot be applied to a substituted user-defined protocol.
    # 该长度规则只适用于精确的内置类型。
    if (not isinstance(fact, dict) or fact.get('kind') != 'builtin_container_length'
            or fact.get('builtin') != 'len' or call.callee_name != 'len'
            or call.target is not None or call.target_status != 'python_protocol'
            or call.binding_status != 'complete' or call.binding_issues or call.effects
            or fact.get('status') != 'requires_exact_input'
            or fact.get('runtime_input_confirmed') is not False
            or fact.get('precondition') != {'argument': {'position': 0},
                'exact_types': ['dict', 'list', 'tuple', 'str', 'bytes', 'set', 'frozenset']}
            or fact.get('completion') != 'normal_return_if_precondition'
            or fact.get('effects') != 'none_if_precondition'
            or fact.get('call_id') != call.id
            or fact.get('source_hash') != analysis.inputs.get('sha256', {}).get(
                call.caller.file_path)
            or not isinstance(fact.get('evidence'), dict)
            or fact['evidence'].get('file_path') != call.caller.file_path
            or _location(fact['evidence']) != (call.lineno, call.col_offset,
                                              call.end_lineno, call.end_col_offset)
            or any(item.get('implicit_protocol') != fact
                   for item in getattr(call, 'analysis_contexts', ()))):
        return None
    return fact
