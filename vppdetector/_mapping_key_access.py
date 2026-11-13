## @package vppdetector._mapping_key_access
#  Read optional PCResolve mapping-key footprints without assuming execution.
#  读取可选的 PCResolve 映射键访问足迹，不假定其已执行。

from __future__ import annotations

from ._program_facts import identity_from_target


## Validate and convert a producer target into a source identity
## 校验并将生产者目标转换为源码身份
#
#  @param value Producer target record to convert
#  @return Source identity, or None if the producer record is invalid
def _identity(value):
    try:
        return identity_from_target(value)
    except (TypeError, ValueError):
        return None


## Return a validated fixed-key access set, or no closed footprint
## 返回已验证的固定键访问集合；证据不足时不推断封闭键集
#
#  @param analysis PCResolve analysis result being validated or consumed
#  @param function Indexed source function under analysis
#  @return Validated set of accessed keys, or None if the footprint is unproven
def closed_keys(analysis, function):
    summaries = [item for item in analysis.functions
                 if isinstance(item, dict)
                 and _identity(item.get('function')) == function.identity]
    if len(summaries) != 1:
        return None
    facts = summaries[0].get('mapping_key_accesses', ())
    hashes = analysis.inputs.get('sha256', {})
    if not isinstance(facts, (list, tuple)) or len(facts) != 1 or not isinstance(hashes, dict):
        return None
    fact = facts[0]
    if (not isinstance(fact, dict) or fact.get('kind') != 'mapping_key_access'
            or fact.get('status') != 'key_local' or fact.get('protocol') != 'keyword_capture'
            or fact.get('parameter') != function.signature.kwarg
            or not isinstance(fact.get('function'), dict)
            or _identity(fact['function']) != function.identity
            or not fact.get('source_hash')
            or fact['source_hash'] != hashes.get(str(function.identity.file_path))
            or fact.get('control_flow_proven') is not False
            or fact.get('assumptions') != ['no_external_frame_introspection']):
        return None
    keys, accesses = fact.get('keys'), fact.get('accesses')
    if (not isinstance(keys, list) or not keys or not all(type(key) is str for key in keys)
            or len(keys) != len(set(keys)) or not isinstance(accesses, list)
            or not 1 <= len(accesses) <= 4000):
        return None
    seen = set()
    for item in accesses:
        if (not isinstance(item, dict)
                or item.get('operation') not in {'get', 'getitem', 'contains', 'pop'}
                or type(item.get('key')) is not str or not isinstance(item.get('evidence'), dict)):
            return None
        span = item['evidence']
        if (span.get('file_path') != str(function.identity.file_path)
                or any(type(span.get(name)) is not int for name in (
                    'lineno', 'col_offset', 'end_lineno', 'end_col_offset'))
                or not function.node.lineno <= span['lineno'] <= span['end_lineno']
                <= function.node.end_lineno):
            return None
        seen.add(item['key'])
    return seen if seen == set(keys) else None
