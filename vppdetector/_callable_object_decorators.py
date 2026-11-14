## @package vppdetector._callable_object_decorators
#  Validate source facts for callable-object decorators
#  校验可调用对象装饰器的源码事实

import hashlib
from pathlib import Path

from ._program_facts import identity_from_target


## Validate PCResolve's callable-object identity proof for the selected function
## 校验PCResolve对选定函数的可调用对象装饰器身份证明
#
#  @param context Reusable analysis context for the selected source snapshot
#  @param analysis PCResolve analysis result being validated
#  @param function Indexed source function under analysis
#  @param fact Producer fact containing the identity proof
#  @return Validated proof, or None when evidence is incomplete
def source_callable_object_decorator_binding(context, analysis, function, fact):
    proof = fact.get('callable_object_identity_proof')
    if not isinstance(proof, dict) or len(function.node.decorator_list) != 1:
        return None
    decorator = function.node.decorator_list[0]
    expression = proof.get('expression')
    assumptions = proof.get('assumptions')
    required = {'source_callable_object_identity_decorator',
                'source_snapshot_bindings_hold',
                'module_initialization_completed_before_query',
                'no_external_monkeypatch_or_import_hook',
                'no_unmodeled_indirect_function_mutation'}
    if (proof.get('kind') != 'source_callable_object_identity'
            or proof.get('status') != 'source_bound'
            or proof.get('basis') != 'source_snapshot'
            or proof.get('completion') != 'normal_return'
            or proof.get('runtime_target_confirmed') is not False
            or proof.get('returned_object') != 'original_function'
            or proof.get('mutated_function_attributes') != ['__doc__']
            or identity_from_target(fact.get('function')) != function.identity
            or identity_from_target(proof.get('function')) != function.identity
            or not isinstance(expression, dict)
            or expression != fact.get('expression')
            or expression.get('file_path') != str(function.identity.file_path)
            or any(expression.get(key) != getattr(decorator, key) for key in (
                'lineno', 'col_offset', 'end_lineno', 'end_col_offset'))
            or not isinstance(assumptions, (list, tuple))
            or not all(isinstance(item, str) for item in assumptions)
            or not required.issubset(assumptions)):
        return None

    # 证据文件必须属于本次分析快照，且仍与快照内容一致
    hashes = analysis.inputs.get('sha256', {})
    proof_hashes = proof.get('source_hashes')
    decorator_files = proof.get('decorator_source_files')
    if (not isinstance(hashes, dict) or not isinstance(proof_hashes, dict)
            or not isinstance(decorator_files, (list, tuple)) or not decorator_files
            or any(not isinstance(path, str) or path not in proof_hashes
                   for path in decorator_files)
            or str(function.identity.file_path) not in proof_hashes
            or any(not isinstance(path, str) or not isinstance(digest, str)
                   or hashes.get(path) != digest for path, digest in proof_hashes.items())):
        return None
    try:
        for path, digest in proof_hashes.items():
            actual = hashlib.sha256(
                Path(path).read_text(encoding='utf-8-sig').encode('utf-8')).hexdigest()
            if actual != digest:
                return None
    except (OSError, UnicodeError):
        return None
    return {'assumptions': tuple(assumptions), 'source_hashes': proof_hashes,
            'decorator_target': fact.get('target'),
            'returned_object': 'original_function',
            'mutated_function_attribute': '__doc__'}
