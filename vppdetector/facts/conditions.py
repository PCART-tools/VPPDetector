## @package vppdetector.facts.conditions
#  Shared source-backed condition fact readers.
#
#
#  Cache bounded constant tests and check that producer witness syntax and path conditions agree.
#  缓存有界常量测试，核对生产者见证语法与路径条件是否一致。



import ast
from pathlib import Path

from ..facts.calls import identity_from_target
from ..facts.locations import _location, _node_location


## Parse a bounded expression supplied by a condition witness.
## 解析条件见证提供的有界表达式。
#
#  @param text Source text to parse
#  @return Expression node, or None when invalid or outside the size limit
def _expression(text):
    if not isinstance(text, str) or len(text) > 4096:
        return None
    try:
        node = ast.parse(text, mode="eval").body
        return node if sum(1 for _ in ast.walk(node)) <= 128 else None
    except (SyntaxError, ValueError, RecursionError):
        return None


## Determine truth for supported constant boolean expressions.
## 判定受支持常量布尔表达式的真假。
#
#  @param node Expression node to inspect
#  @param depth Current recursion depth
#  @return Boolean truth, or None when it cannot be established
def _constant_truth(node, depth=0):
    if depth > 16:
        return None
    if isinstance(node, ast.Constant) and type(node.value) in (
        str,
        bytes,
        int,
        float,
        bool,
        type(None),
    ):
        return bool(node.value)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        truth = _constant_truth(node.operand, depth + 1)
        return not truth if truth is not None else None
    if isinstance(node, ast.BoolOp):
        values = [_constant_truth(value, depth + 1) for value in node.values]
        decisive = isinstance(node.op, ast.Or)
        if decisive in values:
            return decisive
        if all(value is not None for value in values):
            return not decisive
    return None


## Cache source-backed constant tests for one immutable source index.
## 为单个固定源码索引缓存基于源码的常量条件。
class ConstantTests:
    ## Initialize an empty per-context constant test cache.
    ## 初始化上下文专属的常量条件缓存。
    def __init__(self):
        self._tests = {}

    ## Look up the proven truth and syntax at one source location.
    ## 查找指定源码位置已证明的真假值和语法。
    #
    #  @param index Source index defining available condition nodes
    #  @param path Source path associated with the condition
    #  @param witness Producer location record
    #  @return Truth and syntax, or None when no constant test is established
    def lookup(self, index, path, witness):
        if path not in self._tests:
            tests = {}
            roots = [
                function.node for function in index.functions if function.identity.file_path == path
            ]
            roots.extend(index.condition_nodes.get(path, ()))
            for root in roots:
                for node in ast.walk(root):
                    if not isinstance(node, (ast.Constant, ast.UnaryOp, ast.BoolOp)):
                        continue
                    truth = _constant_truth(node)
                    if truth is not None:
                        tests[_node_location(node)] = (truth, ast.dump(node))
            self._tests[path] = tests
        return self._tests[path].get(_location(witness))


## Check whether cached source conditions permit one producer fact.
## 检查缓存的源码条件是否允许采用某条生产者事实。
#
#  @param index Source index containing the condition syntax
#  @param constant_tests Context-owned cache of constant condition facts
#  @param value Producer fact whose branch conditions are checked
#  @return Whether the fact remains possible under the indexed source conditions
def conditions_possible(index, constant_tests, value):
    for condition in value.get("conditions", ()):
        branch = condition.get("branch")
        witness = condition.get("test", {})
        if type(branch) is not bool or not isinstance(witness, dict):
            continue
        path = Path(witness.get("file_path", ""))
        test = constant_tests.lookup(index, path, witness)
        if test is None or test[0] == branch:
            continue
        expression = _expression(witness.get("source_text"))
        if expression is not None and ast.dump(expression) == test[1]:
            return False
    return True


## Check that recorded branches do not contradict each other.
## 检查已记录的分支条件是否相互矛盾。
#
#  @param conditions Producer condition records
#  @return False for malformed records or contradictory branches, otherwise True
def consistent_conditions(conditions):
    seen = {}
    for condition in conditions:
        if not isinstance(condition, dict):
            return False
        test, branch = condition.get("test"), condition.get("branch")
        if not isinstance(test, dict) or type(branch) is not bool:
            continue
        key = test.get("file_path"), _location(test), test.get("source_text")
        if key in seen and seen[key] != branch:
            return False
        seen[key] = branch
    return True


## Select compatible conditions for a source-backed call path.
## 为具有源码依据的调用路径选择相容条件。
#
#  @param analysis Producer analysis for the caller
#  @param call Producer call record
#  @param target Selected source target identity
#  @param flow Producer forwarding fact
#  @return Condition records, or None when path facts are invalid or incompatible
def conditional_path_conditions(
    analysis,
    call,
    target,
    flow,
):
    if analysis.inputs.get("conditional_source_state") is not True:
        return ()
    conditions = list(getattr(call, "conditions", ())) + list(flow.get("conditions", ()))
    paths = getattr(call, "candidate_paths", ())
    if not isinstance(paths, (list, tuple)) or len(paths) > 128:
        return None
    candidate_contexts = []
    if not paths:
        target_owner, _, _ = target.qualname.rpartition(".")
        for source in getattr(call, "receiver_sources", ()):
            if not isinstance(source, dict):
                continue
            declared = {
                identity_from_target(item) for item in source.get("instance_candidates", ())
            }
            for context in source.get("instance_candidate_contexts", ()):
                owner = (
                    identity_from_target(context.get("instance_type"))
                    if isinstance(context, dict)
                    else None
                )
                predicates = context.get("conditions") if isinstance(context, dict) else None
                if (
                    owner is not None
                    and owner.qualname == target_owner
                    and owner == next((item for item in declared if item == owner), None)
                    and isinstance(predicates, (list, tuple))
                    and all(isinstance(item, dict) for item in predicates)
                ):
                    candidate_contexts.append(tuple(predicates))

    # Use only condition paths belonging to this call and target.
    # 条件路径必须属于当前调用和目标，避免混入其他候选接收者的事实
    if paths:
        if any(
            not isinstance(path, dict)
            or not isinstance(path.get("conditions"), (list, tuple))
            or len(path["conditions"]) > 128
            for path in paths
        ):
            return None
        compatible = [
            path
            for path in paths
            if path.get("call_id") == call.id
            and identity_from_target(path.get("target")) == target
            and consistent_conditions(conditions + list(path.get("conditions", ())))
        ]
        if not compatible:
            return None
        conditions += list(compatible[0].get("conditions", ()))
    elif any(
        source.get("instance_candidate_contexts")
        for source in getattr(call, "receiver_sources", ())
        if isinstance(source, dict)
    ):
        if not candidate_contexts or not all(
            consistent_conditions(conditions + list(candidate)) for candidate in candidate_contexts
        ):
            return None
        for item in candidate_contexts[0]:
            if item not in conditions:
                conditions.append(item)

    # Recheck conditions after combining call, flow and candidate-path evidence.
    # 合并调用、数据流和候选路径的证据后，重新检查条件是否一致。
    result = []
    for condition in conditions:
        if condition not in result:
            result.append(condition)
    return tuple(result) if consistent_conditions(result) else None
