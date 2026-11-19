## @package vppdetector.scan.cache
#  Cache completed scan results within one source analysis context.
#
#
#  Index transformation locations per rule and file. Copy mutable evidence on writes and reads of
#  completed results.
#  按规则及文件索引转换位置，在写入和读取已完成扫描结果时复制可变证据。



import ast
from copy import deepcopy

from ..models import replace_record as replace


## Copy mutable producer facts while sharing immutable scan result records.
## 复制可变生产者事实，同时共享不可变扫描结果记录。
#
#  @param result Completed scan result
#  @return Result with isolated nested producer facts
def _copy_result(result):
    findings, boundaries, schema = result

    # Use one memo for the entire result so shared evidence remains shared within this copy.
    # 整个结果共用复制记录，保证共享证据在副本内仍然共享。
    memo = {}
    copies = []
    for finding in findings:
        path = tuple(
            replace(step, conditions=deepcopy(step.conditions, memo)) if step.conditions else step
            for step in finding.path
        )
        if (
            finding.conditions
            or finding.receiver_type_evidence
            or any(step.conditions for step in finding.path)
        ):
            copies.append(
                replace(
                    finding,
                    path=path,
                    conditions=deepcopy(finding.conditions, memo),
                    receiver_type_evidence=deepcopy(finding.receiver_type_evidence, memo),
                )
            )
        else:
            copies.append(finding)
    return tuple(copies), boundaries, schema


## Cache syntax locations that disqualify open-container propagation.
## 缓存使容器传播不再开放的语法位置。
class TransformLocations:
    ## Initialize the separate location sets for both scan rules.
    ## 初始化两种扫描规则各自的位置集合。
    def __init__(self):
        self._comprehensions = {}
        self._returned = {}

    ## Check whether a location is a comprehension or a returned-value transformation.
    ## 检查位置是否为推导式或返回值转换。
    #
    #  @param functions Indexed functions from this context
    #  @param path Source path to inspect
    #  @param location Producer evidence source coordinates
    #  @param returned Select returned-value transformation rules
    #  @return Whether the location matches the selected rule
    def contains(
        self,
        functions,
        path,
        location,
        *,
        returned,
    ):
        cache = self._returned if returned else self._comprehensions
        if path not in cache:
            kinds = (
                (ast.BinOp, ast.UnaryOp, ast.BoolOp, ast.Compare, ast.JoinedStr, ast.FormattedValue)
                if returned
                else (ast.DictComp, ast.ListComp, ast.SetComp, ast.GeneratorExp)
            )
            cache[path] = frozenset(
                (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)
                for function in functions
                if function.identity.file_path == path
                for node in ast.walk(function.node)
                if isinstance(node, ast.expr) and isinstance(node, kinds)
            )

        return location in cache[path]


## Own completed scan results without exposing the mutable cache to callers.
## 管理已完成的扫描结果，不向调用方暴露可变缓存。
class ScanResults:
    ## Create an empty cache owned by one analysis context.
    ## 创建由单个分析上下文持有的空缓存。
    def __init__(self):
        self._completed = {}

    ## Reuse a completed scan for this entry and depth, or compute it once.
    ## 复用相同入口和深度的已完成扫描，否则执行计算。
    #
    #  @param entry Indexed entry including its source query context
    #  @param max_depth Maximum forwarding depth
    #  @param compute Operation producing a complete scan result
    #  @return Completed scan result
    def scan(self, entry, max_depth, compute):
        key = (entry.identity, max_depth, entry.query_class, entry.query_alias)
        if key not in self._completed:
            self._completed[key] = _copy_result(compute())
        return _copy_result(self._completed[key])
