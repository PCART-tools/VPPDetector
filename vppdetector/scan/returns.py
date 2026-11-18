## @package vppdetector.scan.returns
#  Route bounded returned-container flows for structural scanning.
#
#
#  Collect bounded return-flow call links and carry supported returned-container evidence into
#  the scan path.
#  收集有界返回流的调用关联，将受支持的返回容器证据接入扫描路径。



import ast
from pathlib import Path

from ..facts.adapter import ResolutionError
from ..facts.calls import call_span, direct_calls, identity_from_target
from ..facts.calls import target_status as _target_status
from ..facts.conditions import conditions_possible
from ..facts.containers import copy_protocol_target, preserved_mapping_remainder
from ..models import AnalysisBoundary, ForwardingStep, SourceSpan
from .flow import (
    _callee_body_boundaries,
    _capture_flows,
    _capture_return_value,
    _depends_on_parameter,
    _expand_body,
    _open_container,
    _proven_object_alias,
    _receiver_contexts,
    _return_binding_path,
    _return_operation_boundary,
    _routable_return,
    _target_definition,
)


## Convert a return endpoint into a source span when possible.
## 在可能时将返回端点转换为源码范围。
#
#  @param endpoint Return endpoint or AST node
#  @param owner Function owning the endpoint
#  @return Source span, or None when no stable location exists
def _endpoint_span(
    endpoint,
    owner,
):
    if not isinstance(endpoint, ast.AST):
        return call_span(endpoint)
    path = owner.identity.file_path
    if path is None:
        return None
    node = endpoint
    end_line = node.end_lineno if node.end_lineno is not None else node.lineno
    end_column = node.end_col_offset if node.end_col_offset is not None else node.col_offset
    return SourceSpan(path, node.lineno, node.col_offset, end_line, end_column)


## Own one return-flow query's mutable graph and diagnostic boundaries.
## 管理一次返回流查询的可变图和诊断边界。
#
class _ReturnFlowCollector:
    ## Initialize bounded return-flow collection for one scan path.
    ## 初始化一条扫描路径的有界返回流收集状态。
    #
    #  @param context Source and producer context for the scan
    #  @param state Current scan state
    #  @param destination Return-flow destination
    #  @param boundaries Boundary ledger receiving unsupported cases
    #  @param CallBinding Binding record factory
    #  @param ReturnCall Call summary record factory
    def __init__(
        self,
        context,
        state,
        destination,
        boundaries,
        CallBinding,
        ReturnCall,
    ):
        self.context = context
        self.state = state
        self.destination = destination
        self.boundaries = boundaries
        self.CallBinding = CallBinding
        self.ReturnCall = ReturnCall
        # These maps cross into PCResolve's intentionally owner-neutral router.
        # 这些表交给与具体分析策略解耦的 PCResolve 返回值路由器。
        self.summaries = {}
        self.calls = {}
        self.producers = {}
        self.protocols = {}

    ## Build an analysis boundary for an unsupported return-flow path
    ## 为不受支持的返回流路径构建分析边界
    #
    #  @param code Machine-readable analysis boundary code
    #  @param message Explanation of the unsupported return-flow path
    #  @param call Analyzed call edge used to locate the boundary
    def boundary(self, code, message, call):
        self.boundaries.append(
            AnalysisBoundary(code, message, identity_from_target(call.caller), call_span(call))
        )

    ## Collect returned values only when their source and control-flow evidence is safe
    ## 仅在来源及控制流证据可靠时收集返回值
    #
    #  @param values Abstract values propagated through the analysis
    #  @param owner Indexed source function owning the returned value
    #  @param owner_analysis Producer analysis for the owning function
    #  @param endpoint Owning function node or call where returned values are read
    #  @param remaining Forwarding depth left for the analysis
    #  @param captured Names whose wildcard capture paths can be normalized
    #  @return Routable values supported by current source and control-flow evidence
    def safe_values(
        self,
        values,
        owner,
        owner_analysis,
        endpoint,
        remaining,
        captured=(),
    ):
        conditioned = self._conditioned_values(values, owner, endpoint)
        if conditioned is None:
            return []
        values = conditioned
        object_context = self._object_endpoint(values, owner, owner_analysis, endpoint, remaining)
        if object_context is None:
            return []
        endpoints, object_path = object_context
        result = self._routable_values(values, owner, owner_analysis, endpoint)
        result = self._capture_values(result, owner, endpoint, captured)
        if object_path and result:
            return self._object_contents(endpoints[0], object_path, result)
        return result

    ## Remove impossible return values and reject inseparable object contents.
    ## 移除不可能的返回值，并拒绝无法与对象上下文分离的内容。
    #
    #  @param values Candidate abstract return values
    #  @param owner Function owning the values
    #  @param endpoint Return endpoint being checked
    #  @return Feasible values, or None when their object context is inconsistent
    def _conditioned_values(
        self,
        values,
        owner,
        endpoint,
    ):
        values = list(values)
        # Materialized contents need not repeat the object's branch conditions.
        # Dropping an impossible endpoint alone could leave its stale inputs
        # looking like an independent open container after a control-flow join.
        # 已物化内容可能不带对象的分支条件。仅移除不可能的终点会让其旧输入
        # 在汇合后被当作独立开放容器。
        if any(
            (value.get("object_only") or value.get("container_object"))
            and not conditions_possible(
                self.context.index, self.context.constant_tests, value
            )
            for value in values
        ):
            self.boundaries.append(
                AnalysisBoundary(
                    "return_object_unproven",
                    "Current contents cannot be separated from an impossible object context.",
                    owner.identity,
                    _endpoint_span(endpoint, owner),
                )
            )
            return None
        return [
            value for value in values
            if conditions_possible(self.context.index, self.context.constant_tests, value)
        ]

    ## Resolve the unique returned object context, if one is present.
    ## 若存在返回对象上下文，则解析唯一上下文。
    #
    #  @param values Candidate abstract return values
    #  @param owner Function owning the values
    #  @param owner_analysis Producer analysis for the owner
    #  @param endpoint Return endpoint being checked
    #  @param remaining Forwarding depth remaining
    #  @return Object endpoints and context path, or None when ambiguous
    def _object_endpoint(
        self,
        values,
        owner,
        owner_analysis,
        endpoint,
        remaining,
    ):
        endpoints = [
            value for value in values if value.get("object_only") or value.get("container_object")
        ]
        if not endpoints:
            return endpoints, None
        if len(endpoints) != 1:
            self.boundaries.append(
                AnalysisBoundary(
                    "return_object_unproven",
                    "Returned object contexts are conflicting.",
                    owner.identity,
                    _endpoint_span(endpoint, owner),
                )
            )
            return None
        path = self.object_context(endpoints[0], owner, owner_analysis, remaining)
        return (endpoints, path) if path is not None else None

    ## Keep only returned values whose paths and operations remain bounded.
    ## 仅保留路径和操作均保持有界的返回值。
    #
    #  @param values Candidate abstract return values
    #  @param owner Function owning the values
    #  @param owner_analysis Producer analysis for the owner
    #  @param endpoint Return endpoint being checked
    #  @return Values with routable, supported return paths
    def _routable_values(
        self,
        values,
        owner,
        owner_analysis,
        endpoint,
    ):
        result = []
        for value in values:
            if not _routable_return(
                self.context.index, self.context.transform_locations, value
            ):
                continue
            if isinstance(endpoint, ast.AST):
                owner_path = owner.identity.file_path
                locations = [
                    item
                    for item in value.get("evidence", ())
                    if owner_path is not None
                    and Path(item.get("file_path", "")) == owner_path
                    and item.get("lineno") is not None
                ]
                if locations and owner_path is not None:
                    evidence = max(
                        locations,
                        key=lambda item: (
                            item.get("end_lineno", item["lineno"]),
                            item.get("end_col_offset", 0),
                        ),
                    )
                    read_at = SourceSpan(
                        owner_path,
                        evidence["lineno"],
                        evidence.get("col_offset", 0),
                        evidence.get("end_lineno", evidence["lineno"]),
                        evidence.get("end_col_offset", 0),
                    )
                else:
                    fallback = _endpoint_span(endpoint, owner)
                    if fallback is None:
                        continue
                    read_at = fallback
            else:
                read_at = endpoint
            operation = _return_operation_boundary(owner_analysis, owner, value, read_at)
            if operation is not None:
                self.boundaries.append(
                    AnalysisBoundary(
                        "unsupported_carrier_operation",
                        "Unknown effect obscures a returned container.",
                        owner.identity,
                        operation,
                    )
                )
                continue
            result.append(value)
        return result

    ## Normalize captured return values at the owning function boundary.
    ## 在所属函数边界规范化捕获返回值。
    #
    #  @param values Candidate abstract return values
    #  @param owner Function owning the values
    #  @param endpoint Return endpoint being checked
    #  @param captured Captured parameter names on this path
    #  @return Normalized captured values
    def _capture_values(
        self,
        values,
        owner,
        endpoint,
        captured,
    ):
        if self.state.capture and owner.identity == self.state.function.identity:
            values = [
                dict(value, kind="parameter")
                if value.get("kind") == "capture" and value.get("source") == self.state.parameter
                else value
                for value in values
            ]
        if endpoint is owner.node:
            # A capture's final wildcard denotes its elements, not an extra
            # nested container. The incoming binding supplies the open space.
            # 捕获路径末尾的通配符表示容器元素，入参绑定提供开放空间。
            values = [_capture_return_value(value, owner) for value in values]
            values = [
                dict(value, relation="direct", output_path=[])
                if value.get("kind") == "capture"
                and value.get("source") in captured
                and value.get("output_path") == ["*"]
                and not value.get("projection")
                else value
                for value in values
            ]
        return values

    ## Route current object contents through a synthetic parameter binding.
    ## 通过合成参数绑定转发对象当前内容。
    #
    #  @param endpoint Proven source-return endpoint
    #  @param object_path Validated object-return context path
    #  @param values Current abstract object contents
    #  @return Synthetic call-result value for the routed contents
    def _object_contents(
        self,
        endpoint,
        object_path,
        values,
    ):
        # The synthetic binding sends current contents through the router while
        # retaining the proven source-return context as its only call context.
        # 合成绑定将当前内容交给路由器，并仅保留已证明的源码返回调用上下文。
        key = ("vpp_object_contents", endpoint["source"], len(self.calls))
        self.calls[key] = self.ReturnCall(
            key,
            None,
            (self.CallBinding("parameter", "contents", tuple(values)),),
            (
                {
                    "kind": "parameter",
                    "source": "contents",
                    "relation": "direct",
                    "evidence": [],
                    "conditions": [],
                    "call_context": list(object_path[1:]),
                },
            ),
        )
        self.producers[key] = self.producers[object_path[0]]
        return [
            {
                "kind": "call_result",
                "source": key,
                "relation": "direct",
                "evidence": [],
                "conditions": [],
            }
        ]

    ## Collect bounded return-flow candidates for the current forwarding path
    ## 收集当前转发路径中的有界返回流候选
    #
    #  @param values Abstract values propagated through the analysis
    #  @param owner Indexed source function owning the returned values
    #  @param owner_analysis Producer analysis for the owning function
    #  @param remaining Forwarding depth left for the analysis
    #  @param stack Call path used to bound recursive collection
    def collect(
        self,
        values,
        owner,
        owner_analysis,
        remaining,
        stack,
    ):
        owner_calls = {call.id: call for call in direct_calls(owner_analysis, owner.identity)}
        for value in values:
            prepared = self._prepare_return_source(
                value, owner_calls, owner, owner_analysis, remaining, stack
            )
            if prepared is not None:
                self._collect_return_source(*prepared, owner, owner_analysis, remaining, stack)

    ## Resolve and expand one call result used as a return source.
    ## 解析并展开作为返回来源的一项调用结果。
    #
    #  @param value Abstract value representing the returned call result
    #  @param owner_calls Calls indexed for the owning function
    #  @param owner Function owning the return value
    #  @param owner_analysis Producer analysis for the owner
    #  @param remaining Forwarding depth remaining
    #  @param stack Active return-flow identities used to stop recursion
    #  @return Producer, target definition and expanded child analysis
    def _prepare_return_source(
        self,
        value,
        owner_calls,
        owner,
        owner_analysis,
        remaining,
        stack,
    ):
        if value.get("kind") != "call_result":
            return None
        source_id = value.get("source")
        if not isinstance(source_id, str):
            return None
        producer = owner_calls.get(source_id)
        if producer is None:
            return None
        if producer.analysis_status != "analyzed" or producer.binding_status == "invalid":
            self.boundary(
                "return_binding_unavailable", "No usable container return binding.", producer
            )
            return None
        if not producer.target or _target_status(owner_analysis, producer) != "resolved":
            self.boundary(
                "return_target_unresolved",
                "No exact source target for container return.",
                producer,
            )
            return None

        # Return routing requires a body whose decorators leave its modeled behavior available.
        # 返回值路由要求装饰器保留可建模的函数体行为。
        body_boundaries = _callee_body_boundaries(owner_analysis, producer)
        if body_boundaries:
            self.boundaries.extend(body_boundaries)
            return None
        target = identity_from_target(producer.target)
        definition = _target_definition(self.context.index, target)
        if definition is None:
            self.boundary(
                "return_definition_unavailable",
                "Container return source is unavailable.",
                producer,
            )
            return None

        # Recursion and depth are checked before expanding the producer call.
        # 展开生产者调用前先检查递归和深度限制。
        if definition.identity in stack:
            self.boundary("recursive_return_flow", "Recursive container return path.", producer)
            return None
        if remaining <= 0:
            self.boundary(
                "max_forwarding_depth_reached",
                "Container return depth limit reached.",
                producer,
            )
            return None
        try:
            child = _expand_body(self.context, owner_analysis, producer, definition)
        except ResolutionError as exc:
            self.boundary("return_analysis_failed", str(exc), producer)
            return None
        if _receiver_contexts(child, definition.identity):
            self.boundary(
                "return_context_unavailable",
                "Class-context container return composition is not supported.",
                producer,
            )
            return None
        return producer, definition, child

    ## Collect return values and incoming bindings for one expanded call.
    ## 收集一项已展开调用的返回值和输入绑定。
    #
    #  @param producer Producer call being followed
    #  @param definition Resolved source function definition
    #  @param child Expanded analysis for the definition
    #  @param owner Function containing the producer call
    #  @param owner_analysis Producer analysis for the owner
    #  @param remaining Forwarding depth remaining
    #  @param stack Active return-flow identities used to stop recursion
    def _collect_return_source(
        self,
        producer,
        definition,
        child,
        owner,
        owner_analysis,
        remaining,
        stack,
    ):
        bindings, captured = self._incoming_return_bindings(
            producer, definition, owner, owner_analysis, remaining
        )
        returns = next(
            (
                item.get("returns", ())
                for item in child.functions
                if identity_from_target(item["function"]) == definition.identity
            ),
            (),
        )
        returns = self.safe_values(
            returns, definition, child, definition.node, remaining - 1, captured
        )
        self.summaries[definition.identity] = returns
        self.calls[producer.id] = self.ReturnCall(producer.id, definition.identity, bindings)
        self.producers[producer.id] = producer
        self.collect(returns, definition, child, remaining - 1, (*stack, definition.identity))
        self.collect(
            (value for binding in bindings for value in binding.values),
            owner,
            owner_analysis,
            remaining - 1,
            stack,
        )

    ## Map producer arguments to the parameters used by a return source.
    ## 将生产端实参映射到返回来源使用的参数。
    #
    #  @param producer Producer call being followed
    #  @param definition Resolved source function definition
    #  @param owner Function containing the producer call
    #  @param owner_analysis Producer analysis for the owner
    #  @param remaining Forwarding depth remaining
    #  @return Parameter bindings and captured names for the source function
    def _incoming_return_bindings(
        self,
        producer,
        definition,
        owner,
        owner_analysis,
        remaining,
    ):
        bindings = tuple(
            self.CallBinding(
                "parameter",
                item["parameter"],
                self.safe_values(
                    item.get("sources", ()), owner, owner_analysis, producer, remaining - 1
                ),
                _return_binding_path(item, definition, self.state.kind),
            )
            for item in producer.argument_sources
            if item.get("parameter") is not None
        )
        captured = {
            flow["target_capture"]
            for flow in _capture_flows(
                self.context.index,
                self.context.constant_tests,
                self.context.transform_locations,
                owner_analysis,
                self.state,
                producer,
            )
        }
        bindings += tuple(
            self.CallBinding(
                "capture",
                item["capture"],
                tuple(
                    self.safe_values(
                        item.get("current_sources", ()),
                        owner,
                        owner_analysis,
                        producer,
                        remaining - 1,
                    )
                ),
            )
            for item in producer.capture_bindings
            if item.get("capture") in captured
        )
        return bindings, captured

    ## Use identity only for the path; never recover its old input contents
    ## 只用对象身份确定路径，不恢复该对象的旧输入内容
    #
    #  @param value Returned object record whose source context is traced
    #  @param owner Indexed source function owning the returned object
    #  @param owner_analysis Producer analysis for the owning function
    #  @param remaining Forwarding depth left for the analysis
    #  @param stack Call path used to bound recursive resolution
    #  @return Proven object context path, or None when it cannot be established
    def object_context(
        self,
        value,
        owner,
        owner_analysis,
        remaining,
        stack=(),
    ):
        producer = next(
            (
                call
                for call in direct_calls(owner_analysis, owner.identity)
                if call.id == value.get("source")
            ),
            None,
        )
        if producer is None:
            self.boundary(
                "return_object_unproven",
                "Returned object has no local call edge.",
                self.destination,
            )
            return None
        obj = value.get("container_object", {})
        if obj.get("value_completeness") == "unaffected_keys_only" and not (
            preserved_mapping_remainder(owner_analysis, producer, value)
        ):
            self.boundary(
                "return_object_unproven", "Mapping remainder evidence is incomplete.", producer
            )
            return None
        protocol = copy_protocol_target(owner, owner_analysis, producer, value)
        if protocol is None and (
            not _proven_object_alias(value)
            or (
                producer.analysis_status != "analyzed"
                or producer.binding_status != "complete"
                or not producer.target
                or _target_status(owner_analysis, producer) != "resolved"
                or identity_from_target(obj["function"]) != identity_from_target(producer.target)
            )
        ):
            self.boundary(
                "return_object_unproven", "Returned object identity is incomplete.", producer
            )
            return None
        if producer.id in stack:
            self.boundary("recursive_return_flow", "Recursive returned object path.", producer)
            return None
        if remaining <= 0:
            self.boundary(
                "max_forwarding_depth_reached", "Returned object depth limit reached.", producer
            )
            return None
        body_boundaries = _callee_body_boundaries(owner_analysis, producer)
        if body_boundaries:
            self.boundaries.extend(body_boundaries)
            return None

        # Record the producer for reconstruction of the return path through this call.
        # 记录生产者调用，以便重建经过该调用的返回值路径。
        self.producers[producer.id] = producer
        if protocol is not None:
            self.protocols[producer.id] = protocol
            incoming = [
                source
                for source in (
                    *producer.receiver_sources,
                    *(
                        source
                        for item in producer.argument_sources
                        for source in item.get("sources", ())
                    ),
                )
                if source.get("object_only")
            ]
            input_object = obj["copied_from"]
        else:
            incoming = [
                source
                for item in producer.argument_sources
                if item.get("parameter") == obj["parameter"]
                for source in item.get("sources", ())
                if source.get("object_only")
            ]
            input_object = obj["source"]
        if not incoming:
            return (producer.id,)
        if len(incoming) != 1 or (
            incoming[0].get("container_object", {}).get("source") != input_object
        ):
            self.boundary(
                "return_object_unproven", "Returned object contexts are conflicting.", producer
            )
            return None
        parent = self.object_context(
            incoming[0], owner, owner_analysis, remaining - 1, (*stack, producer.id)
        )
        return (*parent, producer.id) if parent is not None else None


## Compose source-resolved whole-container returns using PCResolve's router.
## 使用 PCResolve 的路由结果组合可解析源码的完整容器返回路径。
#
#  @param context Reusable analysis context for the selected source snapshot
#  @param analysis PCResolve analysis result being validated or consumed
#  @param state Current abstract or analysis state
#  @param destination Producer call whose arguments may consume returned containers
#  @param budget Remaining bound for return-flow traversal
#  @param boundaries Mutable collection receiving analysis limits encountered
#  @return Routed return-flow records for the selected variadic parameter
def _returned_flows(
    context,
    analysis,
    state,
    destination,
    budget,
    boundaries,
):
    local_calls = {call.id: call for call in direct_calls(analysis, state.function.identity)}
    arguments = [
        item
        for item in destination.argument_sources
        if isinstance(item.get("argument"), dict)
        and any(value.get("kind") == "call_result" for value in item.get("sources", ()))
        and _depends_on_parameter(item.get("sources", ()), state.parameter, local_calls)
    ]
    if not arguments:
        return []
    from pcresolve.return_resolution import (
        CallBinding,
        ResolutionLimits,
        ReturnCall,
        resolve_return_dependencies,
    )

    collector = _ReturnFlowCollector(
        context, state, destination, boundaries, CallBinding, ReturnCall
    )
    summaries, calls = collector.summaries, collector.calls
    producers, protocols = collector.producers, collector.protocols
    boundary, safe_values, collect = collector.boundary, collector.safe_values, collector.collect

    result = []
    for number, argument in enumerate(arguments):
        values = safe_values(argument["sources"], state.function, analysis, destination, budget)
        collect(values, state.function, analysis, budget, (state.function.identity,))
        entry_key = ("vpp_argument", destination.id, number)
        summaries[entry_key] = values
        resolve_dependencies = resolve_return_dependencies
        resolution = resolve_dependencies(
            entry_key,
            state.parameter,
            summaries,
            calls,
            limits=ResolutionLimits(max_iterations=max(2, budget + 2)),
        )
        if resolution.status != "converged":
            boundary("return_flow_limit_reached", "Return dependency budget reached.", destination)
        for flow in resolution.paths:
            if not conditions_possible(context.index, context.constant_tests, flow):
                continue
            steps = []
            for call_id in flow.get("call_context", ()):
                producer = producers[call_id]
                owner = identity_from_target(producer.caller)
                parameter = (
                    state.parameter
                    if owner == state.function.identity
                    else next(
                        (
                            item["source_parameter"]
                            for item in producer.parameter_flows
                            if _open_container(
                                context.index, context.transform_locations, item
                            )
                        ),
                        state.parameter,
                    )
                )
                steps.append(
                    ForwardingStep(
                        owner,
                        parameter,
                        producer.callee_name,
                        call_span(producer),
                        protocols.get(producer.id) or identity_from_target(producer.target),
                        "local_container_protocol" if producer.id in protocols else "resolved",
                    )
                )
            result.append(
                dict(
                    flow,
                    source_parameter=state.parameter,
                    argument=argument["argument"],
                    target_parameter=argument.get("parameter"),
                    target_path=argument.get("target_path", ()),
                    return_steps=tuple(steps),
                )
            )
    return result
