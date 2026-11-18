## @package vppdetector.facts.containers
#  Source-backed facts about container copying and mapping effects.
#
#
#  Validate exact container copies, supported mapping operations and preserved remainder facts
#  against source witnesses.
#  依据源码见证校验精确容器复制、受支持的映射操作和剩余项保留事实。



import ast
from pathlib import Path

from ..facts.calls import CallFacts, identity_from_target, target_status
from ..facts.conditions import _expression, consistent_conditions
from ..facts.locations import _location, _node_location
from ..models import FunctionIdentity


## Resolve a built-in container copy only from a complete local protocol fact.
## 仅根据完整的局部协议事实解析内置容器复制。
#
#  @param owner Indexed source function containing the operation
#  @param analysis Producer analysis for the function
#  @param call Call fact describing the operation
#  @param value Producer result-source fact
#  @return Built-in function identity, or None when the copy is unproven
def copy_protocol_target(
    owner,
    analysis,
    call,
    value,
):
    obj = value.get("container_object", {})
    results = call.result_sources
    if not (
        call.target_status == "local_container_protocol"
        and call.analysis_status == "analyzed"
        and CallFacts(analysis, call).complete_binding
        and not call.target
        and not call.target_candidates
        and value.get("kind") == "call_result"
        and value.get("source") == call.id
        and value.get("object_only")
        and value.get("relation") == "direct"
        and not any(value.get(flag) for flag in ("value_incomplete", "projection", "output_path"))
        and len(results) == 1
        and results[0].get("kind") == "call_result"
        and results[0].get("relation") == "direct"
        and not any(
            results[0].get(flag)
            for flag in (
                "value_incomplete",
                "projection",
                "output_path",
            )
        )
        and results[0].get("object_only")
        and results[0].get("source") == call.id
        and results[0].get("container_object") == obj
        and obj.get("source")
        and obj.get("copied_from")
        and obj.get("container_shape") in {"dict", "list", "tuple"}
        and obj.get("identity") in {"shallow_copy", "argument_alias"}
        and len(call.effects) == 1
    ):
        return None
    effect = call.effects[0]
    if not (
        effect.get("kind") == "container_copy"
        and effect.get("operation") == "copy"
        and effect.get("status") == "bounded"
        and effect.get("completion") == "normal_return"
        and effect.get("input_container") == obj["copied_from"]
        and effect.get("output_container") == obj["source"]
        and effect.get("container_shape") == obj["container_shape"]
        and effect.get("identity") == obj["identity"]
        and (obj["identity"] != "shallow_copy" or obj["source"] != obj["copied_from"])
        and (
            obj["identity"] != "argument_alias"
            or (obj["container_shape"] == "tuple" and obj["source"] == obj["copied_from"])
        )
        and not any(
            b.get("call_id") == call.id and b.get("reason") not in {"depth_limit"}
            for b in analysis.boundaries
        )
    ):
        return None

    # Match the producer's copy evidence to the exact source call and its receiver.
    # 将生产者的复制证据与源码中的精确调用及其接收者匹配。
    witness = effect.get("evidence", {})
    node = _expression(witness.get("source_text"))
    location = (call.lineno, call.col_offset, call.end_lineno, call.end_col_offset)
    if (
        not isinstance(node, ast.Call)
        or _location(witness) != location
        or Path(witness.get("file_path", "")) != owner.identity.file_path
        or ast.unparse(node.func) != call.callee_name
        or not any(
            isinstance(source, ast.Call)
            and _node_location(source) == location
            and ast.dump(source) == ast.dump(node)
            for source in ast.walk(owner.node)
        )
    ):
        return None
    if (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "copy"
        and obj["container_shape"] == "dict"
        and not node.args
        and not node.keywords
    ):
        return FunctionIdentity("builtins", "dict.copy")
    if (
        isinstance(node.func, ast.Name)
        and node.func.id == obj["container_shape"]
        and len(node.args) == 1
        and not isinstance(node.args[0], ast.Starred)
        and not node.keywords
    ):
        return FunctionIdentity("builtins", node.func.id)
    return None


## Validate a bounded mapping operation on the exact local receiver.
## 校验精确局部接收者上的有界映射操作。
#
#  @param owner Indexed source function containing the operation
#  @param analysis Producer analysis for the function
#  @param call Call fact describing the operation
#  @param operation Mapping method name being checked
#  @param key Optional literal key required for keyed operations
#  @return Whether source evidence supports the operation
def mapping_protocol(
    owner,
    analysis,
    call,
    operation,
    key=None,
):
    if (
        operation not in ("clear", "get", "setdefault")
        or analysis.inputs.get("conditional_source_state")
        or call.target_status != "local_container_protocol"
        or call.analysis_status != "analyzed"
        or call.target
        or call.target_candidates
        or not CallFacts(analysis, call).complete_binding
        or identity_from_target(call.caller) != owner.identity
        or str(owner.identity.file_path) not in analysis.inputs.get("sha256", {})
        or not call.receiver_sources
        or any(not isinstance(value, dict) for value in call.receiver_sources)
        or any(not isinstance(value, dict) for value in call.result_sources + call.effects)
        or any(
            not isinstance(value.get("kind"), str) or not isinstance(value.get("source"), str)
            for value in call.receiver_sources
        )
        or any(
            value.get(flag)
            for value in call.receiver_sources
            for flag in ("value_incomplete", "import_incomplete", "import_modified")
        )
        or (
            operation != "setdefault"
            and any(value.get("projection") for value in call.receiver_sources)
        )
        or any(
            b.get("call_id") == call.id and b.get("reason") not in {"depth_limit"}
            for b in analysis.boundaries
        )
        or any(
            not isinstance(item, dict)
            or any(
                item.get(field) != getattr(call, field)
                for field in ("effects", "result_sources", "binding_status", "target_status")
            )
            for item in getattr(call, "analysis_contexts", ())
        )
    ):
        return False
    location = (call.lineno, call.col_offset, call.end_lineno, call.end_col_offset)
    nodes = [
        node
        for node in ast.walk(owner.node)
        if isinstance(node, ast.Call) and _node_location(node) == location
    ]
    if len(nodes) != 1:
        return False
    node = nodes[0]
    if (
        not isinstance(node.func, ast.Attribute)
        or node.func.attr != operation
        or ast.unparse(node.func) != call.callee_name
        or node.keywords
    ):
        return False

    ## Validate the producer witness required by the enclosing proof
    ## 校验所属证明所需的生产者见证
    #
    #  @param evidence Producer source witness for the call expression
    #  @return Whether the witness matches the current call syntax and location
    def witness(evidence):
        parsed = _expression(evidence.get("source_text")) if isinstance(evidence, dict) else None
        return (
            isinstance(evidence, dict)
            and isinstance(parsed, ast.Call)
            and ast.dump(parsed) == ast.dump(node)
            and evidence.get("file_path") == call.caller.file_path
            and _location(evidence) == location
        )

    if operation == "clear":
        if node.args or len(call.effects) != 1 or call.result_sources:
            return False
        effect = call.effects[0]
        objects = [
            value["container_object"].get("source")
            for value in call.receiver_sources
            if isinstance(value.get("container_object"), dict)
        ]
        if not objects:
            objects = [
                "$parameter:{}:{}:{}".format(
                    call.caller.file_path, call.caller.qualname, value["source"]
                )
                for value in call.receiver_sources
                if value.get("kind") == "parameter"
                and value.get("source")
                and value.get("output_path") == ["*"]
            ]
        return (
            effect.get("kind") == "container_clear"
            and effect.get("operation") == "clear"
            and effect.get("status") == "exact"
            and effect.get("completion") == "normal_return"
            and effect.get("element_path") == []
            and bool(objects)
            and effect.get("object_sources") == list(dict.fromkeys(objects))
            and isinstance(effect.get("conditions"), (list, tuple))
            and consistent_conditions(effect["conditions"])
            and witness(effect.get("evidence"))
        )
    if operation == "setdefault":
        kwarg = owner.node.args.kwarg
        if (
            kwarg is None
            or not isinstance(node.func.value, ast.Name)
            or node.func.value.id != kwarg.arg
            or not isinstance(key, str)
            or len(node.args) not in (1, 2)
            or not isinstance(node.args[0], ast.Constant)
            or type(node.args[0].value) is not str
            or node.args[0].value != key
            or len(call.effects) != 1
        ):
            return False
        parameter_name = kwarg.arg
        object_source = "$parameter:{}:{}:{}".format(
            call.caller.file_path, owner.identity.qualname, parameter_name
        )
        effect = call.effects[0]
        mapping_roots = effect.get("mapping")
        parameter_location = (
            kwarg.lineno,
            kwarg.col_offset,
            kwarg.end_lineno,
            kwarg.end_col_offset,
        )

        ## Validate the source witness that binds a call receiver
        ## 校验绑定调用接收者的源码见证
        #
        #  @param evidence Producer source witness for the receiver parameter
        #  @return Whether the witness matches the parameter name and location
        def receiver_witness(evidence):
            parsed = (
                _expression(evidence.get("source_text")) if isinstance(evidence, dict) else None
            )
            return (
                isinstance(evidence, dict)
                and isinstance(parsed, ast.Name)
                and parsed.id == parameter_name
                and evidence.get("file_path") == call.caller.file_path
                and _location(evidence) == parameter_location
            )

        direct_results = [
            value
            for value in call.result_sources
            if value.get("kind") == "call_result"
            and value.get("relation") == "direct"
            and value.get("object_only") is True
        ]
        receiver_parameters = [
            value
            for value in call.receiver_sources
            if value.get("kind") == "parameter" and value.get("source") == parameter_name
        ]
        return (
            effect.get("kind") == "mapping_element"
            and effect.get("operation") == "setdefault"
            and effect.get("object_source") == object_source
            and effect.get("element_path") == [key]
            and effect.get("status") == "bounded"
            and effect.get("completion") == "normal_return"
            and effect.get("state_before") in {"present", "absent", "unknown"}
            and effect.get("insertion") in {"never", "always", "conditional"}
            and isinstance(effect.get("conditions"), (list, tuple))
            and consistent_conditions(effect["conditions"])
            and witness(effect.get("evidence"))
            and bool(direct_results)
            and any(
                isinstance(value.get("evidence"), (list, tuple))
                and any(witness(evidence) for evidence in value["evidence"])
                for value in direct_results
            )
            and isinstance(mapping_roots, (list, tuple))
            and any(
                isinstance(value, dict)
                and value.get("kind") == "parameter"
                and value.get("name") == parameter_name
                for value in mapping_roots
            )
            and bool(receiver_parameters)
            and all(
                isinstance(value.get("output_path"), (list, tuple))
                and bool(value["output_path"])
                and all(isinstance(part, str) for part in value["output_path"])
                and (
                    not value.get("projection")
                    or value.get("projection") == value.get("output_path")
                )
                and not any(
                    value.get(flag)
                    for flag in ("value_incomplete", "import_incomplete", "import_modified")
                )
                and isinstance(value.get("evidence"), (list, tuple))
                and any(receiver_witness(evidence) for evidence in value["evidence"])
                for value in receiver_parameters
            )
            and all(
                value in receiver_parameters or value.get("relation") == "contained"
                for value in call.receiver_sources
            )
        )
    if (
        len(node.args) not in (1, 2)
        or not isinstance(node.args[0], ast.Constant)
        or type(node.args[0].value) is not str
        or node.args[0].value != key
        or call.effects
    ):
        return False
    receivers = {(value.get("kind"), value.get("source")) for value in call.receiver_sources}
    return any(
        isinstance(value.get("kind"), str)
        and isinstance(value.get("source"), str)
        and value.get("projection") == [key]
        and (value.get("kind"), value.get("source")) in receivers
        and not value.get("value_incomplete")
        and isinstance(value.get("evidence"), (list, tuple))
        and any(witness(evidence) for evidence in value["evidence"])
        for value in call.result_sources
    )


## Check whether an operation preserves all unaffected mapping keys.
## 检查操作是否保留映射中所有未受影响的键。
#
#  @param analysis Producer analysis for the operation
#  @param call Call fact describing the operation
#  @param value Tracked mapping value whose remainder is inspected
#  @return Whether a complete bounded remainder fact is present
def preserved_mapping_remainder(
    analysis,
    call,
    value,
):
    if (
        call.analysis_status != "analyzed"
        or target_status(analysis, call) != "resolved"
        or call.target is None
        or not CallFacts(analysis, call).complete_binding
        or len(call.effects) != 1
    ):
        return False
    effect = call.effects[0]
    if (
        effect.get("kind") != "mapping_remainder"
        or effect.get("operation") != "preserve_unaffected_keys"
        or effect.get("completion") != "normal_return"
        or effect.get("status") != "bounded"
        or effect.get("value_completeness") != "unaffected_keys_only"
        or effect.get("call_id") != call.id
        or identity_from_target(effect.get("function")) != identity_from_target(call.target)
        or not effect.get("evidence")
        or effect.get("assumptions")
        != [
            "fresh_unescaped_builtin_dict",
            "source_snapshot_bindings_hold",
            "no_external_monkeypatch_or_import_hook",
            "no_reflective_frame_access",
        ]
        or any(
            b.get("reason")
            in (
                "mapping_effect_unproven",
                "mapping_remainder_budget",
                "mapping_effect_budget",
                "container_effect_unknown",
            )
            for b in CallFacts(analysis, call).boundaries
        )
    ):
        return False
    binding = effect.get("binding", {})
    arguments = [a for a in call.argument_sources if a.get("parameter") == effect.get("parameter")]
    witness = effect.get("call_evidence", {})
    if (
        binding.get("status") != "exact"
        or binding not in call.parameter_bindings
        or binding.get("parameter") != effect.get("parameter")
        or len(arguments) != 1
        or arguments[0].get("container_binding", {}).get("source") != effect.get("object_source")
        or arguments[0].get("container_binding", {}).get("shape") != "dict"
        or Path(witness.get("file_path", "")) != Path(call.caller.file_path)
        or _location(witness)
        != (call.lineno, call.col_offset, call.end_lineno, call.end_col_offset)
    ):
        return False

    # The preserved remainder is conditional on a concrete, validated set of excluded paths.
    # 剩余内容仍可使用的前提是有一组具体且已验证的排除路径。
    paths = effect.get("excluded_paths")
    if (
        not isinstance(paths, list)
        or len(paths) > 64
        or not all(
            isinstance(path, list) and len(path) == 1 and isinstance(path[0], str) for path in paths
        )
    ):
        return False
    returned = effect.get("return_object", {})
    route = effect.get("return_path")
    if (
        returned.get("identity") != "argument_alias"
        or returned.get("source") != effect.get("object_source")
        or returned.get("parameter") != effect.get("parameter")
        or returned.get("value_completeness") != "unaffected_keys_only"
        or identity_from_target(returned.get("function")) != identity_from_target(call.target)
        or not (
            route is None
            or route == []
            or isinstance(route, list)
            and len(route) == 1
            and type(route[0]) is int
            and route[0] >= 0
        )
    ):
        return False
    if value.get("object_only"):
        return value.get("container_object", {}).get("source") == effect.get("object_source")
    return (
        value.get("kind") in ("parameter", "capture")
        and any(root.get("name") == value.get("source") for root in effect.get("mapping", []))
        and all(path in value.get("excluded_paths", []) for path in paths)
    )
