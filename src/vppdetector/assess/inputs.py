## @package vppdetector.assess.inputs
#  Call-time capture and callable binding checks for assessment frames.
#
#
#  Validate captured-value transfer and callable-instance bindings before source execution is
#  modeled.
#  在建模函数体执行之前校验捕获值传递和可调用实例绑定。



import ast
import copy
import hashlib
import json
import textwrap
from pathlib import Path

from ..facts.calls import CallFacts, candidate_identities, identity_from_target
from ..facts.calls import target_status as _target_status
from ..facts.conditions import conditions_possible
from ..facts.scope import capture_names
from .values import (
    _Keywords,
    _LocalFunction,
    _Positionals,
    _source_state,
    _SourceInstance,
    _tracked,
)


## Bind source-call arguments to the current assessment frame.
## 将源码调用实参绑定到当前评估帧。
class ArgumentBindingOperations:
    ## Read supported captured values for the exact caller and callsite.
    ## 读取精确调用方及调用位置的受支持捕获值。
    #
    #  @param target Resolved source target
    #  @param call Producer call facts
    #  @param local Local values in the current frame
    #  @param node Call AST node
    #  @return Captured abstract values, or None when the source is unproven
    def capture_values(self, target, call, local, node):
        owner = self.function.identity
        local_node = local.node if isinstance(local, _LocalFunction) else None
        if (
            not isinstance(local, _LocalFunction)
            or not isinstance(local_node, (ast.FunctionDef, ast.AsyncFunctionDef))
            or target.identity.module != owner.module
            or target.identity.file_path != owner.file_path
            or target.identity.qualname != owner.qualname + "." + local_node.name
            or target.node is not local_node
            or _target_status(self.analysis, call) != "resolved"
            or call.analysis_status != "analyzed"
            or not CallFacts(self.analysis, call).complete_binding
            or any(candidate != target.identity for candidate in candidate_identities(call))
            or any(
                incoming.get("capture_bindings") != call.capture_bindings
                for incoming in call.analysis_contexts
            )
        ):
            self.unknown("capture_binding_unproven", node)

        # Require a complete, unique capture record for every name actually closed over.
        # 实际捕获的每个名称都必须有完整且唯一的记录。
        records = call.capture_bindings
        names = [item.get("capture") for item in records]
        if len(names) != len(set(names)) or set(names) != set(
            capture_names(target.node, self.values)
        ):
            self.unknown("capture_binding_unproven", node)
        values = {}
        for record in records:
            name = record["capture"]
            value = self.values.get(name)
            shape = (
                "dict"
                if isinstance(value, _Keywords)
                else (value.kind if isinstance(value, _Positionals) else None)
            )
            binding = record.get("container_binding", {})
            roots = record.get("sources", ())
            contents = record.get("current_sources", ())
            root = roots[0] if len(roots) == 1 else {}
            container = root.get("container_object", {}) if root.get("object_only") else root
            if (
                shape is None
                or binding.get("status") != "exact"
                or binding.get("shape") != shape
                or binding.get("contents_unknown")
                or not conditions_possible(
                    self.context.index, self.context.constant_tests, binding
                )
                or root.get("kind") not in {"container", "call_result"}
                or not container.get("source")
                or container["source"] != binding.get("source")
                or container.get("container_shape") != shape
                or root.get("relation") != "direct"
                or not conditions_possible(
                    self.context.index, self.context.constant_tests, root
                )
                or any(
                    root.get(flag)
                    for flag in (
                        "value_incomplete",
                        "projection",
                        "output_path",
                    )
                )
                or not any(
                    Path(witness.get("file_path", "")) == owner.file_path
                    and all(
                        witness.get(key) == getattr(node, key)
                        for key in (
                            "lineno",
                            "col_offset",
                            "end_lineno",
                            "end_col_offset",
                        )
                    )
                    for witness in binding.get("evidence", ())
                )
                or _tracked(value)
                and not any(
                    item.get("kind") in {"parameter", "capture"}
                    and item.get("source") in self.values
                    and not item.get("object_only")
                    for item in contents
                )
                or any(
                    item.get("value_incomplete")
                    or item.get("projection")
                    or not conditions_possible(
                        self.context.index, self.context.constant_tests, item
                    )
                    for item in contents
                )
            ):
                self.unknown("capture_binding_unproven", node)

            # Share the current object, not a copy: modeled pops must reach parent aliases too.
            # 共享当前对象而非副本，使建模的删除操作也能反映到父级别名上。
            values[name] = value
        return values

    ## Validate a source-backed binding for a callable object.
    ## 校验可调用对象的源码绑定事实。
    #
    #  @param call Producer call facts
    #  @param binding Candidate callable binding fact
    #  @return Validated source callable, or None when unsupported
    def source_callable_binding(self, call, binding):
        if not binding or call.binding_status != "complete" or call.binding_issues:
            return None
        target = identity_from_target(call.target)
        definition = self.context.index.find(target)
        if definition is None or not definition.node.args.posonlyargs + definition.node.args.args:
            return None
        try:
            witnessed = ast.parse(
                textwrap.dedent(binding.get("definition", {}).get("source_text", ""))
            )
            if len(witnessed.body) != 1 or ast.dump(witnessed.body[0]) != ast.dump(definition.node):
                return None
        except (SyntaxError, ValueError, TypeError):
            return None
        evidence = call.callable_instance_evidence
        boundaries = [
            b
            for b in self.analysis.boundaries
            if b.get("call_id") == call.id
            and b.get("reason") == "dynamic_callable_instance_override_possible"
        ]
        if not (
            binding.get("status") == "source_bound"
            and binding.get("basis") == "source_snapshot"
            and binding.get("runtime_target_confirmed") is False
            and not binding.get("issues")
            and binding.get("target")
            and identity_from_target(binding["target"]) == target
            and binding.get("instance_type") == evidence.get("instance_type")
            and binding.get("implicit_binding", {}).get("status") == "static_bound"
            and binding.get("implicit_binding", {}).get("parameter")
            == (definition.node.args.posonlyargs + definition.node.args.args)[0].arg
            and binding.get("assumptions")
            and binding.get("evidence")
            and len(call.target_candidates) == 1
            and identity_from_target(call.target_candidates[0]) == target
            and boundaries
            and all(
                b.get("boundary_kind") == "assumption" and b.get("binding_status") == "source_bound"
                for b in boundaries
            )
            and all(
                incoming.get("target") == binding["target"]
                and incoming.get("callable_instance_evidence") == evidence
                for incoming in getattr(call, "analysis_contexts", ())
            )
            and binding.get("snapshot_sha256")
            == hashlib.sha256(
                json.dumps(self.analysis.inputs["sha256"], sort_keys=True).encode("utf-8")
            ).hexdigest()
        ):
            return None

        # Recheck the hashed source before admitting instance state from a producer fact.
        # 接纳生产者事实中的实例状态前，重新核对源码摘要。
        hashes = binding.get("source_hashes", {})
        if not hashes or binding.get("source_hash_policy") != "utf-8-sig-universal-newlines":
            return None
        try:
            if any(
                self.analysis.inputs["sha256"].get(path) != digest
                or hashlib.sha256(
                    Path(path).read_text(encoding="utf-8-sig").encode("utf-8")
                ).hexdigest()
                != digest
                for path, digest in hashes.items()
            ):
                return None
        except (OSError, UnicodeError):
            return None
        try:
            state = {
                name: _source_state(value)
                for name, value in copy.deepcopy(binding.get("receiver_state", {})).items()
            }
        except (ValueError, TypeError, KeyError, RecursionError):
            return None
        return _SourceInstance(state)
