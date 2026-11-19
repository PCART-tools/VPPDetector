## @package vppdetector.facts.creation
#  Proof checks for source-defined class creation and constructor bindings.
#
#
#  Check class construction phases, hooks and receiver bindings before admitting source-backed
#  constructor evidence.
#  在接纳基于源码的构造器证据前校验类构造阶段、钩子和接收者绑定。



from pathlib import Path

from .callable_metadata import creation_metadata_premises
from .calls import identity_from_target
from .creation_metadata import _class_creation_metadata_queries_premises
from .locations import _location


## Validate premises for the source class-creation call graph.
## 校验源码类创建调用图的前提条件。
#
#  @param hook Class-creation hook record
#  @param binding Producer binding containing the hook
#  @return True when the call-graph claims are internally consistent
def _creation_method_premises(hook, binding):
    calls = hook.get("method_calls")
    claimed = "source_class_creation_call_graph" in hook.get("assumptions", ())
    if calls is None:
        return not claimed
    if not claimed or not isinstance(calls, (list, tuple)) or not 1 <= len(calls) <= 256:
        return False

    ## Validate a source identity used by the enclosing proof
    ## 校验所属证明使用的源码身份
    #
    #  @param value Producer source identity record to validate
    #  @return Source identity tuple, or None if required fields or source hashes are invalid
    def identity(value):
        if (
            not isinstance(value, dict)
            or any(
                not isinstance(value.get(key), str) or not value[key]
                for key in ("module", "qualname", "file_path")
            )
            or type(value.get("lineno")) is not int
            or value["lineno"] < 1
            or value["file_path"] not in hook["source_hashes"]
        ):
            return None
        return tuple(value[key] for key in ("module", "qualname", "file_path", "lineno"))

    ## Validate the producer witness required by the enclosing proof
    ## 校验所属证明所需的生产者见证
    #
    #  @param value Producer source witness record to validate
    #  @param owner Source owner tuple whose file and coordinates constrain the witness
    #  @param declaration Whether the witness must start on the owner's declaration line
    #  @return Whether the witness is a valid source span for the owner
    def witness(value, owner, declaration=False):
        return (
            isinstance(value, dict)
            and value.get("file_path") == owner[2]
            and all(
                type(value.get(key)) is int and value[key] >= 0
                for key in ("lineno", "col_offset", "end_lineno", "end_col_offset")
            )
            and value["lineno"] >= owner[3]
            and (not declaration or value["lineno"] == owner[3])
            and (value["lineno"], value["col_offset"])
            < (value["end_lineno"], value["end_col_offset"])
        )

    root = identity(hook["target"])
    if root is None:
        return False
    hierarchy = {
        (owner.get("module"), owner.get("qualname"), owner.get("file_path"))
        for owner in binding.get("hierarchy", ())
        if isinstance(owner, dict)
    }
    if (root[0], root[1].rpartition(".")[0], root[2]) not in hierarchy:
        return False
    graph = {}
    sites = set()
    for call in calls:
        if not isinstance(call, dict):
            return False
        caller, target = identity(call.get("caller")), identity(call.get("target"))
        name = call.get("attribute")
        if (
            caller is None
            or target is None
            or not isinstance(name, str)
            or not name
            or name.startswith("__")
            or name == "mro"
            or name in hook["attributes"]
            or target[1].rsplit(".", 1)[-1] != name
            or (target[0], target[1].rpartition(".")[0], target[2]) not in hierarchy
            or call.get("receiver_class") != hook["receiver_class"]
            or call.get("binding") != "builtin_classmethod"
            or call.get("completion") != "normal_return_only"
            or call.get("argument_binding") != "implicit_receiver_only"
            or not witness(call.get("call_evidence"), caller)
            or not witness(call.get("target_evidence"), target, declaration=True)
        ):
            return False
        site = (
            caller,
            tuple(
                call["call_evidence"][key]
                for key in ("lineno", "col_offset", "end_lineno", "end_col_offset")
            ),
        )
        if site in sites:
            return False
        sites.add(site)
        graph.setdefault(caller, set()).add(target)

    # Require a bounded graph rooted at the hook and reject cycles or unreachable recorded calls.
    # 调用图须有界并以钩子为根，且不得含环或不可达的调用记录。
    vertices = set(graph) | {target for targets in graph.values() for target in targets}
    if len(vertices) > 16 or root not in graph:
        return False
    visited, active = set(), set()

    ## Traverse one producer dependency node and validate its source evidence
    ## 遍历一个生产者依赖节点并校验其源码证据
    #
    #  @param vertex Source method identity to traverse in the call graph
    #  @return Whether the reachable subgraph is acyclic
    def visit(vertex):
        if vertex in active:
            return False
        if vertex in visited:
            return True
        active.add(vertex)
        if any(not visit(target) for target in graph.get(vertex, ())):
            return False
        active.remove(vertex)
        visited.add(vertex)
        return True

    return visit(root) and visited == vertices


## Validate native-type query premises for one class-creation hook.
## 校验一项类创建钩子的原生类型查询前提。
#
#  @param hook Class-creation hook record
#  @param supporting Supporting source hashes
#  @return True when the query claims are internally consistent
def _creation_query_premises(hook, supporting):
    queries = hook.get("native_type_queries")
    claimed = "source_class_creation_native_queries" in hook.get("assumptions", ())
    if queries is None:
        return not claimed
    if not claimed or not isinstance(queries, (list, tuple)) or not 1 <= len(queries) <= 256:
        return False
    primary = hook["source_hashes"]
    if not isinstance(supporting, dict) or any(
        not isinstance(path, str)
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(char not in "0123456789abcdef" for char in digest)
        or path in primary
        for path, digest in supporting.items()
    ):
        return False
    hashes = {**primary, **supporting}
    callers = [hook["target"]] + [call["target"] for call in hook.get("method_calls", ())]
    required = {
        "source_snapshot_bindings_hold",
        "standard_builtin_namespace_preserved",
        "builtin_type_iteration_raises_typeerror",
        "source_function_execution_binding_preserved",
        "no_external_frame_or_gc_observation",
        "no_external_monkeypatch_or_import_hook",
        "no_unmodeled_indirect_function_mutation",
        "no_unmodeled_indirect_module_mutation",
    }
    seen = set()

    ## Validate a source identity used by the enclosing proof
    ## 校验所属证明使用的源码身份
    #
    #  @param value Producer source identity record to validate
    #  @return Whether the identity fields and source path are valid
    def identity(value):
        return (
            isinstance(value, dict)
            and all(
                isinstance(value.get(key), str) and value[key]
                for key in ("module", "qualname", "file_path")
            )
            and type(value.get("lineno")) is int
            and value["lineno"] >= 1
            and value["file_path"] in hashes
        )

    ## Validate the producer witness required by the enclosing proof
    ## 校验所属证明所需的生产者见证
    #
    #  @param value Producer source witness record to validate
    #  @param owner Optional source owner whose file and coordinates constrain the witness
    #  @return Whether the source span matches an available file and optional owner
    def witness(value, owner=None):
        return (
            isinstance(value, dict)
            and isinstance(value.get("file_path"), str)
            and value["file_path"] in hashes
            and (owner is None or value.get("file_path") == owner.get("file_path"))
            and all(
                type(value.get(key)) is int and value[key] >= 0
                for key in ("lineno", "col_offset", "end_lineno", "end_col_offset")
            )
            and value["lineno"] >= (owner.get("lineno", 1) if owner else 1)
            and _location(value)[:2] < _location(value)[2:]
        )

    for query in queries:
        if not isinstance(query, dict):
            return False
        protocol, caller = query.get("source_protocol"), query.get("caller")
        if (
            not isinstance(protocol, dict)
            or not isinstance(caller, dict)
            or not identity(caller)
            or caller not in callers
            or query.get("receiver_class") != hook["receiver_class"]
            or query.get("argument_binding") != "implicit_classmethod_receiver"
            or query.get("phase") != "before_class_decorators"
            or not isinstance(query.get("parameter"), str)
            or not query["parameter"]
            or caller == hook["target"]
            and query["parameter"] != hook["parameter"]
            or not witness(query.get("call_evidence"), caller)
            or type(query.get("result")) is not bool
            or protocol.get("kind") != "source_native_type_iterability_predicate"
            or protocol.get("status") != "requires_native_type_input"
            or protocol.get("basis") != "source_snapshot"
            or protocol.get("precondition")
            != {"argument": {"position": 0}, "exact_metaclass": "type"}
            or type(protocol.get("result")) is not bool
            or protocol["result"] != query["result"]
            or protocol.get("runtime_input_confirmed") is not False
            or protocol.get("effects") != "none_if_precondition"
            or protocol.get("completion") != "normal_return_if_precondition_and_lookup_succeeds"
            or protocol.get("primitive_bindings")
            != {"iter": "confirmed_builtin", "TypeError": "confirmed_builtin"}
            or not isinstance(protocol.get("source_hashes"), dict)
            or any(
                protocol["source_hashes"].get(path) != digest for path, digest in primary.items()
            )
            or any(hashes.get(path) != digest for path, digest in protocol["source_hashes"].items())
            or not isinstance(protocol.get("assumptions"), (list, tuple))
            or any(not isinstance(value, str) for value in protocol["assumptions"])
            or not required.issubset(protocol["assumptions"])
            or not set(protocol["assumptions"]).issubset(hook["assumptions"])
        ):
            return False
        reference = protocol.get("source_binding")
        if not isinstance(reference, dict):
            return False
        target, requested = reference.get("target"), reference.get("requested")
        supporting = reference.get("source_hashes")
        if (
            not isinstance(target, dict)
            or not isinstance(requested, dict)
            or any(
                not isinstance(target.get(key), str) or not target[key]
                for key in ("module", "qualname", "file_path")
            )
            or type(target.get("lineno")) is not int
            or target["lineno"] < 1
            or target["file_path"] not in protocol["source_hashes"]
            or not isinstance(requested.get("module"), str)
            or not isinstance(requested.get("name"), str)
            or query.get("callee") != requested["module"] + "." + requested["name"]
            or reference.get("kind") != "source_module_binding_reference"
            or reference.get("status") != "unique_declaration_when_lookup_succeeds"
            or reference.get("basis") != "source_snapshot"
            or reference.get("completion") != "normal_module_return_and_attribute_lookup_only"
            or type(reference.get("may_be_unbound")) is not bool
            or reference.get("runtime_target_confirmed") is not False
            or reference.get("callable_identity_proven") is not False
            or reference.get("body_binding_proven") is not False
            or not isinstance(supporting, dict)
            or not supporting
            or target["file_path"] not in supporting
            or any(
                protocol["source_hashes"].get(path) != digest for path, digest in supporting.items()
            )
            or not isinstance(reference.get("paths"), (list, tuple))
            or not 1 <= len(reference["paths"]) <= 64
            or any(not isinstance(path, dict) for path in reference["paths"])
            or not isinstance(reference.get("assumptions"), (list, tuple))
            or any(not isinstance(value, str) for value in reference["assumptions"])
            or not {
                "source_snapshot_bindings_hold",
                "standard_source_import_protocol",
                "standard_module_attribute_lookup",
                "no_external_monkeypatch_or_import_hook",
                "no_unmodeled_indirect_module_mutation",
            }.issubset(reference["assumptions"])
            or not set(reference["assumptions"]).issubset(protocol["assumptions"])
        ):
            return False
        for path in reference["paths"]:
            conditions, imports = path.get("conditions"), path.get("imports")
            if (
                type(path.get("fallback")) is not bool
                or not isinstance(conditions, (list, tuple))
                or len(conditions) > 128
                or not isinstance(imports, (list, tuple))
                or len(imports) > 64
                or any(
                    not isinstance(condition, dict)
                    or condition.get("branch") not in ("if", "else")
                    or not witness(condition.get("evidence"))
                    for condition in conditions
                )
            ):
                return False
            previous = target["module"], target["qualname"]
            for imported in imports:
                if (
                    not isinstance(imported, dict)
                    or any(
                        not isinstance(imported.get(key), str) or not imported[key]
                        for key in ("module", "imported_module", "imported_name", "binding_name")
                    )
                    or (imported["imported_module"], imported["imported_name"]) != previous
                    or type(imported.get("wildcard")) is not bool
                    or imported.get("completion") != "normal_import_return_only"
                    or not witness(imported.get("evidence"))
                ):
                    return False
                previous = imported["module"], imported["binding_name"]
            if previous != (requested["module"], requested["name"]):
                return False
        definition = protocol.get("function_evidence")
        iteration = protocol.get("iteration_evidence")
        handler = protocol.get("handler_evidence")
        if (
            not isinstance(definition, dict)
            or not isinstance(iteration, dict)
            or not isinstance(handler, dict)
            or not witness(definition, target)
            or definition["lineno"] != target["lineno"]
            or not witness(iteration, target)
            or not witness(handler, target)
            or _location(iteration)[:2] < _location(definition)[:2]
            or _location(iteration)[2:] > _location(definition)[2:]
            or _location(handler)[:2] < _location(definition)[:2]
            or _location(handler)[2:] > _location(definition)[2:]
            or _location(iteration)[2:] > _location(handler)[:2]
        ):
            return False
        decorations = protocol.get("decorator_effects")
        if (
            not isinstance(decorations, (list, tuple))
            or len(decorations) > 1
            or any(
                not isinstance(fact, dict)
                or fact.get("identity_status") != "preserved"
                or fact.get("body_binding_status") != "preserved"
                or fact.get("boundaries") != []
                or not identity(fact.get("function"))
                or identity_from_target(fact.get("function")) != identity_from_target(target)
                or not isinstance(fact.get("source_hashes"), dict)
                or target["file_path"] not in fact["source_hashes"]
                or any(
                    protocol["source_hashes"].get(path) != digest
                    for path, digest in fact["source_hashes"].items()
                )
                or not isinstance(fact.get("assumptions"), (list, tuple))
                or any(not isinstance(value, str) for value in fact["assumptions"])
                or not set(fact["assumptions"]).issubset(protocol["assumptions"])
                for fact in decorations
            )
        ):
            return False
        site = (
            tuple(caller.get(key) for key in ("module", "qualname", "file_path", "lineno")),
            _location(query["call_evidence"]),
        )
        if site in seen:
            return False
        seen.add(site)
    return True


## Validate all class-creation hook claims in one producer binding.
## 校验一项生产端绑定中的全部类创建钩子声明。
#
#  @param analysis Producer analysis containing the binding
#  @param binding Producer binding record
#  @return True when every present hook satisfies its evidence contract
def _creation_hook_premises(analysis, binding):
    hooks = binding.get("class_creation_hooks")
    claims = binding.get("assumptions", ())
    if not isinstance(claims, (list, tuple)) or any(not isinstance(value, str) for value in claims):
        return False
    if hooks is None:
        return not {
            "source_class_creation_effects",
            "source_class_creation_call_graph",
            "source_class_creation_native_queries",
            "source_class_creation_callable_metadata_queries",
        } & set(claims)
    if not isinstance(hooks, (list, tuple)) or not 1 <= len(hooks) <= 64:
        return False
    required = {
        "source_snapshot_bindings_hold",
        "builtin_type_class_creation_protocol",
        "source_class_creation_effects",
        "builtin_type_attribute_writes",
        "standard_builtin_namespace_preserved",
        "no_unmodeled_indirect_builtin_mutation",
        "no_external_monkeypatch_or_import_hook",
        "no_unmodeled_indirect_class_mutation",
        "no_external_frame_introspection",
    }
    seen = set()
    for hook_index, hook in enumerate(hooks):
        if not isinstance(hook, dict):
            return False
        if not _class_creation_metadata_queries_premises(analysis, binding, hook, hook_index):
            return False
        attributes, assumptions = hook.get("attributes"), hook.get("assumptions")
        receiver, target = hook.get("receiver_class"), hook.get("target")
        if (
            not isinstance(receiver, dict)
            or not isinstance(target, dict)
            or any(
                not isinstance(identity.get(field), str) or not identity[field]
                for identity in (receiver, target)
                for field in ("module", "qualname", "file_path")
            )
            or not isinstance(target.get("qualname"), str)
            or not target["qualname"].endswith(".__init_subclass__")
            or hook.get("kind") != "source_class_creation_hook"
            or hook.get("status") != "source_bound"
            or hook.get("basis") != "source_snapshot"
            or hook.get("phase") != "before_class_decorators"
            or hook.get("binding") != "implicit_classmethod"
            or hook.get("completion") != "normal_return_only"
            or hook.get("preserved_scope") != "other_class_attributes"
            or hook.get("runtime_hook_confirmed") is not False
            or not isinstance(hook.get("parameter"), str)
            or not hook["parameter"]
            or not isinstance(attributes, (list, tuple))
            or len(attributes) > 2000
            or any(
                not isinstance(name, str)
                or not name
                or name == "mro"
                or name.startswith("__")
                and name.endswith("__")
                for name in attributes
            )
            or len(set(attributes)) != len(attributes)
            or not isinstance(assumptions, (list, tuple))
            or any(not isinstance(value, str) for value in assumptions)
            or not required.issubset(assumptions)
            or not set(assumptions).issubset(claims)
            or not isinstance(hook.get("source_hashes"), dict)
            or not hook["source_hashes"]
            or not isinstance(binding.get("source_hashes"), dict)
            or hook.get("source_hashes") != analysis.inputs.get("sha256")
            or not all(
                binding.get("source_hashes", {}).get(path) == digest
                for path, digest in hook.get("source_hashes", {}).items()
            )
        ):
            return False
        if (
            not _creation_method_premises(hook, binding)
            or not _creation_query_premises(
                hook, analysis.inputs.get("supporting_source_sha256", {})
            )
            or not creation_metadata_premises(
                hook, analysis.inputs.get("supporting_source_sha256", {})
            )
        ):
            return False
        for field, identity in (("class_evidence", receiver), ("hook_evidence", target)):
            witness = hook.get(field)
            if (
                not isinstance(witness, dict)
                or witness.get("file_path") != identity.get("file_path")
                or witness.get("lineno") != identity.get("lineno")
            ):
                return False
        key = (
            receiver.get("module"),
            receiver.get("qualname"),
            target.get("module"),
            target["qualname"],
        )
        if key in seen:
            return False
        seen.add(key)
    return (
        ("source_class_creation_call_graph" in claims)
        == any("method_calls" in hook for hook in hooks)
        and ("source_class_creation_native_queries" in claims)
        == any("native_type_queries" in hook for hook in hooks)
        and ("source_class_creation_callable_metadata_queries" in claims)
        == any("callable_metadata_queries" in hook for hook in hooks)
    )


## Resolve constructor-entry evidence for the requested source identity.
## 为请求的源码身份解析构造器入口证据。
#
#  @param analysis Producer analysis for the requested entry
#  @param requested Requested function or class identity
#  @return Validated constructor-entry binding, or None when unproven
def source_constructor_entry_binding(analysis, requested):
    fact = analysis.inputs.get("entry_binding")
    if not isinstance(fact, dict):
        return None
    implicit = fact.get("implicit_binding")
    hashes = fact.get("source_hashes")
    evidence = fact.get("definition_evidence")
    hierarchy = fact.get("hierarchy")
    if (
        not isinstance(implicit, dict)
        or not isinstance(hashes, dict)
        or not isinstance(evidence, dict)
        or not isinstance(hierarchy, (list, tuple))
        or not 1 <= len(hierarchy) <= 64
        or not isinstance(fact.get("assumptions"), (list, tuple))
        or not all(isinstance(item, str) for item in fact["assumptions"])
    ):
        return None
    try:
        receiver = identity_from_target(fact["receiver_class"])
        target = identity_from_target(fact["target"])
        owners = tuple(identity_from_target(item) for item in hierarchy)
    except (AttributeError, KeyError, TypeError, ValueError):
        return None
    if receiver is None or target is None or any(owner is None for owner in owners):
        return None
    phase = fact.get("phase")
    assumptions = {
        "source_snapshot_bindings_hold",
        "builtin_type_call_and_new_binding",
        "no_external_monkeypatch_or_import_hook",
        "no_unmodeled_indirect_class_mutation",
    }
    source_hashes = {
        **analysis.inputs.get("sha256", {}),
        **analysis.inputs.get("supporting_source_sha256", {}),
    }
    valid = (
        fact.get("query_kind") == "source_class_call"
        and fact.get("basis") == "source_snapshot"
        and fact.get("status") == "source_bound"
        and not fact.get("issues")
        and fact.get("runtime_target_confirmed") is False
        and fact.get("instance_state") == "unmodeled"
        and receiver == requested
        and target == identity_from_target(analysis.entry)
        and owners[0] == receiver
        and len(set(owners)) == len(owners)
        and phase in ("__new__", "__init__")
        and target.qualname.endswith("." + phase)
        and fact.get("execution_scope")
        == ("new_invocation_only" if phase == "__new__" else "init_invocation_only")
        and fact.get("body_execution") == "synchronous"
        and implicit.get("status") == "static_bound"
        and isinstance(implicit.get("parameter"), str)
        and implicit.get("value_kind") == ("class" if phase == "__new__" else "instance")
        and bool(hashes)
        and str(receiver.file_path) in hashes
        and str(target.file_path) in hashes
        and all(str(owner.file_path) in hashes for owner in owners)
        and all(
            isinstance(path, str) and isinstance(digest, str) for path, digest in hashes.items()
        )
        and all(source_hashes.get(path) == digest for path, digest in hashes.items())
        and Path(evidence.get("file_path", "")) == receiver.file_path
        and evidence.get("lineno") == receiver.lineno
        and assumptions.issubset(fact["assumptions"])
        and _creation_hook_premises(analysis, fact)
        and any(
            b.get("reason") == "source_constructor_entry_binding"
            and b.get("boundary_kind") == "assumption"
            and b.get("function") == fact["target"]
            for b in analysis.boundaries
        )
    )
    return fact if valid else None


## Resolve constructor binding evidence for one producer call.
## 为一项生产端调用解析构造器绑定证据。
#
#  @param analysis Producer analysis containing the call
#  @param call Producer call facts
#  @return Validated constructor binding, or None when unproven
def source_constructor_binding(analysis, call):
    if analysis.inputs.get("conditional_source_state"):
        return None
    bindings = getattr(call, "constructor_bindings", ())
    if (
        not isinstance(bindings, (list, tuple))
        or call.target_status != "constructor"
        or call.target is None
        or call.binding_status == "invalid"
        or len(bindings) != 1
    ):
        return None
    target_identity = identity_from_target(call.target)
    if target_identity is None:
        return None
    binding = bindings[0]
    if (
        not isinstance(binding, dict)
        or not isinstance(binding.get("implicit_binding"), dict)
        or not isinstance(binding.get("source_hashes"), dict)
        or not isinstance(binding.get("receiver_class"), dict)
        or not isinstance(binding.get("assumptions"), (list, tuple))
        or not isinstance(binding.get("call_evidence"), dict)
    ):
        return None
    implicit = binding["implicit_binding"]
    phase = binding.get("phase")
    if phase not in ("__new__", "__init__") or not all(
        isinstance(item, str) for item in binding["assumptions"]
    ):
        return None
    initializer = phase == "__init__"
    scope = "init_invocation_only" if initializer else "new_invocation_only"
    slot = {"constructor_instance" if initializer else "constructor_class": True}
    receiver_kind = "instance_type" if initializer else "class_type"

    # Check the phase-specific receiver against the actual argument and binding records.
    # 用实际实参和绑定记录校验当前构造阶段的接收者。
    arguments = [
        a
        for a in call.argument_sources
        if a.get("argument") == slot and a.get("parameter") == implicit.get("parameter")
    ]
    records = [r for r in call.parameter_bindings if r.get("argument") == slot]
    values = [v for argument in arguments for v in argument.get("sources", ())]
    witness = binding["call_evidence"]
    assumptions = {
        "source_snapshot_bindings_hold",
        "builtin_type_call_and_new_binding",
        "no_external_monkeypatch_or_import_hook",
        "no_unmodeled_indirect_class_mutation",
    }
    valid = (
        binding.get("status") == "source_bound"
        and binding.get("basis") == "source_snapshot"
        and not binding.get("issues")
        and binding.get("runtime_target_confirmed") is False
        and target_identity.qualname.endswith("." + phase)
        and binding.get("execution_scope") == scope
        and binding.get("instance_state") == "unmodeled"
        and binding.get("body_execution") in ("synchronous", "deferred")
        and binding.get("target") is not None
        and identity_from_target(binding["target"]) == identity_from_target(call.target)
        and implicit.get("status") == "static_bound"
        and implicit.get("argument") == slot
        and implicit.get("receiver_class") == binding.get("receiver_class")
        and len(records) == len(arguments) == 1
        and records[0].get("status") == "exact"
        and records[0].get("parameter") == implicit.get("parameter")
        and bool(values)
        and all(
            v.get(receiver_kind) == binding.get("receiver_class")
            and v.get("relation") == "direct"
            and not any(
                v.get(flag)
                for flag in (
                    "projection",
                    "output_path",
                    "value_incomplete",
                    "import_modified",
                    "import_incomplete",
                )
            )
            for v in values
        )
        and Path(witness.get("file_path", "")) == Path(call.caller.file_path)
        and _location(witness)
        == (call.lineno, call.col_offset, call.end_lineno, call.end_col_offset)
        and bool(binding["source_hashes"])
        and all(
            analysis.inputs.get("sha256", {}).get(path) == digest
            for path, digest in binding["source_hashes"].items()
        )
        and assumptions.issubset(binding.get("assumptions", ()))
        and _creation_hook_premises(analysis, binding)
        and any(
            b.get("call_id") == call.id
            and b.get("reason") == "source_constructor_" + phase.strip("_") + "_binding"
            and b.get("boundary_kind") == "assumption"
            and b.get("execution_scope") == scope
            for b in analysis.boundaries
        )
        and all(
            item.get("target") == binding["target"] and item.get("constructor_bindings") == bindings
            for item in call.analysis_contexts
        )
    )
    return binding if valid else None
