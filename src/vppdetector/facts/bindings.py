## @package vppdetector.facts.bindings
#  Validated source-level binding facts.
#
#
#  Validate public source aliases and prove classmethod lookup and receiver binding from producer
#  evidence.
#  校验公开源码别名，并依据生产者证据验证类方法查找及接收者绑定。



from pathlib import Path

from .calls import identity_from_target
from .locations import _location


## Validate a source snapshot alias for the requested entry point.
## 校验所请求入口在源码快照中的别名事实。
#
#  @param analysis Producer analysis containing alias evidence and boundaries
#  @param requested Requested source function identity
#  @return Validated alias fact, or None when its contract is incomplete
def source_alias_entry(analysis, requested):
    fact = analysis.inputs.get("entry_alias", {})
    if not isinstance(fact, dict):
        return None
    query = fact.get("requested", {})
    if not isinstance(query, dict):
        return None
    alias_target = fact.get("target")
    if (
        not isinstance(alias_target, dict)
        or not all(
            isinstance(alias_target.get(name), str) for name in ("module", "qualname", "file_path")
        )
        or type(alias_target.get("lineno")) is not int
        or not isinstance(query.get("file_path", ""), str)
    ):
        return None
    assignments = fact.get("assignments", ())
    target = identity_from_target(analysis.entry)
    if (
        fact.get("kind") != "source_entry_alias"
        or fact.get("status") != "source_reference"
        or fact.get("basis") != "source_snapshot"
        or fact.get("scope") != "definition_selection"
        or fact.get("runtime_target_confirmed") is not False
        or query.get("module") != requested.module
        or query.get("qualname") != requested.qualname
        or query.get("lineno", 0) != (requested.lineno or 0)
        or requested.file_path
        and Path(query.get("file_path", "")) != requested.file_path
        or identity_from_target(fact.get("target")) != target
        or fact.get("source_hashes") != analysis.inputs.get("sha256")
        or fact.get("assumptions")
        != [
            "source_snapshot_bindings_hold",
            "no_external_monkeypatch_or_import_hook",
            "no_unmodeled_indirect_function_mutation",
        ]
        or not isinstance(fact.get("conditions"), (list, tuple))
        or len(fact["conditions"]) > 128
        or any(not isinstance(condition, dict) for condition in fact["conditions"])
        or not isinstance(assignments, (list, tuple))
        or not 1 <= len(assignments) <= 64
    ):
        return None

    # Replay each alias from the actual target name to the requested public name.
    # 从实际目标名逐次重放别名赋值，直至得到请求的公开名。
    previous = target.qualname.rsplit(".", 1)[-1]
    for assignment in assignments:
        if not isinstance(assignment, dict) or assignment.get("source_name") != previous:
            return None
        evidence = assignment.get("evidence", {})
        if (
            not isinstance(evidence, dict)
            or evidence.get("file_path") not in fact["source_hashes"]
            or Path(evidence["file_path"]) != target.file_path
            or not isinstance(assignment.get("name"), str)
            or not all(type(value) is int for value in _location(evidence))
        ):
            return None
        previous = assignment["name"]
    if previous != requested.qualname.rsplit(".", 1)[-1]:
        return None
    activation = [
        boundary.get("conditions", ())
        for boundary in analysis.boundaries
        if boundary.get("reason") == "conditional_definition_unconfirmed"
        and identity_from_target(boundary.get("function")) == target
    ]
    if (
        fact["conditions"]
        and fact["conditions"] not in activation
        or any(conditions != fact["conditions"] for conditions in activation)
    ):
        return None
    if not any(
        boundary.get("reason") == "source_entry_alias"
        and identity_from_target(boundary.get("function")) == target
        and boundary.get("assumptions") == fact["assumptions"]
        for boundary in analysis.boundaries
    ):
        return None
    return fact


## Validate class-name evidence against source hashes and call metadata.
## 根据源码哈希和调用元数据校验类名证据。
#
#  @param analysis Producer analysis containing source hashes
#  @param effect Class-name effect fact to validate
#  @return Whether the effect has a complete supported premise
def _class_name_premise(analysis, effect):
    basis = effect.get("name_basis")
    if basis is None:
        return "name_metadata" not in effect and "name_evidence" not in effect
    metadata = effect.get("name_metadata")
    if basis != "source_class_metadata" or not isinstance(metadata, dict):
        return False
    receiver, literal = metadata.get("receiver_class"), metadata.get("literal")
    hashes, assumptions = metadata.get("source_hashes"), metadata.get("assumptions")
    required = {
        "source_snapshot_bindings_hold",
        "builtin_type_name_metadata",
        "source_snapshot_class_name_binding_holds",
        "no_external_monkeypatch_or_import_hook",
        "no_unmodeled_indirect_class_mutation",
    }
    evidence = effect.get("name_evidence")
    return (
        metadata.get("kind") == "class_name_literal"
        and metadata.get("status") == "source_bound"
        and metadata.get("basis") == "source_snapshot"
        and metadata.get("attribute") == "__name__"
        and metadata.get("value_phase") == "call_entry"
        and metadata.get("runtime_value_confirmed") is False
        and metadata.get("source_scope") == "analysis_source_snapshot"
        and isinstance(metadata.get("issues"), (list, tuple))
        and not metadata["issues"]
        and isinstance(receiver, dict)
        and receiver == effect.get("receiver_class")
        and isinstance(receiver.get("qualname"), str)
        and bool(receiver["qualname"])
        and isinstance(literal, dict)
        and literal.get("type") == "str"
        and type(literal.get("value")) is str
        and literal["value"] == receiver["qualname"].rsplit(".", 1)[-1]
        and metadata.get("target") == effect.get("target")
        and metadata.get("parameter") == effect.get("parameter")
        and isinstance(metadata.get("call_id"), str)
        and bool(metadata["call_id"])
        and metadata["call_id"] == effect.get("call_id")
        and isinstance(assumptions, (list, tuple))
        and all(isinstance(item, str) for item in assumptions)
        and required.issubset(assumptions)
        and isinstance(hashes, dict)
        and bool(hashes)
        and hashes == analysis.inputs.get("sha256")
        and all(effect["source_hashes"].get(path) == digest for path, digest in hashes.items())
        and isinstance(evidence, (list, tuple))
        and bool(evidence)
        and all(
            isinstance(item, dict) and item.get("file_path") == effect["target"].get("file_path")
            for item in evidence
        )
    )


## Validate the source premises required for reading class metadata.
## 校验读取类元数据所需的源码前提。
#
#  @param analysis Producer analysis containing source hashes
#  @param effect Class-read effect fact to validate
#  @return Whether the class read is supported by complete source evidence
def _class_read_premises(analysis, effect):
    basis = effect.get("read_basis")
    if basis is None:
        return "read_premises" not in effect and "read_evidence" not in effect
    premises, evidence = effect.get("read_premises"), effect.get("read_evidence")
    if (
        basis != "source_class_attribute_invariant"
        or not isinstance(premises, (list, tuple))
        or not 1 <= len(premises) <= 2000
        or not isinstance(evidence, (list, tuple))
        or not 1 <= len(evidence) <= 2000
    ):
        return False
    required = {
        "source_snapshot_bindings_hold",
        "builtin_type_attribute_reads",
        "source_snapshot_class_attribute_invariant",
        "no_external_monkeypatch_or_import_hook",
        "no_unmodeled_indirect_class_mutation",
    }
    attributes = set()
    for premise in premises:
        if not isinstance(premise, dict):
            return False
        name, hashes, claims = (
            premise.get("attribute"),
            premise.get("source_hashes"),
            premise.get("assumptions"),
        )
        if (
            premise.get("kind") != "class_attribute_read_invariant"
            or premise.get("status") != "source_bound"
            or premise.get("basis") != "source_snapshot"
            or premise.get("state") != "absent_or_builtin_literal"
            or premise.get("value_phase") != "call_entry"
            or premise.get("runtime_value_confirmed") is not False
            or premise.get("source_scope") != "analysis_source_snapshot"
            or not isinstance(premise.get("issues"), (list, tuple))
            or premise["issues"]
            or not isinstance(name, str)
            or not name
            or len(name) > 2000
            or name == "mro"
            or name.startswith("__")
            and name.endswith("__")
            or name in attributes
            or any(
                premise.get(key) != effect.get(key)
                for key in ("receiver_class", "target", "parameter", "call_id", "call_evidence")
            )
            or not isinstance(premise.get("call_id"), str)
            or not premise["call_id"]
            or not isinstance(claims, (list, tuple))
            or not all(isinstance(claim, str) for claim in claims)
            or not required.issubset(claims)
            or not isinstance(hashes, dict)
            or not hashes
            or hashes != analysis.inputs.get("sha256")
            or any(effect["source_hashes"].get(path) != digest for path, digest in hashes.items())
            or not isinstance(premise.get("evidence"), (list, tuple))
            or not premise["evidence"]
            or any(
                not isinstance(source, dict) or source.get("file_path") not in hashes
                for source in premise["evidence"]
            )
        ):
            return False
        attributes.add(name)

    # Check that every read premise has a corresponding source witness.
    # 逐项确认读取前提都有对应的源码见证。
    witnessed = set()
    for item in evidence:
        if (
            not isinstance(item, dict)
            or item.get("operation") != "hasattr"
            or not isinstance(item.get("attribute"), str)
            or item["attribute"] not in attributes
            or not isinstance(item.get("evidence"), dict)
            or item["evidence"].get("file_path") != effect["target"].get("file_path")
        ):
            return False
        witnessed.add(item["attribute"])
    return witnessed == attributes


## Check whether source class lookup remains stable for a bound call.
## 检查已绑定调用的源码类查找是否保持稳定。
#
#  @param analysis Producer analysis for the call
#  @param call Call fact whose class lookup is examined
#  @param binding Source binding evidence for the call
#  @return Whether lookup preservation is established
def _class_lookup_preserved(analysis, call, binding):
    observed = []
    for value in call.receiver_sources:
        effects = value.get("class_lookup_mutations", ())
        if not isinstance(effects, (list, tuple)):
            return False
        for effect in effects:
            if effect not in observed:
                observed.append(effect)
    preserved = binding.get("lookup_preservation", ())
    if not isinstance(preserved, (list, tuple)) or list(preserved) != observed:
        return False
    if not observed:
        return True
    hierarchy = binding.get("lookup_hierarchy")
    if (
        not isinstance(hierarchy, (list, tuple))
        or not 1 <= len(hierarchy) <= 64
        or hierarchy[0] != binding.get("receiver_class")
        or any(
            not isinstance(owner, dict) or owner.get("file_path") not in binding["source_hashes"]
            for owner in hierarchy
        )
    ):
        return False
    assumptions = {
        "source_snapshot_bindings_hold",
        "builtin_type_attribute_writes",
        "no_external_monkeypatch_or_import_hook",
        "no_unmodeled_indirect_class_mutation",
    }

    # Check the specific member used by the call against each recorded receiver effect.
    # 将调用所用成员与每条接收者效果记录核对。
    attribute = call.callee_name.rsplit(".", 1)[-1]
    for effect in observed:
        if not isinstance(effect, dict):
            return False
        names, hashes, claims = (
            effect.get("attributes"),
            effect.get("source_hashes"),
            effect.get("assumptions"),
        )
        if (
            effect.get("kind") != "class_attribute_write_set"
            or effect.get("status") != "bounded"
            or effect.get("preserved_scope") != "other_class_attributes"
            or effect.get("completion") != "normal_return"
            or effect.get("value_completeness") != "unmodeled"
            or effect.get("receiver_class") not in hierarchy
            or not isinstance(names, (list, tuple))
            or len(names) > 2000
            or any(
                not isinstance(name, str)
                or name in (attribute, "mro")
                or name.startswith("__")
                and name.endswith("__")
                for name in names
            )
            or not isinstance(hashes, dict)
            or not hashes
            or not isinstance(effect.get("target"), dict)
            or effect["target"].get("file_path") not in hashes
            or not isinstance(claims, (list, tuple))
            or not all(isinstance(claim, str) for claim in claims)
            or not assumptions.issubset(claims)
            or any(
                binding["source_hashes"].get(path) != digest
                or analysis.inputs.get("sha256", {}).get(path) != digest
                for path, digest in hashes.items()
            )
        ):
            return False
        if not _class_name_premise(analysis, effect) or not _class_read_premises(analysis, effect):
            return False
    return True


## Validate source evidence for one classmethod receiver binding.
## 校验单个类方法接收者绑定的源码证据。
#
#  @param analysis Producer analysis containing binding evidence
#  @param call Call fact whose receiver binding is checked
#  @return Validated binding fact, or None when its contract is incomplete
def source_classmethod_binding(analysis, call):
    if analysis.inputs.get("conditional_source_state") or getattr(
        call, "conditional_source_bindings", ()
    ):
        return None
    bindings = getattr(call, "class_method_bindings", ())
    if (
        not isinstance(bindings, (list, tuple))
        or call.target_status != "classmethod"
        or call.target is None
        or len(bindings) != 1
    ):
        return None
    binding = bindings[0]
    if (
        not isinstance(binding, dict)
        or not isinstance(binding.get("descriptor"), dict)
        or not isinstance(binding.get("implicit_binding"), dict)
        or not isinstance(binding.get("source_hashes"), dict)
    ):
        return None
    receiver_boundaries = [
        boundary
        for boundary in analysis.boundaries
        if boundary.get("call_id") == call.id
        and boundary.get("reason") == "dynamic_class_receiver_override_possible"
    ]
    hashes = binding.get("source_hashes", {})
    valid = (
        binding.get("status") == "source_bound"
        and binding.get("basis") == "source_snapshot"
        and not binding.get("issues")
        and binding.get("runtime_target_confirmed") is False
        and binding.get("target") is not None
        and identity_from_target(binding["target"]) == identity_from_target(call.target)
        and binding.get("descriptor", {}).get("kind") == "builtin_classmethod"
        and binding.get("implicit_binding", {}).get("status") == "static_bound"
        and binding.get("implicit_binding", {}).get("receiver_class")
        == binding.get("receiver_class")
        and bool(hashes)
        and all(
            analysis.inputs.get("sha256", {}).get(path) == digest for path, digest in hashes.items()
        )
        and _class_lookup_preserved(analysis, call, binding)
        and bool(receiver_boundaries)
        and all(
            boundary.get("boundary_kind") == "assumption"
            and boundary.get("binding_status") == "source_bound"
            for boundary in receiver_boundaries
        )
        and all(
            isinstance(incoming, dict)
            and incoming.get("target") == binding["target"]
            and incoming.get("class_method_bindings") == bindings
            for incoming in getattr(call, "analysis_contexts", ())
        )
    )
    return binding if valid else None
