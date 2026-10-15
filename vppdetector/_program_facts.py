"""Shared source-matched fact readers; domain policy stays with each consumer."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

from .models import FunctionIdentity, SourceSpan


def capture_names(node, enclosing):
    """Use shared relay facts, retaining a diagnostic fallback for older dependencies."""

    try:
        from pcresolve.scope_facts import transitive_captured_names
    except ImportError:
        from pcresolve.scope_facts import captured_names, function_scope_facts

        return captured_names(function_scope_facts(node), enclosing)
    return transitive_captured_names(node, enclosing)


def immediate_body(node):
    """A synchronous named function call executes its body only if it is not a generator."""

    if not isinstance(node, ast.FunctionDef):
        return False
    pending = list(node.body)
    while pending:
        child = pending.pop()
        if isinstance(child, (ast.Yield, ast.YieldFrom)):
            return False
        if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            pending.extend(ast.iter_child_nodes(child))
    return True


def _location(value):
    return tuple(value.get(name) for name in (
        'lineno', 'col_offset', 'end_lineno', 'end_col_offset',
    ))


def _node_location(node):
    return (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)


def _expression(text):
    if not isinstance(text, str) or len(text) > 4096:
        return None
    try:
        node = ast.parse(text, mode='eval').body
        return node if sum(1 for _ in ast.walk(node)) <= 128 else None
    except (SyntaxError, ValueError, RecursionError):
        return None


def copy_protocol_target(owner, analysis, call, value) -> Optional[FunctionIdentity]:
    """Check an exact copy edge, its output object and its indexed source witness."""

    obj = value.get('container_object', {})
    results = call.result_sources
    if not (
        call.target_status == 'local_container_protocol'
        and call.analysis_status == 'analyzed'
        and CallFacts(analysis, call).complete_binding
        and not call.target
        and not call.target_candidates
        and value.get('kind') == 'call_result'
        and value.get('source') == call.id
        and value.get('object_only')
        and value.get('relation') == 'direct'
        and not any(value.get(flag) for flag in ('value_incomplete', 'projection', 'output_path'))
        and len(results) == 1
        and results[0].get('kind') == 'call_result'
        and results[0].get('relation') == 'direct'
        and not any(results[0].get(flag) for flag in (
            'value_incomplete', 'projection', 'output_path',
        ))
        and results[0].get('object_only')
        and results[0].get('source') == call.id
        and results[0].get('container_object') == obj
        and obj.get('source') and obj.get('copied_from')
        and obj.get('container_shape') in {'dict', 'list', 'tuple'}
        and obj.get('identity') in {'shallow_copy', 'argument_alias'}
        and len(call.effects) == 1
    ):
        return None
    effect = call.effects[0]
    if not (
        effect.get('kind') == 'container_copy'
        and effect.get('operation') == 'copy'
        and effect.get('status') == 'bounded'
        and effect.get('completion') == 'normal_return'
        and effect.get('input_container') == obj['copied_from']
        and effect.get('output_container') == obj['source']
        and effect.get('container_shape') == obj['container_shape']
        and effect.get('identity') == obj['identity']
        and (obj['identity'] != 'shallow_copy' or obj['source'] != obj['copied_from'])
        and (obj['identity'] != 'argument_alias' or (
            obj['container_shape'] == 'tuple' and obj['source'] == obj['copied_from']))
        and not any(b.get('call_id') == call.id and b.get('reason') not in {'depth_limit'}
                    for b in analysis.boundaries)
    ):
        return None
    witness = effect.get('evidence', {})
    node = _expression(witness.get('source_text'))
    location = (call.lineno, call.col_offset, call.end_lineno, call.end_col_offset)
    if (not isinstance(node, ast.Call) or _location(witness) != location
            or Path(witness.get('file_path', '')) != owner.identity.file_path
            or ast.unparse(node.func) != call.callee_name
            or not any(isinstance(source, ast.Call) and _node_location(source) == location
                       and ast.dump(source) == ast.dump(node) for source in ast.walk(owner.node))):
        return None
    if (isinstance(node.func, ast.Attribute) and node.func.attr == 'copy'
            and obj['container_shape'] == 'dict' and not node.args and not node.keywords):
        return FunctionIdentity('builtins', 'dict.copy')
    if (isinstance(node.func, ast.Name) and node.func.id == obj['container_shape']
            and len(node.args) == 1 and not isinstance(node.args[0], ast.Starred)
            and not node.keywords):
        return FunctionIdentity('builtins', node.func.id)
    return None


def _constant_truth(node, depth=0):
    if depth > 16:
        return None
    if isinstance(node, ast.Constant) and type(node.value) in (
        str, bytes, int, float, bool, type(None),
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


def conditions_possible(context, value) -> bool:
    """Prune only a recorded branch contradicted by matching constant source syntax."""

    for condition in value.get('conditions', ()):
        branch = condition.get('branch')
        witness = condition.get('test', {})
        if type(branch) is not bool or not isinstance(witness, dict):
            continue
        path = Path(witness.get('file_path', ''))
        if path not in context._constant_tests:
            tests = {}
            roots = [function.node for function in context.index.functions
                     if function.identity.file_path == path]
            roots.extend(context.index.condition_nodes.get(path, ()))
            for root in roots:
                for node in ast.walk(root):
                    if not isinstance(node, (ast.Constant, ast.UnaryOp, ast.BoolOp)):
                        continue
                    truth = _constant_truth(node)
                    if truth is not None:
                        tests[_node_location(node)] = (truth, ast.dump(node))
            context._constant_tests[path] = tests
        test = context._constant_tests[path].get(_location(witness))
        if test is None or test[0] == branch:
            continue
        node = _expression(witness.get('source_text'))
        if node is not None and ast.dump(node) == test[1]:
            return False
    return True


def identity_from_target(target: Any) -> FunctionIdentity:
    def value(name: str, default: Any) -> Any:
        if isinstance(target, dict):
            return target.get(name, default)
        return getattr(target, name, default)

    path = value("file_path", "")
    return FunctionIdentity(
        module=value("module", ""),
        qualname=value("qualname", ""),
        file_path=Path(path) if path else None,
        lineno=value("lineno", 0) or None,
    )


def candidate_identities(call: Any) -> tuple[FunctionIdentity, ...]:
    result = []
    for candidate in getattr(call, "target_candidates", ()):
        identity = identity_from_target(candidate)
        if identity not in result:
            result.append(identity)
    return tuple(result)


def direct_calls(analysis: Any, caller: FunctionIdentity) -> Iterable[Any]:
    for call in analysis.calls:
        owner = identity_from_target(call.caller)
        if (
            owner.module == caller.module
            and owner.qualname == caller.qualname
            and (not caller.lineno or owner.lineno == caller.lineno)
            and (not caller.file_path or owner.file_path == caller.file_path)
        ):
            yield call


def call_span(call: Any) -> SourceSpan:
    return SourceSpan(
        file_path=Path(call.caller.file_path or ""),
        lineno=call.lineno,
        col_offset=call.col_offset,
        end_lineno=call.end_lineno or call.lineno,
        end_col_offset=call.end_col_offset or call.col_offset,
    )


def target_status(analysis: Any, call: Any) -> str:
    if call.target_status != "resolved":
        return call.target_status
    if any(
        boundary.get("call_id") == call.id
        and boundary.get("reason", "").startswith("dynamic_")
        and boundary.get("reason") != "dynamic_argument_expansion"
        for boundary in analysis.boundaries
    ):
        return "source_candidate"
    return "resolved"


def _class_lookup_preserved(analysis: Any, call: Any, binding: dict) -> bool:
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
    if (not isinstance(hierarchy, (list, tuple)) or not 1 <= len(hierarchy) <= 64
            or hierarchy[0] != binding.get("receiver_class")
            or any(not isinstance(owner, dict) or owner.get("file_path") not in
                   binding["source_hashes"] for owner in hierarchy)):
        return False
    assumptions = {"source_snapshot_bindings_hold", "builtin_type_attribute_writes",
                   "no_external_monkeypatch_or_import_hook",
                   "no_unmodeled_indirect_class_mutation"}
    attribute = call.callee_name.rsplit(".", 1)[-1]
    for effect in observed:
        if not isinstance(effect, dict):
            return False
        names, hashes, claims = (effect.get("attributes"), effect.get("source_hashes"),
                                  effect.get("assumptions"))
        if (effect.get("kind") != "class_attribute_write_set" or effect.get("status") != "bounded"
                or effect.get("preserved_scope") != "other_class_attributes"
                or effect.get("completion") != "normal_return"
                or effect.get("value_completeness") != "unmodeled"
                or effect.get("receiver_class") not in hierarchy
                or not isinstance(names, (list, tuple)) or len(names) > 2000
                or any(not isinstance(name, str) or name in (attribute, "mro")
                       or name.startswith("__") and name.endswith("__") for name in names)
                or not isinstance(hashes, dict) or not hashes
                or not isinstance(effect.get("target"), dict)
                or effect["target"].get("file_path") not in hashes
                or not isinstance(claims, (list, tuple))
                or not all(isinstance(claim, str) for claim in claims)
                or not assumptions.issubset(claims)
                or any(binding["source_hashes"].get(path) != digest
                       or analysis.inputs.get("sha256", {}).get(path) != digest
                       for path, digest in hashes.items())):
            return False
    return True


def source_classmethod_binding(analysis: Any, call: Any) -> Optional[dict]:
    """Read a source binding proof tied to this call and every incoming context."""

    bindings = getattr(call, "class_method_bindings", ())
    if (not isinstance(bindings, (list, tuple)) or call.target_status != "classmethod"
            or call.target is None or len(bindings) != 1):
        return None
    binding = bindings[0]
    if (not isinstance(binding, dict)
            or not isinstance(binding.get("descriptor"), dict)
            or not isinstance(binding.get("implicit_binding"), dict)
            or not isinstance(binding.get("source_hashes"), dict)):
        return None
    receiver_boundaries = [boundary for boundary in analysis.boundaries
        if boundary.get("call_id") == call.id
        and boundary.get("reason") == "dynamic_class_receiver_override_possible"]
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
        and all(analysis.inputs.get("sha256", {}).get(path) == digest
                for path, digest in hashes.items())
        and _class_lookup_preserved(analysis, call, binding)
        and bool(receiver_boundaries)
        and all(boundary.get("boundary_kind") == "assumption"
                and boundary.get("binding_status") == "source_bound"
                for boundary in receiver_boundaries)
        and all(isinstance(incoming, dict) and incoming.get("target") == binding["target"]
                and incoming.get("class_method_bindings") == bindings
                for incoming in getattr(call, "analysis_contexts", ())))
    return binding if valid else None


def source_constructor_entry_binding(analysis: Any, requested: FunctionIdentity) -> Optional[dict]:
    """Validate a class-query binding separately from an actual call-site proof."""

    fact = analysis.inputs.get("entry_binding")
    if not isinstance(fact, dict):
        return None
    implicit = fact.get("implicit_binding")
    hashes = fact.get("source_hashes")
    evidence = fact.get("definition_evidence")
    hierarchy = fact.get("hierarchy")
    if (not isinstance(implicit, dict) or not isinstance(hashes, dict)
            or not isinstance(evidence, dict)
            or not isinstance(hierarchy, (list, tuple)) or not 1 <= len(hierarchy) <= 64
            or not isinstance(fact.get("assumptions"), (list, tuple))
            or not all(isinstance(item, str) for item in fact["assumptions"])):
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
    assumptions = {"source_snapshot_bindings_hold", "builtin_type_call_and_new_binding",
                   "no_external_monkeypatch_or_import_hook", "no_unmodeled_indirect_class_mutation"}
    valid = (
        fact.get("query_kind") == "source_class_call" and fact.get("basis") == "source_snapshot"
        and fact.get("status") == "source_bound" and not fact.get("issues")
        and fact.get("runtime_target_confirmed") is False
        and fact.get("instance_state") == "unmodeled"
        and receiver == requested and target == identity_from_target(analysis.entry)
        and owners[0] == receiver and len(set(owners)) == len(owners)
        and phase in ("__new__", "__init__") and target.qualname.endswith("." + phase)
        and fact.get("execution_scope") == ("new_invocation_only" if phase == "__new__"
                                            else "init_invocation_only")
        and fact.get("body_execution") == "synchronous" and implicit.get("status") == "static_bound"
        and isinstance(implicit.get("parameter"), str)
        and implicit.get("value_kind") == ("class" if phase == "__new__" else "instance")
        and bool(hashes) and str(receiver.file_path) in hashes and str(target.file_path) in hashes
        and all(str(owner.file_path) in hashes for owner in owners)
        and all(isinstance(path, str) and isinstance(digest, str)
                for path, digest in hashes.items())
        and all(analysis.inputs.get("sha256", {}).get(path) == digest
                for path, digest in hashes.items())
        and Path(evidence.get("file_path", "")) == receiver.file_path
        and evidence.get("lineno") == receiver.lineno
        and assumptions.issubset(fact["assumptions"])
        and any(b.get("reason") == "source_constructor_entry_binding"
                and b.get("boundary_kind") == "assumption"
                and b.get("function") == fact["target"] for b in analysis.boundaries)
    )
    return fact if valid else None


def source_constructor_binding(analysis: Any, call: Any) -> Optional[dict]:
    """Read one source constructor invocation proof, never initialized state."""

    bindings = getattr(call, "constructor_bindings", ())
    if (not isinstance(bindings, (list, tuple))
            or call.target_status != "constructor" or call.target is None
            or call.binding_status == "invalid" or len(bindings) != 1):
        return None
    binding = bindings[0]
    if (not isinstance(binding, dict)
            or not isinstance(binding.get("implicit_binding"), dict)
            or not isinstance(binding.get("source_hashes"), dict)
            or not isinstance(binding.get("receiver_class"), dict)
            or not isinstance(binding.get("assumptions"), (list, tuple))
            or not isinstance(binding.get("call_evidence"), dict)):
        return None
    implicit = binding["implicit_binding"]
    phase = binding.get("phase")
    if phase not in ("__new__", "__init__") or not all(
            isinstance(item, str) for item in binding["assumptions"]):
        return None
    initializer = phase == "__init__"
    scope = "init_invocation_only" if initializer else "new_invocation_only"
    slot = {"constructor_instance" if initializer else "constructor_class": True}
    receiver_kind = "instance_type" if initializer else "class_type"
    arguments = [a for a in call.argument_sources if a.get("argument") == slot
                 and a.get("parameter") == implicit.get("parameter")]
    records = [r for r in call.parameter_bindings if r.get("argument") == slot]
    values = [v for argument in arguments for v in argument.get("sources", ())]
    witness = binding["call_evidence"]
    assumptions = {"source_snapshot_bindings_hold", "builtin_type_call_and_new_binding",
                   "no_external_monkeypatch_or_import_hook",
                   "no_unmodeled_indirect_class_mutation"}
    valid = (
        binding.get("status") == "source_bound" and binding.get("basis") == "source_snapshot"
        and not binding.get("issues") and binding.get("runtime_target_confirmed") is False
        and call.target.qualname.endswith("." + phase)
        and binding.get("execution_scope") == scope
        and binding.get("instance_state") == "unmodeled"
        and binding.get("body_execution") in ("synchronous", "deferred")
        and binding.get("target") is not None
        and identity_from_target(binding["target"]) == identity_from_target(call.target)
        and implicit.get("status") == "static_bound" and implicit.get("argument") == slot
        and implicit.get("receiver_class") == binding.get("receiver_class")
        and len(records) == len(arguments) == 1 and records[0].get("status") == "exact"
        and records[0].get("parameter") == implicit.get("parameter")
        and bool(values) and all(v.get(receiver_kind) == binding.get("receiver_class")
            and v.get("relation") == "direct" and not any(v.get(flag) for flag in (
                "projection", "output_path", "value_incomplete", "import_modified",
                "import_incomplete")) for v in values)
        and Path(witness.get("file_path", "")) == Path(call.caller.file_path)
        and _location(witness) == (call.lineno, call.col_offset,
                                  call.end_lineno, call.end_col_offset)
        and bool(binding["source_hashes"])
        and all(analysis.inputs.get("sha256", {}).get(path) == digest
                for path, digest in binding["source_hashes"].items())
        and assumptions.issubset(binding.get("assumptions", ()))
        and any(b.get("call_id") == call.id
                and b.get("reason") == "source_constructor_" + phase.strip("_") + "_binding"
                and b.get("boundary_kind") == "assumption"
                and b.get("execution_scope") == scope for b in analysis.boundaries)
        and all(item.get("target") == binding["target"]
                and item.get("constructor_bindings") == bindings
                for item in call.analysis_contexts))
    return binding if valid else None



@dataclass(frozen=True)
class CallFacts:
    """A neutral view of one producer edge; optional semantics stay unproved."""

    analysis: Any
    call: Any

    @property
    def complete_binding(self):
        return self.call.binding_status == "complete" and not self.call.binding_issues

    @property
    def status(self):
        return target_status(self.analysis, self.call)

    @property
    def boundaries(self):
        return tuple(b for b in self.analysis.boundaries if b.get("call_id") == self.call.id)


def preserved_mapping_remainder(analysis, call, value):
    """Admit only current sources outside a producer's finite affected keys."""

    if (call.analysis_status != 'analyzed' or target_status(analysis, call) != 'resolved'
            or call.target is None or not CallFacts(analysis, call).complete_binding
            or len(call.effects) != 1):
        return False
    effect = call.effects[0]
    if (effect.get('kind') != 'mapping_remainder'
            or effect.get('operation') != 'preserve_unaffected_keys'
            or effect.get('completion') != 'normal_return'
            or effect.get('status') != 'bounded'
            or effect.get('value_completeness') != 'unaffected_keys_only'
            or effect.get('call_id') != call.id
            or identity_from_target(effect.get('function')) != identity_from_target(call.target)
            or not effect.get('evidence')
            or effect.get('assumptions') != [
                'fresh_unescaped_builtin_dict', 'source_snapshot_bindings_hold',
                'no_external_monkeypatch_or_import_hook', 'no_reflective_frame_access']
            or any(b.get('reason') in ('mapping_effect_unproven', 'mapping_remainder_budget',
                                       'mapping_effect_budget', 'container_effect_unknown')
                   for b in CallFacts(analysis, call).boundaries)):
        return False
    binding = effect.get('binding', {})
    arguments = [a for a in call.argument_sources if a.get('parameter') == effect.get('parameter')]
    witness = effect.get('call_evidence', {})
    if (binding.get('status') != 'exact' or binding not in call.parameter_bindings
            or binding.get('parameter') != effect.get('parameter')
            or len(arguments) != 1
            or arguments[0].get('container_binding', {}).get('source')
            != effect.get('object_source')
            or arguments[0].get('container_binding', {}).get('shape') != 'dict'
            or Path(witness.get('file_path', '')) != Path(call.caller.file_path)
            or _location(witness) != (call.lineno, call.col_offset,
                                      call.end_lineno, call.end_col_offset)):
        return False
    paths = effect.get('excluded_paths')
    if (not isinstance(paths, list) or len(paths) > 64
            or not all(isinstance(path, list) and len(path) == 1 and isinstance(path[0], str)
                       for path in paths)):
        return False
    returned = effect.get('return_object', {})
    route = effect.get('return_path')
    if (returned.get('identity') != 'argument_alias'
            or returned.get('source') != effect.get('object_source')
            or returned.get('parameter') != effect.get('parameter')
            or returned.get('value_completeness') != 'unaffected_keys_only'
            or identity_from_target(returned.get('function')) != identity_from_target(call.target)
            or not (route is None or route == [] or isinstance(route, list) and len(route) == 1
                    and type(route[0]) is int and route[0] >= 0)):
        return False
    if value.get('object_only'):
        return value.get('container_object', {}).get('source') == effect.get('object_source')
    return (value.get('kind') in ('parameter', 'capture')
            and any(root.get('name') == value.get('source') for root in effect.get('mapping', []))
            and all(path in value.get('excluded_paths', []) for path in paths))
