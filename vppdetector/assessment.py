"""Narrow call-conditioned assessment of one variadically captured argument.

This is not a Python interpreter or a repair policy. Only finite call binding,
simple guards, finite sequence operations and named-key operations with
PCResolve evidence are modeled.
Unsupported control/effects stop the proof, rather than imply compatibility.
"""

from __future__ import annotations

import ast
import builtins
import copy
import hashlib
import inspect
import json
import operator
import textwrap
import tokenize
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Sequence, Union

from ._analysis_context import (
    AnalysisContext,
    PathLike,
    ScanSource,
)
from ._analysis_context import (
    prepare_context as _prepare_context,
)
from ._analysis_context import (
    validate_depth as _validate_depth,
)
from ._attribute_retention import attribute_retention as observed_attribute_retention
from ._cached_imports import cached_import_binding
from ._caller_arguments import caller_arguments
from ._capture_rejection import capture_rejection as observed_capture_rejection
from ._container_predicates import container_predicate as observed_container_predicate
from ._fact_adapter import ResolutionError
from ._fixed_binding import fixed_binding as observed_fixed_binding
from ._mapping_key_access import closed_keys as closed_mapping_keys
from ._normal_returns import mapping_return as observed_mapping_return
from ._observed_checks import keyword_check as observed_keyword_check
from ._program_facts import (
    CallFacts,
    call_span,
    candidate_identities,
    capture_names,
    conditions_possible,
    container_length_protocol,
    copy_protocol_target,
    direct_calls,
    exact_callability_protocol,
    identity_from_target,
    immediate_body,
    mapping_protocol,
    scalar_truth_protocol,
    source_classmethod_binding,
    source_constructor_binding,
)
from ._program_facts import (
    target_status as _target_status,
)
from ._static_attribute_retention import retained_store as static_retained_store
from .models import (
    AnalysisBoundary,
    CallContext,
    ChangeKind,
    FunctionIdentity,
    ParameterAssessment,
    ParameterChange,
    ParameterEvidence,
    ParameterState,
    SourceSpan,
)
from .source import IndexedFunction

_UNKNOWN = object()


@dataclass(frozen=True)
class _Value:
    literal: Any = _UNKNOWN
    tracked: bool = False
    key_presence: bool = False
    source_state: bool = False
    consumed: bool = False
    type_selected: bool = False


@dataclass
class _Keywords:
    items: dict
    carrier: bool = False
    source_state: bool = False


@dataclass(frozen=True)
class _Positionals:
    items: tuple
    carrier: bool = False
    kind: str = "tuple"
    source_state: bool = False


@dataclass(frozen=True)
class _KeySet:
    # Values mark which known key's presence belongs to the selected argument.
    items: dict


@dataclass(frozen=True)
class _SourceInstance:
    attributes: dict


@dataclass(frozen=True)
class _LocalFunction:
    node: ast.AST


def _source_state(value):
    if not isinstance(value, dict):
        raise ValueError("Unproven receiver state")
    kind = value.get("kind")
    if kind == "literal" and type(value.get("value")) in (str, bytes, int, float, bool, type(None)):
        return _Value(value["value"], source_state=True)
    if (
        kind == "mapping"
        and isinstance(value.get("items"), dict)
        and all(type(key) is str for key in value["items"])
    ):
        return _Keywords(
            {key: _source_state(item) for key, item in value["items"].items()}, source_state=True
        )
    if kind in {"tuple", "list"} and isinstance(value.get("items"), list):
        return _Positionals(
            tuple(_source_state(item) for item in value["items"]), kind=kind, source_state=True
        )
    raise ValueError("Unproven receiver state")


def _tracked(value: Any) -> bool:
    if isinstance(value, _Keywords):
        return any(_tracked(item) for item in value.items.values())
    if isinstance(value, _Positionals):
        return any(_tracked(item) for item in value.items)
    if isinstance(value, _KeySet):
        return any(value.items.values())
    return isinstance(value, _Value) and value.tracked


def _raw_selected(value, seen=None):
    """Keep unresolved original values distinct from proved scalar conversions."""
    seen = set() if seen is None else seen
    if id(value) in seen:
        return False
    seen.add(id(value))
    if isinstance(value, _Value):
        return value.tracked and not value.consumed
    if isinstance(value, _Keywords):
        return any(_raw_selected(item, seen) for item in value.items.values())
    if isinstance(value, _Positionals):
        return any(_raw_selected(item, seen) for item in value.items)
    if isinstance(value, _SourceInstance):
        return any(_raw_selected(item, seen) for item in value.attributes.values())
    return isinstance(value, _KeySet) and _tracked(value)


def _protected_state(value: Any) -> bool:
    if isinstance(value, _SourceInstance):
        return True
    if bool(getattr(value, "source_state", False)):
        return True
    if isinstance(value, _Positionals):
        return any(_protected_state(item) for item in value.items)
    if isinstance(value, _Keywords):
        return any(_protected_state(item) for item in value.items.values())
    return False


def _key_presence(value: Any) -> bool:
    if isinstance(value, _Value):
        return value.key_presence
    return isinstance(value, (_Keywords, _KeySet)) and _tracked(value)


def _finite(node: ast.AST) -> _Value:
    if isinstance(node, ast.Constant) and type(node.value) in (
        str,
        bytes,
        int,
        float,
        bool,
        type(None),
    ):
        return _Value(node.value)
    return _Value()


def _signature(function: IndexedFunction, bound: bool) -> inspect.Signature:
    args = function.node.args
    positional = args.posonlyargs + args.args
    defaults = dict(
        zip(
            (node.arg for node in positional[len(positional) - len(args.defaults) :]), args.defaults
        )
    )
    defaults.update(
        (node.arg, value)
        for node, value in zip(args.kwonlyargs, args.kw_defaults)
        if value is not None
    )
    parameters = []
    for nodes, kind in (
        (args.posonlyargs, inspect.Parameter.POSITIONAL_ONLY),
        (args.args, inspect.Parameter.POSITIONAL_OR_KEYWORD),
        ((args.vararg,) if args.vararg else (), inspect.Parameter.VAR_POSITIONAL),
        (args.kwonlyargs, inspect.Parameter.KEYWORD_ONLY),
        ((args.kwarg,) if args.kwarg else (), inspect.Parameter.VAR_KEYWORD),
    ):
        for node in nodes:
            if bound and positional and node is positional[0]:
                continue
            default = (
                _finite(defaults[node.arg]) if node.arg in defaults else inspect.Parameter.empty
            )
            parameters.append(inspect.Parameter(node.arg, kind, default=default))
    return inspect.Signature(parameters)


class _Stop(Exception):
    def __init__(self, state: ParameterState, reason: str):
        self.state, self.reason = state, reason


@dataclass
class _Proof:
    context: AnalysisContext
    max_depth: int
    known_targets: dict = field(default_factory=dict)
    known_conditions: dict = field(default_factory=dict)
    evidence: list = field(default_factory=list)
    boundaries: list = field(default_factory=list)
    handled_reason: Optional[str] = None
    consumption_witness: Optional[ParameterEvidence] = None
    frames: list = field(default_factory=list, repr=False)
    unrelated_unpack_continuation: bool = False

    def note(self, function, reason, detail, node=None, target=None):
        span = (
            None
            if node is None
            else SourceSpan(
                function.identity.file_path,
                node.lineno,
                node.col_offset,
                node.end_lineno,
                node.end_col_offset,
            )
        )
        self.evidence.append(ParameterEvidence(function.identity, reason, detail, span, target))

    def unknown(self, function, reason, detail, node=None):
        self.note(function, reason, detail, node)
        self.boundaries.append(
            AnalysisBoundary(reason, detail, function.identity, self.evidence[-1].callsite)
        )
        if (reason in ('mapping_effect_unproven', 'call_target_unproven',
                       'ordinary_container_binding_unproven')
                and self.consumption_witness is not None and not any(
                frame.expression_depth > 1 for frame in self.frames) and not any(
                _raw_selected(value) for frame in self.frames
                for value in [*frame.values.values(),
                              *(v for pending in frame.pending_values for v in pending)])):
            self.note(function, 'proven_consumption_before_boundary',
                      'An earlier supported operation used the selected argument; '
                      'later effects and call success remain unresolved.', node)
            raise _Stop(ParameterState.HANDLED, 'proven_consumption_before_boundary')
        raise _Stop(ParameterState.UNKNOWN, reason)

    def handled(self, function, reason, detail, node=None, target=None):
        self.note(function, reason, detail, node, target)
        self.handled_reason = reason
        if reason in ('consumed_presence', 'consumed_value'):
            self.consumption_witness = self.evidence[-1]

    def bind(self, function, positional, keywords, bound, node=None, *, caller=None, change=None):
        signature = _signature(function, bound)
        owner = caller or function
        slots = [
            p.name
            for p in signature.parameters.values()
            if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
        ]
        for position, value in enumerate(positional):
            if not _tracked(value):
                continue
            if position >= len(slots) and not function.signature.vararg:
                self.reject(
                    owner,
                    "too_many_positional_arguments",
                    f"Selected value reaches positional slot {position}; capacity is {len(slots)}.",
                    node,
                    function.identity,
                )
            if position < len(slots) and slots[position] in keywords:
                self.reject(
                    owner, "duplicate_argument_binding", slots[position], node, function.identity
                )
        for name, value in keywords.items():
            if not _tracked(value):
                continue
            parameter = signature.parameters.get(name)
            if parameter and parameter.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD:
                if name in slots[: len(positional)]:
                    self.reject(owner, "duplicate_argument_binding", name, node, function.identity)
            if (parameter is None or parameter.kind is inspect.Parameter.POSITIONAL_ONLY) and not (
                function.signature.kwarg
            ):
                self.reject(owner, "unexpected_keyword_argument", name, node, function.identity)
        try:
            binding = signature.bind(*positional, **keywords)
        except TypeError as exc:
            if change and change.kind is ChangeKind.RENAME:
                try:
                    partial = signature.bind_partial(*positional, **keywords)
                except TypeError:
                    partial = None
                missing = [
                    p.name
                    for p in signature.parameters.values()
                    if p.default is p.empty
                    and p.kind not in (p.VAR_POSITIONAL, p.VAR_KEYWORD)
                    and partial is not None
                    and p.name not in partial.arguments
                ]
                if missing == [change.new_name]:
                    self.reject(
                        owner,
                        "required_parameter_unbound",
                        change.new_name,
                        node,
                        function.identity,
                    )
            if (change is not None and caller is None and node is None
                    and not function.node.decorator_list):
                self.note(function, 'entry_binding_failed',
                          'The original call cannot enter this source implementation: '
                          + str(exc) + '. This does not reject the selected argument '
                          'or authorize its deletion.')
                raise _Stop(ParameterState.NOT_ENTERED, 'entry_binding_failed')
            self.unknown(owner, "call_binding_unproven", str(exc), node)
        binding.apply_defaults()
        values = dict(binding.arguments)
        if function.signature.vararg:
            values[function.signature.vararg] = _Positionals(
                tuple(values.get(function.signature.vararg, ())), carrier=True
            )
        if function.signature.kwarg:
            values[function.signature.kwarg] = _Keywords(
                values.get(function.signature.kwarg, {}), carrier=True
            )
        return values

    def reject(self, function, reason, detail, node=None, target=None):
        if self.unrelated_unpack_continuation:
            self.unknown(function, 'rejection_after_unconfirmed_unpack',
                         'An earlier unrelated unpack may terminate after a proven use; '
                         'this later rejection is not definitely reached.', node)
        self.note(function, reason, detail, node, target or function.identity)
        raise _Stop(ParameterState.REJECTED, reason)

    def decoration_preserved(self, function, analysis):
        """Consume one exact body/binding proof, not callable identity alone."""

        summaries = [
            item
            for item in analysis.functions
            if identity_from_target(item["function"]) == function.identity
        ]
        if len(function.node.decorator_list) != 1 or len(summaries) != 1:
            return False
        effects = summaries[0].get("decorator_effects", ())
        if len(effects) != 1:
            return False
        fact = effects[0]
        expression = fact.get("expression", {})
        decorator = function.node.decorator_list[0]
        if (
            identity_from_target(fact.get("function", {})) != function.identity
            or Path(expression.get("file_path", "")) != function.identity.file_path
            or any(
                expression.get(name) != getattr(decorator, name)
                for name in ("lineno", "col_offset", "end_lineno", "end_col_offset")
            )
            or fact.get("identity_status") != "preserved"
            or fact.get("body_binding_status") != "preserved"
            or fact.get("basis") != "source_snapshot"
            or fact.get("completion") != "normal_return"
            or fact.get("runtime_target_confirmed") is not False
            or fact.get("boundaries")
            or not fact.get("assumptions")
            or not fact.get("evidence")
            or not fact.get("target")
        ):
            return False
        # Supporting records are admitted only within the closed proof above.
        # They do not independently establish that a helper or cache is harmless.
        for effect in fact.get("effects", ()):
            kind = (effect.get("operation"), effect.get("impact"))
            target = effect.get("target")
            if target == "input_function":
                if kind != ("attribute_write", "documentation"):
                    return False
                if effect.get("element_path") != ["__doc__"]:
                    return False
            elif isinstance(target, dict):
                if kind != ("helper_call", "analyzed_source"):
                    return False
            elif target == "documentation_cache":
                if kind not in (
                    ("construction", "data_only"),
                    ("setdefault", "data_only"),
                    ("mapping_lookup", "data_protocol"),
                ):
                    return False
            elif target == "decorator_instance":
                construction = fact.get("construction") or {}
                path = effect.get("element_path", ())
                scalar_shapes = {"str", "int", "bool", "float", "NoneType"}
                if (
                    kind != ("attribute_write", "data_only")
                    or construction.get("lifetime") != "single_decoration"
                    or len(path) != 1
                    or not path[0].isidentifier()
                    or path[0].startswith("__")
                    or not effect.get("before_shapes")
                    or not set(effect["before_shapes"]) <= scalar_shapes
                    or not effect.get("after_shapes")
                    or not set(effect["after_shapes"]) <= scalar_shapes
                    or effect.get("conditions")
                ):
                    return False
            elif target in ('inspect.cleandoc', 'textwrap.dedent'):
                if (kind != ('builtin_call', 'data_only')
                        or effect.get('protocol') != 'stdlib_text_normalization'
                        or effect.get('input_shapes') != [['str']]
                        or effect.get('output_shape') != 'str'
                        or effect.get('completion') != 'normal_return'
                        or 'standard_library_text_protocols_hold' not in fact['assumptions']):
                    return False
            elif target in ('str.split', 'str.format', 'str.endswith'):
                shapes = effect.get('argument_shapes')
                if (kind != ('builtin_call', 'data_only')
                        or effect.get('protocol') != 'finite_builtin_text'
                        or effect.get('receiver_shape') != 'str'
                        or effect.get('completion') != 'normal_return'
                        or not isinstance(shapes, list)
                        or any(shape != ['str'] for shape in shapes)
                        or target == 'str.split' and (
                            shapes != [['str']] or effect.get('output_shape') != 'list_of_str'
                            or effect.get('restriction') != 'explicit_nonempty_separator')
                        or target == 'str.format' and (
                            effect.get('output_shape') != 'str'
                            or effect.get('restriction') != 'no_attribute_or_item_fields')
                        or target == 'str.endswith' and (
                            shapes != [['str']] or effect.get('output_shape') != 'bool'
                            or effect.get('restriction') != 'literal_string_suffix')):
                    return False
            elif target == 'str.__getitem__':
                bounds = effect.get('bounds')
                if (kind != ('builtin_call', 'data_only')
                        or effect.get('protocol') != 'finite_builtin_text_slice'
                        or effect.get('receiver_shape') != 'str'
                        or effect.get('output_shape') != 'str'
                        or effect.get('completion') != 'normal_return'
                        or not isinstance(bounds, list) or len(bounds) != 3
                        or any(type(value) not in (int, type(None)) for value in bounds)
                        or bounds[2] == 0):
                    return False
            elif target == 'len':
                if (kind != ('builtin_call', 'data_only')
                        or effect.get('protocol') != 'exact_builtin_string_length'
                        or effect.get('input_shapes') != [['str']]
                        or effect.get('output_shape') != 'int'
                        or effect.get('completion') != 'normal_return'
                        or fact.get('source_hashes') != analysis.inputs.get('sha256')
                        or not {'standard_builtin_namespace_preserved',
                                'no_unmodeled_indirect_builtin_mutation'}.issubset(fact['assumptions'])):
                    return False
            elif target in ('KeyError', 'TypeError', 'ValueError', 'AttributeError'):
                shapes = effect.get('argument_shapes')
                if (kind != ('raise', 'control_only')
                        or effect.get('protocol') != 'builtin_exception_raise'
                        or effect.get('completion') != 'exceptional_exit'
                        or not isinstance(shapes, list)
                        or any(not isinstance(shape, list) or not shape
                               or any(item not in ('str', 'int', 'bool', 'float', 'NoneType')
                                      for item in shape) for shape in shapes)
                        or fact.get('source_hashes') != analysis.inputs.get('sha256')
                        or not {'standard_builtin_namespace_preserved',
                                'no_unmodeled_indirect_builtin_mutation'}.issubset(fact['assumptions'])):
                    return False
            elif target == "str.join":
                if (
                    kind != ("builtin_call", "data_only")
                    or effect.get("receiver_shape") != "str"
                    or effect.get("sequence_shape") not in ("list", "tuple")
                    or "element_shapes" not in effect
                    or any(shape != ["str"] for shape in effect["element_shapes"])
                ):
                    return False
            else:
                return False
        hashes = fact.get("source_hashes", {})
        if str(function.identity.file_path) not in hashes:
            return False
        try:
            for path, digest in hashes.items():
                # Match the producer's decoded, universal-newline source snapshot.
                with Path(path).open(encoding='utf-8-sig') as stream:
                    actual = hashlib.sha256(stream.read().encode('utf-8')).hexdigest()
                if actual != digest:
                    return False
        except (OSError, UnicodeError):
            return False
        self.note(
            function,
            "source_decorator_binding",
            "Original body/binding preserved on normal decoration completion; "
            + "; ".join(fact["assumptions"]),
            decorator,
        )
        return True

    def run(self, function, values, *, analysis=None, ancestry=(), facts=()):
        if function.identity in ancestry:
            self.unknown(function, "recursive_forwarding", "Recursive variadic forwarding.")
        if len(ancestry) >= self.max_depth:
            self.unknown(function, "depth_limit", "Argument propagation depth exhausted.")
        if not immediate_body(function.node):
            self.unknown(
                function, "deferred_execution", "Async/generator execution is not modeled."
            )
        try:
            analysis = analysis or self.context.adapter.analyze(
                function.query_class or function.query_alias or function.identity)
        except ResolutionError as exc:
            self.unknown(function, exc.code, str(exc))
        if (function.query_class is not None
                and analysis.inputs.get("entry_binding", {}).get("phase") == "__new__"):
            self.unknown(function, "dynamic_construction",
                         "Later constructor phases are unmodeled.")
        if function.node.decorator_list and not self.decoration_preserved(function, analysis):
            for summary in analysis.functions:
                if identity_from_target(summary['function']) != function.identity:
                    continue
                for fact in summary.get('decorator_effects', ()):
                    for boundary in fact.get('boundaries', ()):
                        helper = boundary.get('source_target')
                        if (boundary.get('source_available') is False and isinstance(helper, str)
                                and boundary.get('reason') == 'decorator_call_unresolved'):
                            self.boundaries.append(AnalysisBoundary(
                                'decorator_source_unavailable',
                                f'Decorator helper {helper} has no source in this snapshot.',
                                function.identity,
                            ))
            self.unknown(function, "decorated_entry", "Entry/body decoration is not proven.")
        mapping = values.get(function.signature.kwarg)
        if (isinstance(mapping, _Keywords) and not mapping.source_state
                and _tracked(mapping)
                and not any(_tracked(value) for name, value in values.items()
                            if name != function.signature.kwarg)):
            keys = closed_mapping_keys(analysis, function)
            selected = {key for key, value in mapping.items.items() if _tracked(value)}
            if keys is not None and selected.isdisjoint(keys):
                self.note(function, 'unread_mapping_element',
                          'PCResolve bounds all capture accesses to fixed keys: '
                          + ', '.join(sorted(keys)) + '. The selected element is unread. '
                          'Assumes no external frame introspection; execution and call success '
                          'are not established.')
                return _Value()
        frame = _Frame(
            self, function, analysis, values, ancestry + (function.identity,), dict(facts)
        )
        self.frames.append(frame)
        try:
            frame.statements(function.node.body)
        finally:
            self.frames.pop()
        return frame.result


@dataclass
class _Frame:
    proof: _Proof
    function: IndexedFunction
    analysis: Any
    values: dict
    ancestry: tuple
    facts: dict
    returned: bool = False
    rejection_guard: bool = False
    result: Any = field(default_factory=_Value)
    pending_values: list = field(default_factory=list, repr=False)
    expression_depth: int = 0

    def unknown(self, reason, node):
        self.proof.unknown(
            self.function, reason, ast.unparse(node), node if self.analysis is not None else None
        )

    def related(self, node):
        return any(
            isinstance(item, ast.Name)
            and (
                _tracked(self.values.get(item.id))
                or isinstance(self.values.get(item.id), (_Keywords, _Positionals))
                and self.values[item.id].carrier
            )
            for item in ast.walk(node)
        )

    def simple_guard_read(self, node):
        """Accept finite-model reads, not calls, projections or known getters."""

        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return self.simple_guard_read(node.operand)
        if isinstance(node, ast.Name):
            value = self.values.get(node.id)
            return isinstance(value, _Value) and not value.tracked
        if not isinstance(node, ast.Attribute) or not isinstance(node.value, ast.Name):
            return False
        positional = self.function.node.args.posonlyargs + self.function.node.args.args
        if (
            not self.function.is_bound_method
            or not positional
            or node.value.id != positional[0].arg
            or node.value.id in self.values
        ):
            return False
        owner = self.function.identity.qualname.rpartition(".")[0]
        names = {owner + "." + name for name in (node.attr, "__getattribute__", "__getattr__")}
        return not any(
            function.identity.module == self.function.identity.module
            and function.identity.qualname in names
            for function in self.proof.context.index.functions
        )

    def normal_path_guard(self, statement):
        """Record an unrelated error-only guard without inventing its value."""

        if self.related(statement) or not self.simple_guard_read(statement.test):
            return False
        for exceptional, normal, required in (
            (statement.body, statement.orelse, False),
            (statement.orelse, statement.body, True),
        ):
            if len(exceptional) != 1 or any(not isinstance(item, ast.Pass) for item in normal):
                continue
            raised = exceptional[0]
            if not isinstance(raised, ast.Raise) or raised.cause is not None:
                continue
            call = raised.exc
            if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name):
                continue
            exception = getattr(builtins, call.func.id, None)
            if (
                not isinstance(exception, type)
                or not issubclass(exception, Exception)
                or call.keywords
                or any(not isinstance(item, ast.Constant) for item in call.args)
                or not self.unshadowed_builtin_name(call.func.id)
            ):
                continue
            edge = next(
                (
                    edge
                    for edge in direct_calls(self.analysis, self.function.identity)
                    if (edge.lineno, edge.col_offset, edge.end_lineno, edge.end_col_offset)
                    == (call.lineno, call.col_offset, call.end_lineno, call.end_col_offset)
                ),
                None,
            )
            if edge is None or edge.target is not None or edge.target_status != "builtin_boundary":
                continue
            test = ast.unparse(statement.test)
            condition = f"({test})" if required else f"not ({test})"
            self.proof.note(
                self.function,
                "normal_path_precondition",
                f"Normal execution requires {condition}; the guard value is not inferred.",
                statement.test,
            )
            return True
        return False

    def unshadowed_builtin_name(self, name):
        from pcresolve.scope_facts import statement_scope_facts

        try:
            with tokenize.open(self.function.identity.file_path) as stream:
                tree = ast.parse(stream.read())
        except (OSError, SyntaxError, UnicodeError):
            return False
        scopes = [tree] + [
            item
            for item in ast.walk(tree)
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            and item.lineno <= self.function.node.lineno <= item.end_lineno
        ]
        return name not in self.values and all(
            name not in (facts.bound | facts.globals | facts.nonlocals)
            for scope in scopes
            for facts in (statement_scope_facts(scope.body),)
        )

    def finite_identity_truth(self, node, depth=0):
        """Join only pure local identity probes, without reading custom truth values."""
        if depth > 8:
            return None
        if isinstance(node, ast.BoolOp) and len(node.values) <= 8:
            possibilities = {isinstance(node.op, ast.And)}
            for child in node.values:
                incoming = self.finite_identity_truth(child, depth + 1)
                if incoming is None:
                    return None
                possibilities = {
                    (left and right if isinstance(node.op, ast.And) else left or right)
                    for left in possibilities for right in incoming
                }
            return possibilities
        if (not isinstance(node, ast.Compare) or len(node.ops) != 1
                or not isinstance(node.ops[0], (ast.Is, ast.IsNot))
                or not isinstance(node.left, ast.Name)
                or not isinstance(node.comparators[0], ast.Constant)
                or node.comparators[0].value is not None):
            return None
        value = self.values.get(node.left.id)
        if not isinstance(value, _Value):
            return None
        if value.literal is _UNKNOWN:
            return {False, True}
        equal = value.literal is None
        return {equal if isinstance(node.ops[0], ast.Is) else not equal}

    def statements(self, statements):
        for statement in statements:
            if self.returned:
                break
            if isinstance(statement, ast.Return):
                result = self.expression(statement.value) if statement.value else _Value(None)
                self.result = result
                if _tracked(result):
                    self.proof.handled(
                        self.function, "consumed_value", "Value participates in return.", statement
                    )
                self.returned = True
            elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
                result = self.expression(statement.value) if statement.value else _Value()
                targets = (
                    statement.targets if isinstance(statement, ast.Assign) else (statement.target,)
                )
                for target in targets:
                    if isinstance(target, (ast.Tuple, ast.List)):
                        names = [child.id for child in ast.walk(target)
                                 if isinstance(child, ast.Name)]
                        plain = all(isinstance(child, (ast.Tuple, ast.List, ast.Name,
                                                      ast.Store, ast.Load))
                                    for child in ast.walk(target))
                        if (not isinstance(result, _Positionals) and plain
                                and self.proof.consumption_witness is not None
                                and not self.related(statement) and not _tracked(result)
                                and not _protected_state(result)):
                            for name in names:
                                if isinstance(self.values.get(name), _LocalFunction):
                                    self.unknown('local_callable_rebinding', statement)
                                self.values[name] = _Value()
                                for path in tuple(self.facts):
                                    if path == name or path.startswith(name + '.'):
                                        del self.facts[path]
                            self.proof.unrelated_unpack_continuation = True
                            self.proof.note(self.function, 'unrelated_unpack_after_consumption',
                                            'The selected argument was already used. If this '
                                            'unrelated unpack fails, that use remains; otherwise '
                                            'the continuation is checked with unknown locals.',
                                            statement)
                            continue
                        for name, item in self.finite_unpack(target, result):
                            if isinstance(self.values.get(name), _LocalFunction):
                                self.unknown('local_callable_rebinding', statement)
                            self.values[name] = item
                            for path in tuple(self.facts):
                                if path == name or path.startswith(name + '.'):
                                    del self.facts[path]
                        continue
                    if not isinstance(target, ast.Name):
                        capture = self.function.signature.kwarg
                        mapping_store = (
                            isinstance(result, _Keywords) and result.carrier
                            and not result.source_state
                            and result is self.values.get(capture)
                        )
                        if _tracked(result) and (isinstance(result, _Value) or mapping_store):
                            retention = static_retained_store(
                                self.analysis, self.function, statement, target,
                                mapping_capture=capture if mapping_store else None,
                            )
                            if retention is not None:
                                self.proof.handled(
                                    self.function, "retained_instance_attribute",
                                    "PCResolve proves an ordinary fresh-instance store of the "
                                    "selected value, without later overwrite or receiver escape "
                                    "before normal constructor return. "
                                    + "; ".join(retention["assumptions"]), statement,
                                )
                                continue
                        root = target
                        while isinstance(root, (ast.Attribute, ast.Subscript)):
                            root = root.value
                        if isinstance(root, ast.Name) and _protected_state(
                            self.values.get(root.id)
                        ):
                            self.unknown("callable_instance_state_write_unproven", statement)
                        if self.related(statement) or _tracked(result):
                            self.unknown("unsupported_assignment", statement)
                        path = ast.unparse(target)
                        for name in tuple(self.facts):
                            if name == path or name.startswith(path + "."):
                                del self.facts[name]
                        continue
                    if isinstance(self.values.get(target.id), _LocalFunction):
                        self.unknown("local_callable_rebinding", statement)
                    self.values[target.id] = result
                    # A reassignment invalidates trusted receiver/parameter facts too.
                    for name in tuple(self.facts):
                        if name == target.id or name.startswith(target.id + "."):
                            del self.facts[name]
            elif isinstance(statement, ast.Expr):
                self.expression(statement.value)
            elif isinstance(statement, (ast.Import, ast.ImportFrom)):
                binding = cached_import_binding(self.analysis, self.function, statement)
                if binding is None:
                    self.unknown('local_import_execution_unconfirmed', statement)
                for value in binding['bindings']:
                    name = value['name']
                    self.values[name] = _Value()
                    for path in tuple(self.facts):
                        if path == name or path.startswith(name + '.'):
                            del self.facts[path]
                self.proof.note(self.function, 'source_cached_import_binding',
                                'Source initialization already imported this module. '
                                'Continuation assumes the recorded import cache and namespace '
                                'bindings remain unchanged: ' + '; '.join(binding['assumptions']),
                                statement)
            elif isinstance(statement, ast.If):
                condition = self.expression(statement.test)
                truth = self.truth(condition)
                span = SourceSpan(self.function.identity.file_path, statement.test.lineno,
                                  statement.test.col_offset, statement.test.end_lineno,
                                  statement.test.end_col_offset)
                if (span in self.proof.known_conditions
                        and not self.related(statement.test)):
                    supplied = self.proof.known_conditions[span]
                    if truth is not None and truth is not supplied:
                        self.unknown('conflicting_call_facts', statement.test)
                    truth = supplied
                    self.proof.note(self.function, 'supplied_condition_fact',
                                    'Caller supplied the global predicate outcome: '
                                    + str(supplied), statement.test)
                if truth is None:
                    if self.normal_path_guard(statement):
                        continue
                    abrupt = any(
                        isinstance(item, (ast.Return, ast.Raise, ast.Break, ast.Continue))
                        for branch in (*statement.body, *statement.orelse)
                        for item in ast.walk(branch)
                    )
                    if self.related(statement) or abrupt:
                        self.unknown("unresolved_condition", statement.test)
                    # Only non-terminating, unrelated branches may be skipped.
                    for item in ast.walk(statement):
                        if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Store):
                            self.values[item.id] = _Value()
                            self.facts.pop(item.id, None)
                    continue
                if _tracked(condition):
                    self.proof.handled(
                        self.function,
                        "consumed_presence",
                        "Parameter controls a guard.",
                        statement.test,
                    )
                self.proof.note(
                    self.function,
                    "selected_branch",
                    f"{ast.unparse(statement.test)}: {truth}",
                    statement.test,
                )
                previous = self.rejection_guard
                # This narrow rejection concerns captured key acceptance, not
                # arbitrary value constraints or errors in the other branch.
                self.rejection_guard = previous or bool(truth and _key_presence(condition))
                try:
                    self.statements(statement.body if truth else statement.orelse)
                finally:
                    self.rejection_guard = previous
            elif isinstance(statement, ast.Assert):
                condition = self.expression(statement.test)
                if self.truth(condition) is not True or _tracked(condition):
                    self.unknown('assertion_execution_unconfirmed', statement)
                # A proved true, unrelated test has the same continuation with
                # assertions enabled or disabled. Its message is never evaluated.
                self.proof.note(self.function, 'static_assertion_continuation',
                                'The assertion test is statically true; its message is skipped.',
                                statement.test)
            elif isinstance(statement, ast.Raise):
                call = statement.exc
                if (
                    not self.rejection_guard
                    or statement.cause is not None
                    or not isinstance(call, ast.Call)
                    or not isinstance(call.func, ast.Name)
                    or call.keywords
                    or not self.unshadowed_builtin_name(call.func.id)
                ):
                    self.unknown("unsupported_control_flow", statement)
                exception = getattr(builtins, call.func.id, None)
                edge = next(
                    (
                        edge
                        for edge in direct_calls(self.analysis, self.function.identity)
                        if (edge.lineno, edge.col_offset, edge.end_lineno, edge.end_col_offset)
                        == (call.lineno, call.col_offset, call.end_lineno, call.end_col_offset)
                    ),
                    None,
                )
                if (
                    not isinstance(exception, type)
                    or not issubclass(exception, Exception)
                    or edge is None
                    or edge.target is not None
                    or edge.target_status != "builtin_boundary"
                ):
                    self.unknown("exception_construction_unproven", statement)
                # Even an established rejection guard must not execute a custom
                # message formatter or turn an unrelated error into permission.
                arguments = [self.expression(item) for item in call.args]
                if any(
                    not isinstance(item, _Value) or item.literal is _UNKNOWN for item in arguments
                ):
                    self.unknown("exception_construction_unproven", statement)
                self.proof.reject(
                    self.function, "proven_guard_rejection", ast.unparse(statement), statement
                )
            elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                # A definition does not execute its body; captured calls are checked below.
                if statement.decorator_list or any(
                    self.related(item)
                    or isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and any(isinstance(child, ast.Call) for child in ast.walk(item))
                    for item in ast.iter_child_nodes(statement)
                    if not isinstance(item, ast.stmt)
                ):
                    self.unknown("definition_effects_unmodeled", statement)
                self.values[statement.name] = (
                    _LocalFunction(statement)
                    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
                    else _Value(tracked=self.related(statement))
                )
            elif isinstance(statement, ast.Pass):
                continue
            else:
                self.unknown("unsupported_control_flow", statement)

    def finite_unpack(self, target, value, depth=0):
        """Bind exact builtin tuple/list shapes without invoking an iterator protocol."""
        if depth > 8:
            self.unknown('unpacking_binding_unproven', target)
        if isinstance(target, ast.Name):
            return [(target.id, value)]
        if (not isinstance(target, (ast.Tuple, ast.List))
                or not isinstance(value, _Positionals)
                or value.kind not in ('tuple', 'list')
                or len(target.elts) != len(value.items) or len(target.elts) > 1000):
            self.unknown('unpacking_binding_unproven', target)
        result = []
        for child, item in zip(target.elts, value.items):
            result.extend(self.finite_unpack(child, item, depth + 1))
        if value.carrier and _tracked(value):
            self.proof.handled(self.function, 'consumed_presence',
                               'Exact unpacking requires the selected captured element.', target)
        return result

    @staticmethod
    def truth(value):
        if isinstance(value, (_Keywords, _Positionals, _KeySet)):
            return bool(value.items)
        if isinstance(value, _Value) and value.literal is not _UNKNOWN:
            return bool(value.literal)
        return None

    def expression(self, node):
        self.expression_depth += 1
        try:
            return self._expression(node)
        finally:
            self.expression_depth -= 1

    def _expression(self, node):
        if isinstance(node, ast.Constant):
            return _finite(node)
        if isinstance(node, ast.Name):
            value = self.values.get(node.id, _Value())
            if isinstance(value, _LocalFunction):
                self.unknown("deferred_callable_not_followed", node)
            if node.id in self.facts and isinstance(value, _Value):
                return _Value(self.facts[node.id], value.tracked,
                              type_selected=value.type_selected)
            return value
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                receiver = self.values.get(node.value.id)
                if isinstance(receiver, _SourceInstance):
                    if node.attr not in receiver.attributes:
                        self.unknown("callable_instance_state_unproven", node)
                    return receiver.attributes[node.attr]
            path = ast.unparse(node)
            if path in self.facts:
                return _Value(self.facts[path])
            if self.related(node):
                self.unknown("unsupported_attribute_use", node)
            return _Value()
        if isinstance(node, ast.IfExp):
            condition = self.expression(node.test)
            truth = self.truth(condition)
            if truth is None:
                self.unknown("unresolved_condition", node.test)
            self.proof.note(
                self.function,
                "selected_expression_branch",
                f"{ast.unparse(node.test)}: {truth}",
                node.test,
            )
            return self.expression(node.body if truth else node.orelse)
        if isinstance(node, (ast.Tuple, ast.List)):
            return _Positionals(
                tuple(self.positional_items(node.elts)),
                carrier=any(isinstance(child, ast.Starred) and self.related(child.value)
                            for child in node.elts),
                kind="tuple" if isinstance(node, ast.Tuple) else "list",
            )
        if isinstance(node, ast.Subscript):
            value = self.expression(node.value)
            if isinstance(value, _Positionals):
                return self.positional_projection(value, node)
        if isinstance(node, ast.JoinedStr):
            pieces = []
            tracked = False
            for item in node.values:
                if isinstance(item, ast.Constant) and type(item.value) is str:
                    pieces.append(item.value)
                    continue
                if not isinstance(item, ast.FormattedValue) or item.format_spec is not None:
                    self.unknown("unsupported_value_use", node)
                value = self.expression(item.value)
                if not isinstance(value, _Value) or value.literal is _UNKNOWN:
                    self.unknown("unsupported_value_use", node)
                if item.conversion not in (-1, 115, 114, 97):
                    self.unknown("unsupported_value_use", node)
                convert = {115: str, 114: repr, 97: ascii}.get(item.conversion, str)
                pieces.append(convert(value.literal))
                tracked = tracked or value.tracked
            return _Value("".join(pieces), tracked)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Sub):
            left, right = self.expression(node.left), self.expression(node.right)
            if isinstance(left, _KeySet) and isinstance(right, _KeySet):
                return _KeySet(
                    {key: tracked for key, tracked in left.items.items() if key not in right.items}
                )
            if _tracked(left) or _tracked(right):
                self.unknown("key_comparison_unproven", node)
            return _Value()
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = self.expression(node.left), self.expression(node.right)
            if (
                isinstance(left, _Positionals)
                and isinstance(right, _Positionals)
                and left.kind == right.kind
            ):
                return _Positionals(
                    left.items + right.items, left.carrier or right.carrier, left.kind
                )
        if isinstance(node, ast.Dict):
            items = {}
            carrier = False
            for key, value in zip(node.keys, node.values):
                if key is None:
                    mapping = self.expression(value)
                    if not isinstance(mapping, _Keywords):
                        self.unknown("dynamic_argument_expansion", node)
                    # Dictionary displays overwrite earlier keys; unlike call
                    # keyword expansions, duplicate keys do not raise here.
                    items.update(mapping.items)
                    carrier = carrier or mapping.carrier
                    continue
                if not isinstance(key, ast.Constant) or type(key.value) is not str:
                    self.unknown("dynamic_argument_expansion", node)
                items[key.value] = self.expression(value)
            return _Keywords(items, carrier)
        if isinstance(node, ast.Call):
            return self.call(node)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            value = self.expression(node.operand)
            truth = self.truth(value)
            return _Value(
                not truth if truth is not None else _UNKNOWN, _tracked(value), _key_presence(value)
            )
        if isinstance(node, ast.BoolOp):
            tracked = False
            key_presence = False
            for item in node.values:
                value = self.expression(item)
                tracked = tracked or _tracked(value)
                key_presence = key_presence or _key_presence(value)
                truth = self.truth(value)
                if truth is None:
                    joined = self.finite_identity_truth(node)
                    if joined is not None and len(joined) == 1:
                        # The final boolean is independent of every unknown
                        # operand; only builtin identity tests were inspected.
                        return _Value(next(iter(joined)))
                    return _Value(tracked=tracked)
                if truth == isinstance(node.op, ast.Or):
                    return _Value(truth, tracked)
            return _Value(truth, tracked, key_presence and isinstance(node.op, ast.And) and truth)
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            left, right = self.expression(node.left), self.expression(node.comparators[0])
            tracked = _tracked(left) or (not isinstance(right, _Keywords) and _tracked(right))
            lval = left.literal if isinstance(left, _Value) else _UNKNOWN
            rval = right.literal if isinstance(right, _Value) else _UNKNOWN
            operation = node.ops[0]
            if isinstance(operation, (ast.In, ast.NotIn)) and isinstance(right, _Positionals):
                primitives = (str, bytes, int, float, bool, type(None))
                if (type(lval) not in primitives or any(
                        not isinstance(item, _Value) or type(item.literal) not in primitives
                        for item in right.items)):
                    self.unknown('sequence_membership_unproven', node)
                present = lval in tuple(item.literal for item in right.items)
                return _Value(present if isinstance(operation, ast.In) else not present,
                              _tracked(left) or _tracked(right))
            if (isinstance(operation, (ast.Eq, ast.NotEq))
                    and isinstance(left, _Keywords) and isinstance(right, _Keywords)
                    and (not left.items or not right.items)):
                # Comparing to an empty builtin dict cannot invoke payload
                # equality. Both mappings retain finite, exact string keys.
                equal = not left.items and not right.items
                selected = _tracked(left) or _tracked(right)
                return _Value(equal if isinstance(operation, ast.Eq) else not equal,
                              selected, selected)
            if isinstance(operation, (ast.In, ast.NotIn)) and isinstance(right, _Keywords):
                if lval is not _UNKNOWN:
                    present = lval in right.items
                    tracked = tracked or _tracked(right.items.get(lval))
                    return _Value(
                        present if isinstance(operation, ast.In) else not present,
                        tracked,
                        _tracked(right.items.get(lval)),
                    )
            if lval is not _UNKNOWN and rval is not _UNKNOWN:
                if isinstance(operation, (ast.Is, ast.IsNot)) and (lval is None or rval is None):
                    result = lval is rval
                    return _Value(result if isinstance(operation, ast.Is) else not result, tracked)
                if isinstance(operation, (ast.Eq, ast.NotEq)):
                    result = lval == rval
                    return _Value(result if isinstance(operation, ast.Eq) else not result, tracked)
                numeric = type(lval) in (bool, int, float) and type(rval) in (bool, int, float)
                text = type(lval) is type(rval) and type(lval) in (str, bytes)
                comparison = {
                    ast.Lt: operator.lt, ast.LtE: operator.le,
                    ast.Gt: operator.gt, ast.GtE: operator.ge,
                }.get(type(operation))
                if comparison is not None and (numeric or text):
                    return _Value(comparison(lval, rval), tracked)
            return _Value(tracked=tracked)
        if self.related(node):
            self.unknown("unsupported_value_use", node)
        return _Value()

    def positional_items(self, nodes):
        positional = []
        for argument in nodes:
            if isinstance(argument, ast.Starred):
                value = self.expression(argument.value)
                if not isinstance(value, _Positionals):
                    self.unknown("dynamic_argument_expansion", argument)
                positional.extend(value.items)
            else:
                positional.append(self.expression(argument))
        return positional

    def positional_projection(self, value, node):
        def index(item):
            if item is None:
                return None
            if isinstance(item, ast.Constant) and type(item.value) is int:
                return item.value
            if (
                isinstance(item, ast.UnaryOp)
                and isinstance(item.op, (ast.USub, ast.UAdd))
                and isinstance(item.operand, ast.Constant)
                and type(item.operand.value) is int
            ):
                return -item.operand.value if isinstance(item.op, ast.USub) else item.operand.value
            self.unknown("positional_projection_unproven", node)

        try:
            if isinstance(node.slice, ast.Slice):
                selection = slice(
                    index(node.slice.lower), index(node.slice.upper), index(node.slice.step)
                )
                return _Positionals(value.items[selection], value.carrier, value.kind,
                                    value.source_state)
            return value.items[index(node.slice)]
        except (IndexError, TypeError, ValueError):
            self.unknown("positional_projection_unproven", node)

    def arguments(self, node):
        positional, keywords = self.positional_items(node.args), {}
        for keyword in node.keywords:
            value = self.expression(keyword.value)
            items = (
                {keyword.arg: value}
                if keyword.arg is not None
                else (value.items if isinstance(value, _Keywords) else None)
            )
            if items is None:
                self.unknown("dynamic_argument_expansion", keyword.value)
            for name, item in items.items():
                if name in keywords:
                    if _tracked(item) or _tracked(keywords[name]):
                        self.proof.reject(self.function, "duplicate_argument_binding", name, node)
                    self.unknown("call_binding_unproven", node)
                keywords[name] = item
        return positional, keywords

    def call(self, node):
        self.pending_values.append([])
        try:
            return self._call(node)
        finally:
            self.pending_values.pop()

    def _call(self, node):
        if self.analysis is None:
            # Client expressions are opaque: no user code, including nested
            # argument calls, is executed or attributed to the library source.
            return _Value()
        facts = next(
            (
                call
                for call in direct_calls(self.analysis, self.function.identity)
                if (call.lineno, call.col_offset, call.end_lineno, call.end_col_offset)
                == (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)
            ),
            None,
        )
        if isinstance(node.func, ast.Attribute):
            receiver = self.expression(node.func.value)
            if isinstance(receiver, _Positionals):
                self.unknown('sequence_effect_unproven', node)
            if (
                isinstance(receiver, _Value)
                and type(receiver.literal) is str
                and node.func.attr in ("startswith", "endswith")
            ):
                positional, keywords = self.arguments(node)
                tracked = _tracked(receiver) or any(
                    _tracked(item) for item in positional + list(keywords.values())
                )
                if (
                    len(positional) == 1
                    and not keywords
                    and isinstance(positional[0], _Value)
                    and type(positional[0].literal) is str
                ):
                    return _Value(
                        getattr(str, node.func.attr)(receiver.literal, positional[0].literal),
                        tracked,
                    )
                return _Value(tracked=tracked)
            if isinstance(receiver, _Keywords):
                if node.func.attr == 'clear':
                    if (not facts or receiver.source_state
                            or not mapping_protocol(self.function, self.analysis, facts, 'clear')):
                        self.unknown('mapping_effect_unproven', node)
                    receiver.items.clear()
                    return _Value(None)
                if node.func.attr == 'get':
                    positional, keywords = self.arguments(node)
                    key = (positional[0].literal
                           if positional and isinstance(positional[0], _Value) else _UNKNOWN)
                    if (not facts or len(positional) not in (1, 2) or keywords
                            or type(key) is not str or not mapping_protocol(
                                self.function, self.analysis, facts, 'get', key)):
                        self.unknown('mapping_effect_unproven', node)
                    return receiver.items.get(key, positional[1] if len(positional) == 2
                                              else _Value(None))
                if node.func.attr == "copy" and facts:
                    if (
                        facts.target_status == "local_container_protocol"
                        and not node.args
                        and not node.keywords
                        and any(
                            effect.get("operation") == "copy"
                            and effect.get("status") == "bounded"
                            and effect.get("identity") == "shallow_copy"
                            and effect.get("completion") == "normal_return"
                            for effect in facts.effects
                        )
                    ):
                        return _Keywords(dict(receiver.items), receiver.carrier)
                    self.unknown("mapping_effect_unproven", node)
                if (
                    node.func.attr == "pop"
                    and facts
                    and facts.target_status == "local_container_protocol"
                ):
                    positional, keywords = self.arguments(node)
                    key = (
                        positional[0].literal
                        if positional and isinstance(positional[0], _Value)
                        else _UNKNOWN
                    )
                    if (
                        len(positional) not in (1, 2)
                        or keywords
                        or type(key) is not str
                        or not any(
                            effect.get("status") == "bounded"
                            and effect.get("operation") == "pop"
                            and effect.get("state_after") in {"absent", "conditional"}
                            and effect.get("element_path") == [key]
                            for effect in facts.effects
                        )
                    ):
                        self.unknown("mapping_effect_unproven", node)
                    if key not in receiver.items and len(positional) == 1:
                        self.unknown("call_binding_unproven", node)
                    result = receiver.items.pop(
                        key, positional[1] if len(positional) == 2 else _Value()
                    )
                    if _tracked(result):
                        self.proof.note(self.function, "removed_key", key, node)
                        if len(positional) == 1:
                            self.proof.handled(
                                self.function,
                                "consumed_presence",
                                "Required pop uses key presence.",
                                node,
                            )
                    return result
                if receiver.carrier:
                    self.unknown("mapping_effect_unproven", node)
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "isinstance"
            and node.func.id not in self.values
            and len(node.args) == 2
            and not node.keywords
            and facts
            and facts.target is None
            and facts.target_status == "builtin_boundary"
            and self.unshadowed_builtin_name("isinstance")
        ):
            return self.instance_guard(node)
        if self.related(node.func):
            self.unknown("call_target_unproven", node)
        positional, keywords = self.arguments(node)
        self.pending_values[-1] = positional + list(keywords.values())
        callability = exact_callability_protocol(self.analysis, facts) if facts else None
        if callability is not None and len(positional) == 1 and not keywords:
            value = positional[0]
            if (isinstance(value, (_Keywords, _Positionals, _KeySet))
                    or isinstance(value, _Value)
                    and type(value.literal) in (type(None), bool, int, float, str, bytes)):
                self.proof.note(self.function, 'builtin_exact_callability',
                                'This exact builtin input type has no call protocol.', node)
                # Exact carrier type is independent of its selected payload
                # or element presence. Only a selected object itself is read.
                return _Value(False, isinstance(value, _Value) and value.type_selected,
                              consumed=True)
            self.unknown('callability_input_unproven', node)
        length_protocol = container_length_protocol(self.analysis, facts) if facts else None
        if length_protocol is not None and len(positional) == 1 and not keywords:
            value = positional[0]
            if isinstance(value, (_Keywords, _Positionals, _KeySet)):
                length = len(value.items)
            elif isinstance(value, _Value) and type(value.literal) in (str, bytes):
                length = len(value.literal)
            else:
                self.unknown('length_input_unproven', node)
            self.proof.note(self.function, 'builtin_container_length',
                            'Exact builtin input discharges the source length obligation.', node)
            return _Value(length, _tracked(value),
                          isinstance(value, (_Keywords, _KeySet)) and _tracked(value),
                          consumed=True)
        truth_protocol = scalar_truth_protocol(self.analysis, facts) if facts else None
        if truth_protocol is not None and len(positional) == 1 and not keywords:
            value = positional[0]
            if (isinstance(value, _Value)
                    and type(value.literal) in (type(None), bool, int, float, str, bytes)):
                truth = self.truth(value)
                self.proof.note(self.function, 'builtin_scalar_truth',
                                f'Exact scalar conversion: {truth}.', node)
                return _Value(truth, _tracked(value), _key_presence(value), consumed=True)
        if facts and len(facts.result_sources) == 1:
            protocol = copy_protocol_target(
                self.function, self.analysis, facts, facts.result_sources[0]
            )
            if protocol is not None and isinstance(node.func, ast.Name):
                value = positional[0]
                copied = None
                if protocol.qualname == "dict" and isinstance(value, _Keywords):
                    copied = _Keywords(dict(value.items), value.carrier, value.source_state)
                elif protocol.qualname in ("tuple", "list") and isinstance(value, _Positionals):
                    copied = _Positionals(
                        value.items, value.carrier, protocol.qualname, value.source_state
                    )
                if copied is not None:
                    # Copy current modeled contents, retaining selected values and element order.
                    self.proof.note(
                        self.function, "builtin_container_copy", ast.unparse(node), node, protocol
                    )
                    return copied
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in ("set", "list")
            and facts
            and facts.target is None
            and facts.target_status == "python_protocol"
            and self.unshadowed_builtin_name(node.func.id)
            and len(positional) == 1
            and not keywords
        ):
            value = positional[0]
            if node.func.id == "set" and isinstance(value, _Keywords):
                return _KeySet({key: _tracked(item) for key, item in value.items.items()})
            if node.func.id == "set" and isinstance(value, _KeySet):
                return _KeySet(dict(value.items))
            if node.func.id == "list" and isinstance(value, _KeySet):
                if len(value.items) > 1:
                    self.unknown("key_iteration_order_unproven", node)
                return _Positionals(
                    tuple(_Value(key, tracked) for key, tracked in value.items.items()), kind="list"
                )
            self.unknown("key_comparison_unproven", node)
        arguments = [({"position": position}, item) for position, item in enumerate(positional)]
        arguments.extend(({"keyword": name}, item) for name, item in keywords.items())
        ordinary = [
            (argument, item)
            for argument, item in arguments
            if isinstance(item, (_Keywords, _Positionals, _KeySet)) and _tracked(item)
        ]
        local = self.values.get(node.func.id) if isinstance(node.func, ast.Name) else None
        captured = (
            isinstance(local, _LocalFunction)
            or facts
            and any(
                source.get("source") is not None
                and source.get("source")
                in {self.function.signature.kwarg, self.function.signature.vararg}
                for binding in facts.capture_bindings
                for source in binding.get("sources", ())
            )
        )
        if (
            not ordinary
            and not any(_tracked(item) for item in positional + list(keywords.values()))
            and not captured
        ):
            if any(_protected_state(item) for item in positional + list(keywords.values())):
                self.unknown("callable_instance_state_effects_unproven", node)
            return _Value()
        confirmed = self.proof.known_targets.get(call_span(facts)) if facts else None
        if facts and facts.target is None and confirmed is not None:
            target = self.proof.context.index.find(confirmed)
            if target is None or target.is_overload or target.node.decorator_list:
                self.unknown('conflicting_target_fact', node)
            self.proof.note(self.function, 'confirmed_call_target',
                            'Caller supplied this unresolved call target for signature rejection '
                            'only; body binding and effects remain unproved.',
                            node, target.identity)
            self.proof.bind(target, positional, keywords, target.is_bound_method, node,
                            caller=self.function)
            self.unknown('confirmed_target_body_unproven', node)
        if not facts or not facts.target or captured and not isinstance(local, _LocalFunction):
            self.unknown("call_target_unproven", node)
        status = _target_status(self.analysis, facts)
        confirmed = self.proof.known_targets.get(call_span(facts))
        if confirmed is not None:
            confirmed_definition = self.proof.context.index.find(confirmed)
            if (
                confirmed_definition is None
                or confirmed_definition.identity != identity_from_target(facts.target)
            ):
                self.unknown("conflicting_target_fact", node)
            self.proof.note(
                self.function,
                "confirmed_call_target",
                "Caller supplied this call's source implementation.",
                node,
                confirmed,
            )
        reasons = {
            boundary.get("reason")
            for boundary in self.analysis.boundaries
            if boundary.get("call_id") == facts.id
        }
        dynamic = {reason for reason in reasons if reason and reason.startswith("dynamic_")}
        dynamic.discard("dynamic_argument_expansion")
        instance = None
        instance_binding = getattr(facts, "callable_instance_evidence", {}).get("binding", {})
        if status == "callable_instance_candidate":
            instance = self.source_callable_binding(facts, instance_binding)
            if instance is not None:
                dynamic.discard("dynamic_callable_instance_override_possible")
                self.proof.note(
                    self.function,
                    "source_callable_instance_binding",
                    "; ".join(instance_binding["assumptions"]),
                    node,
                    identity_from_target(facts.target),
                )
        source_binding = source_classmethod_binding(self.analysis, facts)
        if source_binding is not None:
            # Source-snapshot binding is conditional evidence, not a runtime observation.
            dynamic.discard("dynamic_class_receiver_override_possible")
            self.proof.note(
                self.function,
                "source_classmethod_binding",
                "; ".join(source_binding.get("assumptions", ())),
                node,
                identity_from_target(facts.target),
            )
        constructor = source_constructor_binding(self.analysis, facts)
        if (constructor is not None and constructor['phase'] == '__init__'
                and constructor['body_execution'] == 'synchronous'):
            dynamic.discard('dynamic_construction')
            self.proof.note(
                self.function, 'source_initializer_binding',
                'PCResolve confirms this initializer invocation only; returned instance '
                'state remains unmodeled. ' + '; '.join(constructor['assumptions']),
                node, identity_from_target(facts.target),
            )
        if confirmed is not None:
            # A method observation resolves this target only, not decorator
            # effects, metaclass construction, binding or later body behavior.
            dynamic.discard("dynamic_class_receiver_override_possible")
        if (
            status not in {"resolved", "constructor", "staticmethod", "classmethod"}
            and instance is None
        ) or dynamic:
            reason = sorted(dynamic)[0] if dynamic else "call_target_unproven"
            self.unknown(reason, node)
        if status == "classmethod" and confirmed is None and not source_binding:
            self.unknown("class_receiver_unconfirmed", node)
        if any(
            boundary.get("call_id") == facts.id
            and boundary.get("reason")
            in {
                "identity_decorator_effects_unmodeled",
                "dynamic_dispatch",
                "dynamic_callable_binding",
            }
            for boundary in self.analysis.boundaries
        ):
            self.unknown("callee_effects_unmodeled", node)
        target = self.proof.context.index.find(identity_from_target(facts.target))
        if target is None:
            self.unknown("call_target_unavailable", node)
        captures = self.capture_values(target, facts, local, node) if captured else {}
        if ordinary and (
            facts.binding_status != "complete"
            or facts.binding_issues
            or any(
                not any(
                    binding.get("argument") == argument
                    and binding.get("status") == "exact"
                    and binding.get("destination_kind") == "parameter"
                    for binding in facts.parameter_bindings
                )
                for argument, _ in ordinary
            )
        ):
            self.unknown("ordinary_container_binding_unproven", node)
        values = self.proof.bind(
            target, positional, keywords, target.is_bound_method, node, caller=self.function
        )
        values.update(captures)
        if instance is not None:
            values[instance_binding["implicit_binding"]["parameter"]] = instance
        captured_keywords = values.get(target.signature.kwarg)
        captured_positionals = values.get(target.signature.vararg)
        if captured or ordinary or _tracked(captured_keywords) or _tracked(captured_positionals):
            self.proof.note(
                self.function,
                "immediate_capture_forwarding"
                if captured
                else "ordinary_container_forwarding"
                if ordinary
                else (
                    "forwarded_positional"
                    if _tracked(captured_positionals)
                    else "forwarded_keyword"
                ),
                ast.unparse(node),
                node,
                target.identity,
            )
            try:
                expanded = self.proof.context.adapter.expand(self.analysis, facts.id)
            except ResolutionError as exc:
                self.proof.unknown(self.function, "flow_expansion_failed", str(exc), node)
            result = self.proof.run(target, values, analysis=expanded, ancestry=self.ancestry)
            if captured:
                return result
        else:
            self.proof.handled(
                self.function,
                "accepted_binding",
                "Changed value binds an explicit parameter.",
                node,
                target.identity,
            )
        return _Value()

    def capture_values(self, target, call, local, node):
        """Bind only exact call-time containers of this local source definition."""

        owner = self.function.identity
        if (
            not isinstance(local, _LocalFunction)
            or target.identity.module != owner.module
            or target.identity.file_path != owner.file_path
            or target.identity.qualname != owner.qualname + "." + local.node.name
            or target.node is not local.node
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
                or not conditions_possible(self.proof.context, binding)
                or root.get("kind") not in {"container", "call_result"}
                or not container.get("source")
                or container["source"] != binding.get("source")
                or container.get("container_shape") != shape
                or root.get("relation") != "direct"
                or not conditions_possible(self.proof.context, root)
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
                    or not conditions_possible(self.proof.context, item)
                    for item in contents
                )
            ):
                self.unknown("capture_binding_unproven", node)
            # Share the current object, not a copy: modeled pops must reach parent aliases too.
            values[name] = value
        return values

    def source_callable_binding(self, call, binding):
        if not binding or call.binding_status != "complete" or call.binding_issues:
            return None
        target = identity_from_target(call.target)
        definition = self.proof.context.index.find(target)
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

    def instance_guard(self, node):
        value = self.expression(node.args[0])
        if not isinstance(value, _Value) or value.literal is _UNKNOWN:
            return _Value(tracked=_tracked(value))
        expression = ast.unparse(node.args[1])
        if (
            isinstance(node.args[1], ast.Name)
            and expression in ("str", "bytes", "int", "float", "bool", "object")
            and self.unshadowed_builtin_name(expression)
        ):
            return _Value(isinstance(value.literal, getattr(builtins, expression)), value.tracked)
        classes = self.proof.context.index
        identity = classes._definitions().resolve_name(
            self.function.identity.module,
            self.function.identity.qualname,
            expression,
            classes.imports,
            kind="class",
        )
        if identity and identity.file_path:
            # A primitive cannot be an instance of a plain source class. Custom
            # metaclasses/inherited instance checks deliberately remain unknown.
            try:
                with tokenize.open(identity.file_path) as stream:
                    tree = ast.parse(stream.read())
            except (OSError, SyntaxError, UnicodeError):
                return _Value()
            matching = [
                item
                for item in ast.walk(tree)
                if isinstance(item, ast.ClassDef) and item.lineno == identity.lineno
            ]
            if (
                len(matching) == 1
                and not matching[0].keywords
                and not matching[0].decorator_list
                and all(
                    isinstance(base, ast.Name) and base.id == "object" for base in matching[0].bases
                )
                and not any(
                    isinstance(item, ast.Name)
                    and item.id == "object"
                    and isinstance(item.ctx, ast.Store)
                    or isinstance(item, (ast.FunctionDef, ast.ClassDef))
                    and item.name == "object"
                    for item in ast.walk(tree)
                )
                and "object" not in classes.imports.get(identity.module, {})
            ):
                return _Value(False, value.tracked)
        return _Value(tracked=value.tracked)


def _parse_call(call: CallContext) -> Optional[ast.Call]:
    if isinstance(call.expression, ast.Call):
        return call.expression
    try:
        node = ast.parse(call.expression, mode="eval").body
    except (SyntaxError, TypeError):
        return None
    if isinstance(node, ast.Await):
        node = node.value
    return node if isinstance(node, ast.Call) else None


def assess_change(
    source: ScanSource,
    target_api: FunctionIdentity,
    change: ParameterChange,
    call: Union[str, ast.Call, CallContext],
    *,
    import_roots: Optional[Sequence[PathLike]] = None,
    max_depth: int = 5,
    context: Optional[AnalysisContext] = None,
) -> ParameterAssessment:
    """Assess one changed captured argument under finite original-call conditions.

    Results may be conditional on recorded normal-path preconditions for
    unrelated, error-only guards; those records do not infer a receiver value.
    HANDLED/IGNORED are handling facts, not old/new behavior equivalence.
    REJECTED supplies parameter-specific evidence, not a patch or proof that a
    proposed patch works. UNKNOWN never means that the parameter is compatible.
    Positional selection uses old_position in the expanded client argument list,
    excluding an implicit receiver. Exception recovery remains unmodeled.
    """

    _validate_depth(max_depth)
    call = call if isinstance(call, CallContext) else CallContext(call)
    node = _parse_call(call)
    text = ast.unparse(node) if node else str(call.expression)
    _, context = _prepare_context(source, import_roots, context)
    entry = None
    proof = _Proof(context, max_depth, dict(call.known_targets), dict(call.known_conditions))
    state, reason = ParameterState.UNKNOWN, "target_api_unavailable"
    try:
        if context is None:
            raise ResolutionError("No Python sources available.")
        entry = context.resolve_api(target_api)
        if entry is None or entry.is_overload:
            raise ResolutionError("The API does not resolve to one source implementation.")
        if node is None:
            proof.unknown(
                entry, "callsite_not_resolved", "Supply an original call AST or expression."
            )
        # The client expression is not in the library AST. Only finite argument
        # syntax is read; calls/attributes in its argument values are never run.
        frame = _Frame(proof, entry, None, {}, (), {})
        positional, keywords = frame.arguments(node)
        caller = caller_arguments(context.adapter, call, node, target_api, entry)
        if caller is not None:
            source_values, assumptions = caller
            applied = []
            selected = (('keyword', change.old_name) if change.old_name in keywords
                        else ('position', change.old_position))
            for slot, value in source_values.items():
                # A selected container needs element/identity tracking beyond
                # the scalar selection contract. Do not pretend it is a scalar.
                if slot == selected and value['kind'] != 'literal':
                    continue
                items = positional if slot[0] == 'position' else keywords
                previous = items[slot[1]]
                restored = _source_state(value)
                if isinstance(restored, _Value):
                    # Immutable primitive arguments carry no mutable alias
                    # state for an unrelated call to invalidate.
                    restored = _Value(restored.literal)
                if (isinstance(previous, _Value) and previous.literal is not _UNKNOWN
                        and (not isinstance(restored, _Value)
                             or type(previous.literal) is not type(restored.literal)
                             or previous.literal != restored.literal)):
                    proof.unknown(entry, 'conflicting_call_facts',
                                  'Caller source and supplied argument syntax disagree.')
                items[slot[1]] = restored
                applied.append(str(slot))
            if applied:
                proof.evidence.append(ParameterEvidence(
                    entry.identity, 'source_caller_arguments',
                    'PCResolve recovered finite literals for slots ' + ', '.join(applied)
                    + ' from the exact original source call, conditional on: '
                    + '; '.join(assumptions), call.callsite))
        elif call.callsite is not None:
            proof.note(entry, 'source_caller_arguments_unconfirmed',
                       'Caller source facts are unavailable or do not match this exact call.')
        bound = entry.is_bound_method if call.bound_receiver is None else call.bound_receiver
        if change.old_name in keywords:
            original = keywords[change.old_name]
            capture = entry.signature.kwarg
            if not capture or change.old_name in (
                *entry.signature.positional_or_keyword,
                *entry.signature.keyword_only,
            ):
                proof.unknown(
                    entry,
                    "not_variadic_capture",
                    "The changed keyword is not captured by **kwargs.",
                )
            destination = f"{capture}[{change.old_name!r}]"
        elif change.old_position is not None:
            position = change.old_position
            if position >= len(positional):
                proof.unknown(
                    entry, "changed_argument_not_passed", "The selected position is absent."
                )
            original = positional[position]
            signature = _signature(entry, bound)
            fixed = sum(
                parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)
                for parameter in signature.parameters.values()
            )
            capture = entry.signature.vararg
            if not capture or position < fixed:
                proof.unknown(
                    entry, "not_variadic_capture", "The changed element is not captured by *args."
                )
            destination = f"{capture}[{position - fixed}] (client position {position})"
        else:
            proof.unknown(
                entry, "changed_argument_not_passed", "The selected keyword is not supplied."
            )
        if not isinstance(original, _Value):
            proof.unknown(
                entry,
                "changed_value_unsupported",
                "Only primitive/unknown scalar arguments are modeled.",
            )
        if change.old_name in keywords:
            keywords[change.old_name] = _Value(original.literal, tracked=True, type_selected=True)
        else:
            positional[change.old_position] = _Value(original.literal, tracked=True,
                                                     type_selected=True)
        values = proof.bind(
            entry,
            positional,
            keywords,
            bound,
            change=change,
        )
        receiver = (entry.node.args.posonlyargs + entry.node.args.args)[:1]
        receiver_name = receiver[0].arg if receiver and entry.is_bound_method else None
        for name, value in call.known_values:
            if name in values and isinstance(values[name], _Value):
                known = values[name].literal
                if known is not _UNKNOWN and (type(known) is not type(value) or known != value):
                    proof.unknown(entry, "conflicting_call_facts", f"Conflicting fact for {name}.")
            elif not (receiver_name and name.startswith(receiver_name + ".")):
                proof.unknown(entry, "unsupported_call_fact", f"No supported binding for {name}.")
        proof.note(entry, "entry_binding", f"{change.old_name} captured by {destination}.")
        if call.observed_fixed_bindings:
            target = observed_fixed_binding(context, entry, call, change, original.literal)
            if target is None:
                proof.unknown(entry, 'observed_fixed_binding_unconfirmed',
                              'Original-element provenance, actual fixed binding, normal '
                              'completion or source call/signature evidence is unconfirmed.')
            observed = call.observed_fixed_bindings[0]
            proof.note(context.index.find(observed.caller), 'runtime_fixed_parameter_binding',
                       'Caller independently traced the original captured primitive through '
                       'this exact builtin mapping expansion into the actual bound method\'s '
                       'fixed formal, and confirmed normal completion of the original call. '
                       'PCResolve supplies the source call and target parameters.',
                       node=observed.call_span, target=target.identity)
            raise _Stop(ParameterState.HANDLED, 'observed_fixed_parameter_binding')
        if call.observed_capture_rejections:
            guard = observed_capture_rejection(context, entry, call, change, original.literal)
            if guard is None:
                proof.unknown(entry, 'observed_capture_rejection_unconfirmed',
                              'Original-key provenance, dictionary type, reached source guard '
                              'or escaping exception is missing or conflicting.')
            observed = call.observed_capture_rejections[0]
            proof.note(context.index.find(observed.checker), 'runtime_capture_rejection',
                       'Caller traced this original captured primitive into an exact builtin '
                       'dictionary and confirmed the source nonempty-dictionary rejection '
                       'guard completed and its exception escaped the original call.',
                       node=observed.raise_span, target=observed.checker)
            proof.reject(entry, 'observed_capture_guard_rejection',
                         change.old_name + ' reaches the observed dictionary rejection guard.',
                         target=observed.checker)
        if call.observed_attribute_retentions:
            transfer = observed_attribute_retention(context, entry, call, change, original.literal)
            if transfer is None:
                proof.unknown(entry, 'observed_attribute_retention_unconfirmed',
                              'Construction, original capture retention, normal completion or '
                              'source-store evidence is missing or conflicting.')
            observed = call.observed_attribute_retentions[0]
            proof.note(entry, 'runtime_instance_attribute_retention',
                       'Caller independently confirmed ordinary class construction and the '
                       'returned original receiver retaining this same builtin capture dict '
                       'and selected primitive after the source store and normal completion.',
                       node=observed.store_span)
            raise _Stop(ParameterState.HANDLED, 'observed_instance_attribute_retention')
        if call.observed_container_predicates:
            predicate = observed_container_predicate(context, entry, call, change)
            if predicate is None:
                proof.unknown(entry, 'observed_container_predicate_unconfirmed',
                              'Container type, original-element provenance, execution or source '
                              'evidence is missing or conflicting.')
            observed = call.observed_container_predicates[0]
            proof.note(context.index.find(observed.checker), 'runtime_container_predicate',
                       'Caller traced the original selected element/presence into this exact '
                       'builtin container, observed this source predicate completing, and '
                       'confirmed normal completion of the original entry body. '
                       'The predicate consumes container presence, not a compatibility verdict.',
                       node=observed.predicate_span)
            raise _Stop(ParameterState.HANDLED, 'observed_container_predicate_consumption')
        if call.observed_normal_returns:
            transfer = observed_mapping_return(context, entry, call, change, original.literal)
            if transfer is None:
                proof.unknown(entry, 'observed_normal_return_unconfirmed',
                              'The normal-return observation and source retention fact disagree.')
            proof.note(entry, 'runtime_normal_return',
                       'Caller observed normal completion of this original call with the same '
                       'captured primitive. PCResolve proves that the selected key survives '
                       'the update in the returned fresh mapping. Assumes standard builtin dict '
                       'and no external frame introspection.',
                       node=call.observed_normal_returns[0].return_span)
            raise _Stop(ParameterState.HANDLED, 'observed_mapping_return_consumption')
        if call.observed_keyword_checks:
            observation = observed_keyword_check(context, entry, call, change, original.literal)
            if observation is None:
                proof.unknown(entry, 'observed_keyword_check_unconfirmed',
                              'The checkpoint does not match this call and source guard.')
            proof.note(context.index.find(observation.checker), 'runtime_keyword_checkpoint',
                       'Caller supplied an uncaught original-call trace: the entry and validator '
                       'received the selected value, and attribute lookup returned None. '
                       'This is runtime evidence, not static path or lookup confirmation.',
                       node=observation.raise_span, target=observation.checker)
            proof.reject(entry, 'observed_keyword_validation_rejection',
                         change.old_name + ' reaches the observed source rejection guard.',
                         target=observation.checker)
        proof.run(entry, values, facts=call.known_values)
        state = ParameterState.HANDLED if proof.handled_reason else ParameterState.IGNORED
        reason = proof.handled_reason or "unused_parameter"
        if state is ParameterState.IGNORED:
            proof.note(
                entry, reason, "Supported executed paths do not use the value or argument presence."
            )
    except _Stop as outcome:
        state, reason = outcome.state, outcome.reason
    except ResolutionError as exc:
        proof.boundaries.append(AnalysisBoundary(reason, str(exc), target_api))
    return ParameterAssessment(
        target_api,
        change,
        text,
        state,
        reason,
        tuple(proof.evidence),
        tuple(proof.boundaries),
        entry.identity if entry else None,
        call.callsite,
    )
