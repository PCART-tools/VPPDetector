"""Source identities, structural findings and parameter-level evidence."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional, Tuple, Union


class StringEnum(str, Enum):
    """Enum whose values remain convenient at CLI and report boundaries."""

    def __str__(self) -> str:
        return self.value


class VariadicKind(StringEnum):
    POSITIONAL = "var_positional"
    KEYWORD = "var_keyword"


class ChangeKind(StringEnum):
    DELETE = "delete"
    RENAME = "rename"


class ParameterState(StringEnum):
    """Disposition of one changed argument, not a repair or compatibility verdict."""

    HANDLED = "handled"
    REJECTED = "rejected"
    IGNORED = "ignored"
    UNKNOWN = "unknown"
    NOT_ENTERED = "not_entered"


class ScanCoverageStatus(StringEnum):
    """Observed analysis limits, never a proof of complete coverage."""

    NO_KNOWN_BOUNDARY = "no_known_boundary"
    LIMITED = "limited"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class ParameterChange:
    """One parameter deletion or rename supplied by the caller."""

    kind: ChangeKind
    old_name: str
    new_name: Optional[str] = None
    old_position: Optional[int] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", ChangeKind(self.kind))
        if not self.old_name.isidentifier():
            raise ValueError("old_name must be a parameter name")
        if self.kind is ChangeKind.RENAME and (
            not self.new_name or not self.new_name.isidentifier()
        ):
            raise ValueError("A rename requires new_name")
        if self.old_position is not None and (
            type(self.old_position) is not int or self.old_position < 0
        ):
            raise ValueError("old_position must be a nonnegative integer")


@dataclass(frozen=True)
class SourceContext:
    """Source files and module roots available to the analysis."""

    package_root: Path
    import_roots: Tuple[Path, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class FunctionIdentity:
    """Source-level identity of one function or method."""

    module: str
    qualname: str
    file_path: Optional[Path] = None
    lineno: Optional[int] = None


@dataclass(frozen=True)
class SourceSpan:
    file_path: Path
    lineno: int
    col_offset: int
    end_lineno: int
    end_col_offset: int


@dataclass(frozen=True)
class ObservedKeywordCheck:
    """Trusted, call-specific runtime checkpoint; never a static lookup proof.

    The observation must come from an uncaught exception trace of the original
    call. The entry and checker mappings contained this same primitive value,
    and the checker lookup produced lookup_value at raise_span.
    """

    entry: FunctionIdentity
    call_text: str
    keyword: str
    value: object
    checker: FunctionIdentity
    raise_span: SourceSpan
    mapping_parameter: str
    key_variable: str
    lookup_variable: str
    attribute_name: str
    lookup_value: object
    exception: str
    uncaught: bool
    source_hashes: Tuple[Tuple[Path, str], ...]


@dataclass(frozen=True)
class ObservedAttributeRetention:
    """Trusted completed class construction retaining the original keyword capture.

    The original invocation used type.__call__, object.__new__ and ordinary
    object attribute access/store. Its original constructor receiver is the
    returned instance, whose plain state retains the same builtin capture dict
    and selected primitive after this source assignment and normal completion.
    """

    entry: FunctionIdentity
    call_text: str
    keyword: str
    value: object
    attribute: str
    store_span: SourceSpan
    retained_builtin_dict: bool
    construction_confirmed: bool
    store_completed: bool
    completed_normally: bool
    source_hashes: Tuple[Tuple[Path, str], ...]


@dataclass(frozen=True)
class ObservedContainerPredicate:
    """Trusted execution of a source predicate on the selected argument's carrier.

    The caller independently establishes that this original call entered entry,
    the original element/presence reached selection in the checker's exact builtin
    container, this predicate completed, and the entry body completed normally.
    No runtime object graphs or argument values are accepted in this record.
    """

    entry: FunctionIdentity
    call_text: str
    parameter_name: str
    old_position: Optional[int]
    checker: FunctionIdentity
    predicate_span: SourceSpan
    container_parameter: str
    container_kind: str
    selection: Union[str, int]
    container_size: int
    key_variable: Optional[str]
    predicate_value: bool
    origin_confirmed: bool
    predicate_completed: bool
    completed_normally: bool
    source_hashes: Tuple[Tuple[Path, str], ...]


@dataclass(frozen=True)
class ObservedNormalReturn:
    """Trusted original-call completion with the same captured primitive value.

    The actual source frame received keyword/value and returned an exact builtin
    dict normally at return_span. This attestation alone proves no consumption;
    a matching PCResolve retention fact is additionally required.
    """

    entry: FunctionIdentity
    call_text: str
    keyword: str
    value: object
    return_span: SourceSpan
    returned_builtin_dict: bool
    source_hashes: Tuple[Tuple[Path, str], ...]


@dataclass(frozen=True)
class CallContext:
    """Original call and optional trusted, finite facts for that call only.

    known_values supplies primitive constants under source parameter names or
    receiver attribute paths, e.g. (("self.closed", False),). These are caller
    evidence, not expressions to execute. None is distinct from an unknown value.
    bound_receiver overrides the indexed method convention for unbound calls.
    known_targets confirms implementations at exact library call locations;
    copying a nominal PCResolve candidate is not an independent confirmation.
    known_conditions supplies independently established predicate outcomes at
    exact source spans. observed_keyword_checks supplies an explicit original
    call trace checkpoint; these runtime facts never enter scan/producer caches.
    observed_normal_returns confirms original-call completion for a matching
    conditional source retention proof; completion alone never implies handling.
    """

    expression: Union[str, ast.Call]
    bound_receiver: Optional[bool] = None
    known_values: Tuple[Tuple[str, object], ...] = ()
    callsite: Optional[SourceSpan] = None
    known_targets: Tuple[Tuple[SourceSpan, FunctionIdentity], ...] = ()
    known_conditions: Tuple[Tuple[SourceSpan, bool], ...] = ()
    observed_keyword_checks: Tuple[ObservedKeywordCheck, ...] = ()
    observed_normal_returns: Tuple[ObservedNormalReturn, ...] = ()
    observed_container_predicates: Tuple[ObservedContainerPredicate, ...] = ()
    observed_attribute_retentions: Tuple[ObservedAttributeRetention, ...] = ()

    def __post_init__(self) -> None:
        if self.bound_receiver is not None and type(self.bound_receiver) is not bool:
            raise ValueError("bound_receiver must be bool or None")
        names = [name for name, _ in self.known_values]
        if len(set(names)) != len(names) or any(
            not all(part.isidentifier() for part in name.split(".")) for name in names
        ):
            raise ValueError("known_values requires unique parameter or attribute paths")
        if any(
            type(value) not in (str, bytes, int, float, bool, type(None))
            for _, value in self.known_values
        ):
            raise ValueError("known_values accepts only primitive constants")
        spans = [span for span, _ in self.known_targets]
        if len(set(spans)) != len(spans):
            raise ValueError("known_targets requires unique library call locations")
        conditions = [span for span, _ in self.known_conditions]
        if (any(not isinstance(span, SourceSpan) or type(value) is not bool
                for span, value in self.known_conditions)
                or len(set(conditions)) != len(conditions)):
            raise ValueError('known_conditions requires unique source spans and bool outcomes')
        if (len(self.observed_keyword_checks) > 8
                or any(not isinstance(value, ObservedKeywordCheck)
                       for value in self.observed_keyword_checks)):
            raise ValueError('observed_keyword_checks requires bounded observation records')
        if (len(self.observed_normal_returns) > 8
                or any(not isinstance(value, ObservedNormalReturn)
                       for value in self.observed_normal_returns)):
            raise ValueError('observed_normal_returns requires bounded observation records')
        if self.observed_normal_returns and self.observed_keyword_checks:
            raise ValueError('Normal-return and uncaught-rejection observations conflict')
        if (len(self.observed_container_predicates) > 8 or any(
                not isinstance(value, ObservedContainerPredicate)
                for value in self.observed_container_predicates)):
            raise ValueError('observed_container_predicates requires bounded observation records')
        if self.observed_container_predicates and (
                self.observed_normal_returns or self.observed_keyword_checks):
            raise ValueError('Supply one observation family for an assessment')
        if (len(self.observed_attribute_retentions) > 8 or any(
                not isinstance(value, ObservedAttributeRetention)
                for value in self.observed_attribute_retentions)):
            raise ValueError('observed_attribute_retentions requires bounded observation records')
        if self.observed_attribute_retentions and (self.observed_container_predicates
                or self.observed_normal_returns or self.observed_keyword_checks):
            raise ValueError('Supply one observation family for an assessment')


@dataclass(frozen=True)
class AnalysisBoundary:
    """A diagnostic explaining an analysis limit, rather than a VPP finding."""

    code: str
    message: str
    function: Optional[FunctionIdentity] = None
    callsite: Optional[SourceSpan] = None
    root_function: Optional[FunctionIdentity] = None
    parameter_name: Optional[str] = None
    parameter_kind: Optional[VariadicKind] = None


@dataclass(frozen=True)
class ParameterEvidence:
    """A binding, use, drop or selected condition supporting an assessment."""

    function: FunctionIdentity
    reason: str
    detail: str
    callsite: Optional[SourceSpan] = None
    target: Optional[FunctionIdentity] = None


@dataclass(frozen=True)
class ParameterAssessment:
    """Handling state and supporting evidence for one changed argument in a call."""

    target_api: FunctionIdentity
    change: ParameterChange
    call_text: str
    state: ParameterState
    reason: str
    evidence: Tuple[ParameterEvidence, ...] = ()
    boundaries: Tuple[AnalysisBoundary, ...] = ()
    resolved_api: Optional[FunctionIdentity] = None
    callsite: Optional[SourceSpan] = None


@dataclass(frozen=True)
class VariadicFunction:
    function: FunctionIdentity
    parameters: Tuple[Tuple[str, VariadicKind], ...]
    implementation: Optional[FunctionIdentity] = None


@dataclass(frozen=True)
class ForwardingStep:
    """One source or proven builtin-protocol hop in an API's forwarding path."""

    function: FunctionIdentity
    parameter_name: str
    callee_expression: str
    callsite: SourceSpan
    target: FunctionIdentity
    target_status: str = "resolved"
    conditions: Tuple[dict, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ForwardingFinding:
    """A root variadic parameter reaches an incompatible expansion signature."""

    function: FunctionIdentity
    parameter_name: str
    parameter_kind: VariadicKind
    callee_expression: str
    callsite: SourceSpan
    target: FunctionIdentity
    reason_code: str
    path: Tuple[ForwardingStep, ...] = field(default_factory=tuple)
    target_status: str = "resolved"
    target_candidates: Tuple[FunctionIdentity, ...] = field(default_factory=tuple)
    receiver_type_evidence: Tuple[dict, ...] = field(default_factory=tuple)
    conditions: Tuple[dict, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class VariadicCoverage:
    """One root channel's findings and recorded limits in a scan snapshot."""

    function: FunctionIdentity
    parameter_name: str
    parameter_kind: VariadicKind
    status: ScanCoverageStatus
    finding_count: int = 0
    boundary_codes: Tuple[str, ...] = ()
    implementation: Optional[FunctionIdentity] = None


@dataclass(frozen=True)
class ScanReport:
    """Positive VPP findings and diagnostics for one scan scope."""

    source: SourceContext
    functions_scanned: int
    variadic_functions: Tuple[VariadicFunction, ...]
    findings: Tuple[ForwardingFinding, ...]
    boundaries: Tuple[AnalysisBoundary, ...] = field(default_factory=tuple)
    analyzer_schema_version: Optional[str] = None
    target_api: Optional[FunctionIdentity] = None
    resolved_api: Optional[FunctionIdentity] = None
    coverage: Tuple[VariadicCoverage, ...] = ()

    @property
    def has_vpp(self) -> bool:
        """Whether this scan found a VPP; false does not prove full coverage."""

        return bool(self.findings)

    @property
    def potential_pitfalls(self) -> Tuple[ForwardingFinding, ...]:
        """Compatibility alias for the positive findings collection."""

        return self.findings
