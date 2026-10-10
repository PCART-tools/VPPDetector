"""Whole-library and on-demand VPP detection backed by PCResolve facts."""

from .assessment import assess_change
from .core import AnalysisContext, ResolutionError
from .encoding import get_encoding, getEncoding
from .models import (
    AnalysisBoundary,
    CallContext,
    ChangeKind,
    ForwardingFinding,
    ForwardingStep,
    FunctionIdentity,
    ParameterAssessment,
    ParameterChange,
    ParameterEvidence,
    ParameterState,
    ScanReport,
    SourceContext,
    SourceSpan,
    VariadicFunction,
    VariadicKind,
)
from .scanner import scan_api, scan_package

__all__ = [
    "AnalysisBoundary",
    "AnalysisContext",
    "CallContext",
    "ChangeKind",
    "ForwardingFinding",
    "ForwardingStep",
    "FunctionIdentity",
    "ParameterAssessment",
    "ParameterChange",
    "ParameterEvidence",
    "ParameterState",
    "ResolutionError",
    "ScanReport",
    "SourceContext",
    "SourceSpan",
    "VariadicFunction",
    "VariadicKind",
    "assess_change",
    "getEncoding",
    "get_encoding",
    "scan_api",
    "scan_package",
]

__version__ = "1.1.0"
