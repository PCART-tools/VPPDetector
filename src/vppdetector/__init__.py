## @package vppdetector
#  Public scan and assess interfaces backed by PCResolve.
#
#
#  Export the public context, scanning and assessment interfaces and their result models.
#  导出公开的分析上下文、扫描和评估入口及其结果模型。



from ._analysis_context import AnalysisContext
from .assessment import assess_change
from .facts.adapter import ResolutionError
from .models import (
    AnalysisBoundary,
    CallContext,
    ChangeKind,
    ForwardingFinding,
    ForwardingStep,
    FunctionIdentity,
    ObservedAttributeRetention,
    ObservedCaptureRejection,
    ObservedContainerPredicate,
    ObservedFixedBinding,
    ObservedKeywordCheck,
    ObservedNormalReturn,
    ParameterAssessment,
    ParameterChange,
    ParameterEvidence,
    ParameterState,
    ScanCoverageStatus,
    ScanReport,
    SourceContext,
    SourceSpan,
    VariadicCoverage,
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
    "ObservedAttributeRetention",
    "ObservedCaptureRejection",
    "ObservedContainerPredicate",
    "ObservedFixedBinding",
    "ObservedKeywordCheck",
    "ObservedNormalReturn",
    "ParameterAssessment",
    "ParameterChange",
    "ParameterEvidence",
    "ParameterState",
    "ResolutionError",
    "ScanReport",
    "ScanCoverageStatus",
    "SourceContext",
    "SourceSpan",
    "VariadicFunction",
    "VariadicCoverage",
    "VariadicKind",
    "assess_change",
    "scan_api",
    "scan_package",
]

__version__ = "1.1.0"
