## @package vppdetector.scanner
#  Whole-package and on-demand scans over the shared detection core.
#  基于共享检测核心执行全包扫描和按需扫描。

"""Whole-package and on-demand scopes over the same VPP detection core."""

from __future__ import annotations

from dataclasses import replace
from typing import List, Optional, Sequence

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
from ._fact_adapter import ResolutionError
from .core import scan_function
from .models import (
    AnalysisBoundary,
    ForwardingFinding,
    FunctionIdentity,
    ScanCoverageStatus,
    ScanReport,
    VariadicCoverage,
    VariadicFunction,
)
from .source import IndexedFunction, SourceIndex


## Scan every eligible function in one library source snapshot
## 扫描单个库源码快照中的所有可分析函数
#
#  @param package_root Library source directory or standalone Python file
#  @param import_roots Optional module roots used for import resolution
#  @param max_depth Maximum forwarding depth; must be positive
#  @param context Optional reusable analysis context for the same source snapshot
#  @return ScanReport containing findings, boundaries and coverage
def scan_package(
    package_root,
    *,
    import_roots=None,
    max_depth=5,
    context=None,
):
    _validate_depth(max_depth)
    index, context = _prepare_context(package_root, import_roots, context)
    if index.is_api_scope:
        raise ValueError("Whole-package scanning requires a full-source context")
    if not index.files:
        return _empty_source_report(index)
    entries = tuple(function for function in index.functions if not function.is_overload)
    return _scan_entries(context, entries, max_depth=max_depth)


## Scan one requested API and its reachable forwarding path
## 扫描指定API及其可达的参数转发路径
#
#  @param package_root Library source directory or standalone Python file
#  @param target_api Source identity of the requested API
#  @param import_roots Optional module roots used for import resolution
#  @param max_depth Maximum forwarding depth; must be positive
#  @param context Optional reusable analysis context for the same source snapshot
#  @return ScanReport scoped to the requested API
def scan_api(
    package_root,
    target_api,
    *,
    import_roots=None,
    max_depth=5,
    context=None,
):
    _validate_depth(max_depth)
    index, context = _prepare_context(package_root, import_roots, context)
    if not index.files:
        return replace(_empty_source_report(index), target_api=target_api)
    try:
        entry = context.resolve_api(target_api)
    except ResolutionError as exc:
        report = _missing_api_report(
            index, target_api,
            exc.code if exc.code in {'pcresolve_fact_contract_unavailable', 'flow_analysis_failed',
                                     'constructor_analysis_failed'}
            else 'entry_resolution_failed', str(exc))
        nominal = index.find(target_api)
        if nominal is not None and exc.code in {
                'pcresolve_fact_contract_unavailable', 'flow_analysis_failed'}:
            return replace(report, coverage=tuple(
                VariadicCoverage(nominal.identity, name, kind, ScanCoverageStatus.UNAVAILABLE,
                                 0, (exc.code,)) for name, kind in nominal.variadic_parameters))
        return report
    if entry is None or entry.is_overload:
        return _missing_api_report(
            index,
            target_api,
            "target_api_unavailable",
            "The requested API could not be resolved to one source implementation.",
        )
    report = _scan_entries(context, (entry,), max_depth=max_depth)
    return replace(
        report,
        target_api=target_api,
        resolved_api=entry.identity,
        variadic_functions=tuple(
            replace(
                function,
                function=target_api,
                implementation=entry.identity if target_api != entry.identity else None,
            )
            for function in report.variadic_functions
        ),
        findings=tuple(replace(finding, function=target_api) for finding in report.findings),
        boundaries=tuple(
            replace(boundary, root_function=target_api)
            if boundary.root_function == entry.identity else boundary
            for boundary in report.boundaries
        ),
        coverage=tuple(
            replace(
                channel, function=target_api,
                implementation=entry.identity if target_api != entry.identity else None,
            )
            for channel in report.coverage
        ),
    )


## Scan selected indexed functions and assemble findings, boundaries and coverage
## 扫描选定的索引函数并汇总发现、边界及覆盖信息
#
#  @param context Reusable analysis context for the selected source snapshot
#  @param entries Input value of type `Sequence[IndexedFunction]`
#  @param max_depth Maximum number of forwarding steps to analyze
#  @return Result of type `ScanReport`
def _scan_entries(
    context,
    entries,
    *,
    max_depth,
):
    variadic_functions = []
    findings = []
    boundaries = list(context.index.boundaries)
    coverage = []
    schema_version = None
    for entry in entries:
        if not entry.variadic_parameters:
            continue
        variadic_functions.append(VariadicFunction(entry.identity, entry.variadic_parameters))
        entry_findings, entry_boundaries, entry_schema = scan_function(context, entry, max_depth)
        findings.extend(entry_findings)
        boundaries.extend(entry_boundaries)
        for name, kind in entry.variadic_parameters:
            channel_boundaries = (
                *context.index.boundaries,
                *(boundary for boundary in entry_boundaries
                  if boundary.parameter_name == name and boundary.parameter_kind == kind),
            )
            unavailable = any(
                boundary.code in {"flow_analysis_failed", "pcresolve_fact_contract_unavailable"}
                and boundary.function == entry.identity
                for boundary in channel_boundaries
            )

            # 区分分析不可用、存在已知边界以及没有已知边界
            status = (
                ScanCoverageStatus.UNAVAILABLE if unavailable else
                ScanCoverageStatus.LIMITED if channel_boundaries else
                ScanCoverageStatus.NO_KNOWN_BOUNDARY
            )
            coverage.append(VariadicCoverage(
                entry.identity, name, kind, status,
                sum(f.parameter_name == name and f.parameter_kind == kind for f in entry_findings),
                tuple(dict.fromkeys(boundary.code for boundary in channel_boundaries)),
            ))
        if entry_schema is not None:
            schema_version = entry_schema
    return ScanReport(
        source=context.index.source,
        functions_scanned=len(entries),
        variadic_functions=tuple(variadic_functions),
        findings=tuple(findings),
        boundaries=tuple(boundaries),
        analyzer_schema_version=schema_version,
        coverage=tuple(coverage),
    )


## Build a report explaining that the source scope contains no Python files
## 构建说明源码作用域中没有Python文件的报告
#
#  @param index Source index used for definitions and imports
#  @return Result of type `ScanReport`
def _empty_source_report(index):
    return ScanReport(
        source=index.source,
        functions_scanned=0,
        variadic_functions=(),
        findings=(),
        boundaries=(
            *index.boundaries,
            AnalysisBoundary(
                code="no_python_sources",
                message="No Python source files are available in the requested analysis scope.",
            ),
        ),
    )


## Build a report for an API that cannot be resolved to one implementation
## 为无法解析到唯一实现的API构建报告
#
#  @param index Source index used for definitions and imports
#  @param target_api Source identity of the API being analyzed
#  @param code Input value of type `str`
#  @param message Input value of type `str`
#  @return Result of type `ScanReport`
def _missing_api_report(
    index, target_api, code, message
):
    return ScanReport(
        source=index.source,
        functions_scanned=0,
        variadic_functions=(),
        findings=(),
        boundaries=(
            *index.boundaries,
            AnalysisBoundary(code=code, message=message, function=target_api),
        ),
        target_api=target_api,
    )
