## @package vppdetector.cli
#  Standalone command-line entry point for VPP scanning.
#
#
#  Parse package root and scan options, call the shared scanner and write its result as JSON.
#  解析包根和扫描选项，调用共享扫描入口并以 JSON 写出结果。



import argparse
import json
from dataclasses import fields, is_dataclass
from enum import Enum
from pathlib import Path

from .models import ScanReport, asdict_record
from .scanner import scan_package


## Convert report values into JSON-serializable data
## 将报告值转换为可序列化的JSON数据
#
#  @param value Value or producer record being interpreted
#  @return The value converted to JSON-compatible containers and scalars
def _to_data(value):

    # Include the computed risk flag alongside the report's stored fields for CLI consumers.
    # CLI 输出除报告字段外，还包含计算得到的风险标志。
    if isinstance(value, ScanReport):
        data = {key: _to_data(item) for key, item in asdict_record(value).items()}
        data["has_vpp"] = value.has_vpp
        return data
    if is_dataclass(value):
        data = {field.name: _to_data(getattr(value, field.name)) for field in fields(value)}
        return data

    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, tuple):
        return [_to_data(item) for item in value]
    if isinstance(value, list):
        return [_to_data(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _to_data(item) for key, item in value.items()}
    return value


## Create the command-line argument parser
## 创建命令行参数解析器
#
#  @return Configured parser for package root, import roots, depth and output
def build_parser():
    parser = argparse.ArgumentParser(description="scan one package version for VPP risks")
    parser.add_argument("package_root", type=Path)
    parser.add_argument("--import-root", action="append", type=Path, default=[])
    parser.add_argument("--max-depth", type=int, default=5)
    parser.add_argument("--output", type=Path)
    return parser


## Run a whole-package scan and serialize its report
## 执行全包扫描并序列化报告
#
#  @param argv Optional command-line arguments; defaults to process arguments
#  @return Zero after a successful scan and report write
def main(argv=None):
    arguments = build_parser().parse_args(argv)
    report = scan_package(
        arguments.package_root,
        import_roots=arguments.import_root,
        max_depth=arguments.max_depth,
    )
    text = json.dumps(_to_data(report), ensure_ascii=False, indent=2)
    if arguments.output:
        arguments.output.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0
