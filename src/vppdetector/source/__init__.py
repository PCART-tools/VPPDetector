## @package vppdetector.source
#  Source discovery, indexing, and query services.
#
#
#  Export the source index, query service, discovery helpers and indexed declaration records.
#  导出源码索引、查询服务、发现辅助函数和已索引声明记录。



from .build import build_source_index as build_source_index
from .discovery import module_name_for_path as module_name_for_path
from .discovery import normalized_import_roots as normalized_import_roots
from .index import SourceIndex as SourceIndex
from .queries import SourceQueries as SourceQueries
from .records import IndexedConstructor as IndexedConstructor
from .records import IndexedFunction as IndexedFunction
from .records import SignatureFacts as SignatureFacts

__all__ = (
    "SourceIndex",
    "SourceQueries",
    "IndexedConstructor",
    "IndexedFunction",
    "SignatureFacts",
    "build_source_index",
    "module_name_for_path",
    "normalized_import_roots",
)
