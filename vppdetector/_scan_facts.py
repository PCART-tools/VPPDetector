## @package vppdetector._scan_facts
#  Compatibility exports for shared source-fact readers.
#  为共享源码事实读取器提供兼容导出。

"""Compatibility imports for the shared, domain-neutral fact readers."""

from ._program_facts import (
    capture_names as capture_names,
)
from ._program_facts import (
    conditions_possible as conditions_possible,
)
from ._program_facts import (
    copy_protocol_target as copy_protocol_target,
)
from ._program_facts import (
    immediate_body as immediate_body,
)
