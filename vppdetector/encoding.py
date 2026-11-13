## @package vppdetector.encoding
#  Select source encodings and retain the compatibility helper.
#  选择源码编码并保留兼容性辅助接口。

from __future__ import annotations

import io
import tokenize
from pathlib import Path
from typing import Union

import chardet


PathLike = Union[str, Path]


## Return an encoding that is verified to decode the complete file
## 选择能够完整解码源码文件的字符编码
#
#  @param file_path Path of the source file
#  @return Encoding name that decodes the entire file
#  @exception OSError If the file cannot be read
#  @exception UnicodeError If none of the candidate encodings can decode it
def get_encoding(file_path):
    raw_data = Path(file_path).read_bytes()
    candidates = []

    try:
        declared, _ = tokenize.detect_encoding(io.BytesIO(raw_data).readline)
        candidates.append(declared)
    except SyntaxError:
        pass

    candidates.append("utf-8-sig")
    detected = chardet.detect(raw_data).get("encoding")
    if detected:
        candidates.append(detected)
    candidates.append("latin-1")

    tried = set()
    for encoding in candidates:
        normalized = encoding.lower()
        if normalized in tried:
            continue
        tried.add(normalized)
        try:
            raw_data.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
        return encoding

    raise UnicodeError("No usable encoding found for {}".format(file_path))


## Compatibility alias for the VPPDetector 1.0 public helper
## 保留VPPDetector 1.0旧版公开辅助函数的兼容别名
#
#  @param filePath Source file path
#  @return Encoding name that decodes the entire file
#  @exception OSError If the file cannot be read
#  @exception UnicodeError If none of the candidate encodings can decode it
def getEncoding(filePath):
    return get_encoding(filePath)
