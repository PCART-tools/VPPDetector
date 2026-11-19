## @package vppdetector.encoding
#  Select source encodings.
#
#
#  Select an encoding by checking that the full source file decodes under the candidate.
#  校验候选字符编码能否解码完整源码文件，据此选择编码。



import io
import tokenize
from pathlib import Path

import chardet


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

    # Try UTF-8 before the detector's guess, then fall back to a byte-preserving encoding.
    # 先尝试 UTF-8，再尝试检测结果，最后回退到可解码所有字节值的编码。
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
