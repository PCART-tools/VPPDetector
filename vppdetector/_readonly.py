## @package vppdetector._readonly
#  Freeze cached facts while preserving controlled expansion copies.
#  冻结缓存事实，同时保留受控扩展所需的副本。

"""Read-only cached fact trees, with mutable deep copies for producer expansion."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, fields, is_dataclass


## Reject mutations on cached read-only fact containers
## 拒绝对只读缓存事实容器的修改
#
#  @param *args Arguments to the operation.
#  @param **kwargs Keyword options for the operation.
#  @return None; always raises TypeError to reject the attempted mutation.
def _immutable(*args, **kwargs):
    raise TypeError("Cached program facts are read-only; use deepcopy for a separate copy")


## Provide list-compatible access to immutable fact items.
## 提供兼容列表读取方式的不可变事实项。
class _FactList(list):
    __setitem__ = __delitem__ = __iadd__ = __imul__ = _immutable
    append = clear = extend = insert = pop = remove = reverse = sort = _immutable

    ## Create a mutable deep copy for isolated producer expansion
    ## 为隔离的生产者扩展创建可变深拷贝
    #
    #  @param memo Value named `memo` supplied by the enclosing analysis.
    #  @return Result of the `__deepcopy__` operation.
    def __deepcopy__(self, memo):
        result = []
        memo[id(self)] = result
        result.extend(deepcopy(value, memo) for value in self)
        return result


## Provide dictionary-compatible access to immutable fact fields.
## 提供兼容字典读取方式的不可变事实字段。
class _FactDict(dict):
    __setitem__ = __delitem__ = __ior__ = _immutable
    clear = pop = popitem = setdefault = update = _immutable

    ## Create a mutable deep copy for isolated producer expansion
    ## 为隔离的生产者扩展创建可变深拷贝
    #
    #  @param memo Value named `memo` supplied by the enclosing analysis.
    #  @return Result of the `__deepcopy__` operation.
    def __deepcopy__(self, memo):
        result = {}
        memo[id(self)] = result
        result.update((deepcopy(key, memo), deepcopy(value, memo)) for key, value in self.items())
        return result


## Expose an immutable fact record with mapping-style conversion.
## 提供支持映射转换方式的不可变事实记录。
class _FactRecord:
    __setattr__ = __delattr__ = _immutable

    ## Create a mutable deep copy for isolated producer expansion
    ## 为隔离的生产者扩展创建可变深拷贝
    #
    #  @param memo Value named `memo` supplied by the enclosing analysis.
    #  @return Result of the `__deepcopy__` operation.
    def __deepcopy__(self, memo):
        result = object.__new__(self._record_type)
        memo[id(self)] = result
        for item in fields(self):
            object.__setattr__(result, item.name, deepcopy(getattr(self, item.name), memo))
        return result

    ## Compare the fact record with another mapping or record
    ## 将事实记录与其他映射或记录进行比较
    #
    #  @param other Value named `other` supplied by the enclosing analysis.
    #  @return Result of the `__eq__` operation.
    def __eq__(self, other):
        if not isinstance(other, self._record_type):
            return NotImplemented
        return all(getattr(self, item.name) == getattr(other, item.name) for item in fields(self))

    ## Return a mutable dictionary copy of the fact record
    ## 返回事实记录的可变字典副本
    #
    #  @return Result of the `to_dict` operation.
    def to_dict(self):
        return asdict(deepcopy(self))


_RECORD_TYPES = {}
## Freeze one producer result once; preserve dict/list and dataclass readers
## 冻结一次生产者结果，同时保留dict、list和dataclass读取方式
#
#  @param value Value or producer record being interpreted.
#  @param memo Value named `memo` supplied by the enclosing analysis.
#  @return Result of the `readonly` operation.
def readonly(value, memo=None):
    if isinstance(value, (_FactList, _FactDict, _FactRecord)):
        return value

    # 保留共享对象身份并终止容器中的循环引用
    memo = {} if memo is None else memo
    if id(value) in memo:
        return memo[id(value)]
    if is_dataclass(value) and not isinstance(value, type):
        if value.__dataclass_params__.frozen:
            return value
        record_type = type(value)
        frozen_type = _RECORD_TYPES.get(record_type)
        if frozen_type is None:
            frozen_type = type("ReadOnly" + record_type.__name__, (_FactRecord, record_type),
                               {"_record_type": record_type, "__module__": __name__})
            _RECORD_TYPES[record_type] = frozen_type
        result = object.__new__(frozen_type)
        memo[id(value)] = result
        for item in fields(value):
            object.__setattr__(result, item.name, readonly(getattr(value, item.name), memo))
        return result
    if isinstance(value, dict):
        result = _FactDict()
        memo[id(value)] = result
        dict.update(result, ((key, readonly(item, memo)) for key, item in value.items()))
        return result
    if isinstance(value, list):
        result = _FactList()
        memo[id(value)] = result
        list.extend(result, (readonly(item, memo) for item in value))
        return result
    if isinstance(value, tuple):
        return tuple(readonly(item, memo) for item in value)
    return value
