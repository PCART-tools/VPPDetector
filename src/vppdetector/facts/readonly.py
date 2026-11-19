## @package vppdetector.facts.readonly
#  Freeze cached fact trees while allowing mutable deep copies for expansion.
#
#
#  Guard shared producer records and their nested containers against mutation. Deep copies
#  provide private state for expansion.
#  防止写入共享生产者记录及其嵌套容器，通过深拷贝为扩展提供私有状态。



from copy import deepcopy
from dataclasses import asdict, fields, is_dataclass


## Read fields from dynamically wrapped dataclass producer records.
## 读取动态包装的 dataclass 生产者记录字段。
#
#  @param value Dynamically wrapped producer record.
#  @return Fields exposed by the producer record.
def _record_fields(value):
    return fields(value)


## Convert a dynamically wrapped producer record through dataclasses.asdict.
## 通过 dataclasses.asdict 转换动态包装的生产者记录。
#
#  @param value Dynamically wrapped producer record.
#  @return Mutable dictionary copy of the producer record fields.
def _record_asdict(value):
    return asdict(value)


## Reject mutations on cached read-only fact containers
## 拒绝对只读缓存事实容器的修改
#
#  @param args Positional arguments passed to the immutable operation
#  @param kwargs Keyword arguments passed to the immutable operation
#  @exception TypeError Always raised to reject the attempted mutation
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
    #  @param memo Deep-copy memo used to preserve shared references
    #  @return Mutable list containing deep copies of the fact items
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
    #  @param memo Deep-copy memo used to preserve shared references
    #  @return Mutable dictionary containing deep copies of the fact fields
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
    #  @param memo Deep-copy memo used to preserve shared references
    #  @return Mutable instance of the original record type with copied fields
    def __deepcopy__(self, memo):
        result = object.__new__(self._record_type)
        memo[id(self)] = result
        for item in _record_fields(self):
            object.__setattr__(result, item.name, deepcopy(getattr(self, item.name), memo))
        return result

    ## Compare the fact record with another instance of its original type
    ## 将事实记录与其原始类型的另一个实例进行比较
    #
    #  @param other Object to compare with this fact record
    #  @return Whether all fields match, or NotImplemented for another type
    def __eq__(self, other):
        if not isinstance(other, self._record_type):
            return NotImplemented
        return all(
            getattr(self, item.name) == getattr(other, item.name) for item in _record_fields(self)
        )

    ## Return a mutable dictionary copy of the fact record
    ## 返回事实记录的可变字典副本
    #
    #  @return Dictionary containing mutable deep copies of the record fields
    def to_dict(self):
        return _record_asdict(deepcopy(self))


_RECORD_TYPES = {}


## Freeze one producer result once; preserve dict/list and dataclass readers
## 冻结一次生产者结果，同时保留dict、list和dataclass读取方式
#
#  @param value Producer fact tree or scalar to freeze
#  @param memo Optional identity cache for shared and cyclic objects
#  @return Read-only wrapper for mutable supported containers or records; other values unchanged
def readonly(value, memo=None):
    if isinstance(value, (_FactList, _FactDict, _FactRecord)):
        return value

    # Share one memo to preserve aliases and stop recursion through container cycles.
    # 共用一份复制记录，以保留别名并在遇到容器循环引用时停止递归。
    memo = {} if memo is None else memo
    if id(value) in memo:
        return memo[id(value)]

    if is_dataclass(value) and not isinstance(value, type):
        record_value = value
        if record_value.__dataclass_params__.frozen:
            return value
        record_type = type(value)
        frozen_type = _RECORD_TYPES.get(record_type)
        if frozen_type is None:
            frozen_type = type(
                "ReadOnly" + record_type.__name__,
                (_FactRecord, record_type),
                {"_record_type": record_type, "__module__": __name__},
            )
            _RECORD_TYPES[record_type] = frozen_type
        record_result = object.__new__(frozen_type)
        memo[id(value)] = record_result
        for item in _record_fields(record_value):
            object.__setattr__(record_result, item.name, readonly(getattr(value, item.name), memo))
        return record_result
    if isinstance(value, dict):
        result = _FactDict()
        memo[id(value)] = result
        dict.update(result, ((key, readonly(item, memo)) for key, item in value.items()))
        return result
    if isinstance(value, list):
        list_result = _FactList()
        memo[id(value)] = list_result
        list.extend(list_result, (readonly(item, memo) for item in value))
        return list_result
    if isinstance(value, tuple):
        return tuple(readonly(item, memo) for item in value)
    return value
