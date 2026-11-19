## @package vppdetector._records
#  Shared runtime support for annotation-free value records.
#
#
#  Implement field-based equality, representation, freezing and replacement for internal records.
#  Recursive export detaches nested container values.
#  为内部记录提供基于字段的比较、表示、冻结与替换，并在导出时递归复制嵌套容器。



from copy import deepcopy
from dataclasses import FrozenInstanceError, fields, is_dataclass


## Mark a constructor argument whose default must be created per instance.
## 标记需要为每个实例单独创建默认值的构造参数。
class _FactoryDefault:
    ## Return a stable marker representation for diagnostics.
    ## 为诊断输出稳定的标记表示。
    #
    #  @return Stable factory marker text
    def __repr__(self):
        return "<factory>"


FACTORY_DEFAULT = _FactoryDefault()


## Common equality and representation for annotation-free records
## 无类型注解记录共用的相等性和表示实现
class Record:
    _record_fields = ()

    ## Compare records of the same concrete class by their configured fields.
    ## 按配置字段比较同一具体类型的记录。
    #
    #  @param other Record to compare against
    #  @return True or False for same-class records; NotImplemented otherwise
    def __eq__(self, other):
        fields = getattr(self, "_record_compare_fields", self._record_fields)
        if other.__class__ is self.__class__:
            return tuple(getattr(self, name) for name in fields) == tuple(
                getattr(other, name) for name in fields
            )
        return NotImplemented

    ## Render configured fields for debugging.
    ## 输出配置字段的调试表示。
    #
    #  @return Text representation of the configured record fields
    def __repr__(self):
        fields = getattr(self, "_record_repr_fields", self._record_fields)
        display = ", ".join(f"{name}={getattr(self, name)!r}" for name in fields)
        return f"{type(self).__name__}({display})"


## Preserve immutable record behavior without declared field annotations
## 在不声明字段注解的情况下保持记录不可变行为
class FrozenRecord(Record):
    ## Reject assignment to immutable record fields.
    ## 拒绝修改不可变记录字段。
    #
    #  @param name Field name being assigned
    #  @param value Value proposed for the field
    def __setattr__(self, name, value):
        raise FrozenInstanceError(f"cannot assign to field '{name}'")

    ## Reject deletion of immutable record fields.
    ## 拒绝删除不可变记录字段。
    #
    #  @param name Field name being deleted
    def __delattr__(self, name):
        raise FrozenInstanceError(f"cannot delete field '{name}'")

    ## Hash the fields used by record equality.
    ## 对记录相等比较所用字段计算哈希值。
    #
    #  @return Hash of the configured comparison fields
    def __hash__(self):
        fields = getattr(self, "_record_compare_fields", self._record_fields)
        return hash(tuple(getattr(self, name) for name in fields))


## Preserve mutable record behavior and unhashability
## 保持记录可变行为及不可哈希属性
class MutableRecord(Record):
    __hash__ = None


## Replace fields on one annotation-free record
## 替换一个无类型注解记录中的字段
#
#  @param record Record whose fields are copied
#  @param changes Field values supplied as keyword replacements
#  @return New record of the same class with the requested values
def replace_record(record, **changes):
    values = {name: getattr(record, name) for name in record._record_fields}
    unknown = changes.keys() - values.keys()
    if unknown:
        name = next(iter(unknown))
        raise TypeError(f"{name!r} is not a valid field for {type(record).__name__}")

    values.update(changes)
    return type(record)(**values)


## Convert a record and its nested containers into detached plain values
## 将记录及其嵌套容器转换为分离的普通值
#
#  @param record Record or nested value to copy
#  @return Dictionary for records and recursively copied containers
def asdict_record(record):
    if isinstance(record, Record):
        return {name: asdict_record(getattr(record, name)) for name in record._record_fields}
    if is_dataclass(record) and not isinstance(record, type):
        return {item.name: asdict_record(getattr(record, item.name)) for item in fields(record)}
    if isinstance(record, dict):
        return type(record)(
            (asdict_record(key), asdict_record(value)) for key, value in record.items()
        )
    if isinstance(record, (list, tuple)):
        return type(record)(asdict_record(item) for item in record)
    return deepcopy(record)
