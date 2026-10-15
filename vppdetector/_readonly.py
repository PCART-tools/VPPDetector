"""Read-only cached fact trees, with mutable deep copies for producer expansion."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, fields, is_dataclass


def _immutable(*args, **kwargs):
    raise TypeError("Cached program facts are read-only; use deepcopy for a separate copy")


class _FactList(list):
    __setitem__ = __delitem__ = __iadd__ = __imul__ = _immutable
    append = clear = extend = insert = pop = remove = reverse = sort = _immutable

    def __deepcopy__(self, memo):
        result = []
        memo[id(self)] = result
        result.extend(deepcopy(value, memo) for value in self)
        return result


class _FactDict(dict):
    __setitem__ = __delitem__ = __ior__ = _immutable
    clear = pop = popitem = setdefault = update = _immutable

    def __deepcopy__(self, memo):
        result = {}
        memo[id(self)] = result
        result.update((deepcopy(key, memo), deepcopy(value, memo)) for key, value in self.items())
        return result


class _FactRecord:
    __setattr__ = __delattr__ = _immutable

    def __deepcopy__(self, memo):
        result = object.__new__(self._record_type)
        memo[id(self)] = result
        for item in fields(self):
            object.__setattr__(result, item.name, deepcopy(getattr(self, item.name), memo))
        return result

    def __eq__(self, other):
        if not isinstance(other, self._record_type):
            return NotImplemented
        return all(getattr(self, item.name) == getattr(other, item.name) for item in fields(self))

    def to_dict(self):
        return asdict(deepcopy(self))


_RECORD_TYPES = {}


def readonly(value, memo=None):
    """Freeze one producer result once; preserve dict/list and dataclass readers."""

    if isinstance(value, (_FactList, _FactDict, _FactRecord)):
        return value
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
