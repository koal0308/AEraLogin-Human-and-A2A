"""A secret string that cannot be leaked by accident.

`repr`, `str`, `format` and therefore `vars(obj)`, f-strings, logging and
pytest assertion output all render `<redacted>`. The raw value is only
reachable via the explicit `.reveal()` call, which greps as an audit point.
"""
from __future__ import annotations


class Secret:
    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __bool__(self) -> bool:
        return bool(self._value)

    def __len__(self) -> int:
        return len(self._value)

    def __repr__(self) -> str:
        return "<redacted>"

    __str__ = __repr__

    def __format__(self, spec: str) -> str:
        return "<redacted>"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Secret):
            return self._value == other._value
        return NotImplemented

    def __hash__(self) -> int:
        return hash(("Secret", self._value))
