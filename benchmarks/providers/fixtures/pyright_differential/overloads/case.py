from typing import overload

@overload
def convert(value: int) -> str: ...

@overload
def convert(value: str) -> int: ...

def convert(value: int | str) -> str | int:
    return str(value) if isinstance(value, int) else len(value)

reveal_type(convert(1))
