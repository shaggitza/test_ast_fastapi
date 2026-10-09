from collections.abc import Callable

def changed(value: str) -> int:
    return len(value)

callback: Callable[[str], int] = changed

def invoke(fn: Callable[[str], int], arg: str) -> int:
    return fn(arg)

reveal_type(invoke(callback, "x"))
