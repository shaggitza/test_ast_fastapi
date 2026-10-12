"""Cross-file import and alias call fixture."""

from provider import target as renamed_target

ACCENT = "café"


def direct_call() -> str:
    return renamed_target()


def alias_call() -> str:
    call = renamed_target
    return call()
