from pathlib import Path

def local_shadow(Path: str) -> str:
    return Path

def imported_name(value: Path) -> str:
    return value.name

reveal_type(imported_name(Path("file")))
