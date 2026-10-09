from pkg.service import normalize

def route(value: str) -> str:
    return normalize(value)

reveal_type(route("abc"))
