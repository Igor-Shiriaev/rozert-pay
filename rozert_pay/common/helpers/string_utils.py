import typing as ty


def string_matches(
    value: str,
    pattern_: ty.Union[str, ty.Pattern[str], ty.Sequence[str | ty.Pattern[str]]],
) -> bool:
    if not isinstance(pattern_, list):
        pattern = [pattern_]
    else:
        pattern = pattern_

    for p in pattern:
        if isinstance(p, str):
            if value == p:
                return True
        elif isinstance(p, ty.Pattern):
            if p.search(value):
                return True
    return False
