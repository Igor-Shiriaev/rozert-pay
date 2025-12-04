import threading
from contextlib import contextmanager
from typing import Generator, TypedDict, cast

_ContextType = TypedDict(
    "_ContextType",
    {
        "incoming_callback_id": int | None,
    },
)


class _LocalsType:
    context: _ContextType


_locals = cast(_LocalsType, threading.local())


@contextmanager
def global_context(
    incoming_callback_id: int | None = None,
) -> Generator[None, None, None]:
    if not hasattr(_locals, "context"):
        _locals.context = {
            "incoming_callback_id": None,
        }

    context = [
        ("incoming_callback_id", incoming_callback_id),
    ]

    for key, value in context:
        if value is not None:
            if v := _locals.context.get(key):
                raise ValueError(
                    f"Key {key} already exists in context (current value={v}, new value={value})!"
                )
            _locals.context[key] = value  # type: ignore[literal-required]

    try:
        yield
    finally:
        assert _locals.context
        for key, value in context:
            if value is not None:
                assert key in _locals.context, f"Key {key} not found in context!"
                del _locals.context[key]  # type: ignore[misc]


def current_context() -> _ContextType:
    return cast(_ContextType, getattr(_locals, "context", {}))
