import logging
import typing as ty

logger = logging.getLogger(__name__)

P = ty.ParamSpec("P")
V = ty.TypeVar("V")


ErrorCode = ty.NewType("ErrorCode", str)


class Error(Exception):
    def __init__(self, message: str, code: ErrorCode | None = None):
        super().__init__(message)
        self.message = message
        self.code = code


def wrap_errors(func: ty.Callable[P, V]) -> ty.Callable[P, ty.Union[V, Error]]:
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> ty.Union[V, Error]:
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.exception("Error in wrapped function")  # pragma: no cover
            return Error(f"Error: {e}")

    return wrapper


class SafeFlowInterruptionError(Exception):
    """
    Use this error ONLY if no operation performed in payment system,
    and our transaction can be successfully cancelled.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
