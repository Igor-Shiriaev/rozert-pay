import typing as ty
from typing import Any

Faker: ty.Any

T = ty.TypeVar("T")

class Factory(ty.Generic[T]):
    @classmethod
    def create(cls, *args: Any, **kwargs: Any) -> T: ...
    @classmethod
    def _create(cls, *args: Any, **kwargs: Any) -> T: ...
    @classmethod
    def build(cls, *args: Any, **kwargs: Any) -> T: ...

class SubFactory:
    def __init__(self, factory: ty.Type[Factory[T]], **kwargs: ty.Any) -> None: ...

class DictFactory(Factory[dict[ty.Any, ty.Any]]): ...

TC = ty.TypeVar("TC", bound=ty.Callable[..., ty.Any])

def lazy_attribute(func: TC) -> TC: ...

LazyAttribute = lazy_attribute

class Sequence:
    def __init__(self, sequence: ty.Callable[[int], Any]) -> None: ...

class Dict:
    def __init__(self, params: dict[str, Any]) -> None: ...
