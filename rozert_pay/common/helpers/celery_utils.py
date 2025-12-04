from typing import Callable, TypeVar

from django.conf import settings
from django.db import transaction

T = TypeVar("T")


def execute_on_commit(func: Callable[[], T]) -> None:
    if settings.IS_UNITTESTS:
        func()
        return

    transaction.on_commit(func)
