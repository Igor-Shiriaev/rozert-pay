from typing import TypeVar

from django.core.exceptions import ValidationError
from django.db.models import Model, Q, QuerySet
from rozert_pay.payment.services import errors

T = TypeVar("T", bound=Model)


def filter_by_uuid_prefix(
    qs: "QuerySet[T]",
    value: str,
    column: str = "uuid",
) -> list[T] | errors.Error:
    value = value.replace("-", "")

    uuid_size = 32
    min_range = value + "0" * (uuid_size - len(value))
    max_range = value + "f" * (uuid_size - len(value))

    query = Q(**{f"{column}__range": (min_range, max_range)})

    try:
        return [
            item
            for item in qs.filter(query)
            if getattr(item, column).hex.startswith(value)
        ]
    except ValidationError as e:
        return errors.Error(
            f"Validation error: {e}",
        )
