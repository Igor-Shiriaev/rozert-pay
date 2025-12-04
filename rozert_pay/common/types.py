from typing import Any
from uuid import UUID

from rest_framework import request


class Request(request.Request):
    auth: dict | None


class AuthorizedRequest(request.Request):
    auth: dict


def to_uuid(value: str | UUID) -> UUID:
    if isinstance(value, UUID):
        return value
    return UUID(value)


def to_any(value: Any) -> Any:
    return value
