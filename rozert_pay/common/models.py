import uuid
from typing import Any

from django.db import models


class PrimaryKeyField(models.UUIDField):  # type: ignore[type-arg]
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs["max_length"] = 36
        kwargs["primary_key"] = True
        kwargs["unique"] = True
        kwargs["default"] = uuid.uuid4
        super().__init__(*args, **kwargs)


class BaseDjangoModel(models.Model):
    id = models.BigAutoField(primary_key=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True
