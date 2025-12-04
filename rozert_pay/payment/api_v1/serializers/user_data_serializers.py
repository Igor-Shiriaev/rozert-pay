import typing as ty
import warnings
from copy import deepcopy
from typing import Literal

from rest_framework import serializers
from rest_framework.serializers import SerializerMetaclass
from rozert_pay.payment import entities


class UserDataSerializer(serializers.Serializer):
    email = serializers.EmailField(
        help_text="Customer email address",
    )
    phone = serializers.CharField()
    first_name = serializers.CharField()
    last_name = serializers.CharField()
    post_code = serializers.CharField()
    city = serializers.CharField()
    country = serializers.CharField()
    state = serializers.CharField(allow_null=True, allow_blank=True, required=False)
    address = serializers.CharField()
    language = serializers.CharField(
        help_text="Language code",
        max_length=10,
        required=False,
    )
    date_of_birth = serializers.DateField(
        format="%Y-%m-%d",
        allow_null=True,
        required=False,
    )
    ip_address = serializers.IPAddressField(
        allow_null=True,
        required=False,
    )
    province = serializers.CharField(
        allow_null=True,
        required=False,
    )


_UserDataSerializerKey = Literal[
    "email",
    "phone",
    "first_name",
    "last_name",
    "post_code",
    "city",
    "country",
    "state",
    "address",
    "language",
    "date_of_birth",
    "ip_address",
    "province",
]


assert set(ty.cast(ty.Any, _UserDataSerializerKey).__args__) == set(
    UserDataSerializer().get_fields().keys()
), "Keys in _UserDataSerializerKey must correspond to the fields of UserDataSerializer"


assert set(entities.UserData.__annotations__) == set(
    UserDataSerializer().get_fields().keys()
), "Fields in UserDataSerializer must correspond to the fields of UserData"


class UserDataSerializerMixin(serializers.Serializer):
    user_data = UserDataSerializer()


def custom_user_data_serializer(
    serializer_name: str,
    required_fields: list[_UserDataSerializerKey],
    required: bool = True,
    allow_null: bool = False,
) -> UserDataSerializer:
    declared_fields = deepcopy(UserDataSerializer._declared_fields)

    # Some magic, because Field.__deepcopy__ resets state from Field._args/._kwargs parameters from __init__ method
    for name, f in declared_fields.items():
        field = ty.cast(ty.Any, f)

        if name in required_fields:
            field.required = True
            field._kwargs["required"] = True
            field._kwargs["allow_null"] = False
        else:
            field.required = False
            field._kwargs["required"] = False
            field._kwargs["allow_null"] = True

    CustomUserDataSerializer = SerializerMetaclass(
        serializer_name,
        (serializers.Serializer,),
        deepcopy(declared_fields),
    )
    return CustomUserDataSerializer(required=required, allow_null=allow_null)


def user_data_serializer_mixin_factory(
    # serializer_name must be unique per usage, otherwise doc will be generated wrongly.
    serializer_name: str,
    required_fields: list[_UserDataSerializerKey],
) -> SerializerMetaclass:
    """
    Creates a subclass of UserDataSerializer with specified required fields.

    Args:
        required_fields: A set of fields that should be required.

    Returns:
        A subclass of UserDataSerializer with configured required fields.
    """
    warnings.warn("Use custom_user_data_serializer instead", DeprecationWarning)

    return SerializerMetaclass(
        "CustomUserDataSerializerMixin",
        (serializers.Serializer,),
        {
            "user_data": custom_user_data_serializer(serializer_name, required_fields),
        },
    )


class UserDataSerializerOptional(serializers.Serializer):
    email = serializers.EmailField(
        help_text="Customer email address",
        allow_null=True,
        required=False,
    )
    phone = serializers.CharField(
        allow_null=True,
        required=False,
    )
    first_name = serializers.CharField(
        allow_null=True,
        required=False,
    )
    last_name = serializers.CharField(
        allow_null=True,
        required=False,
    )
    post_code = serializers.CharField(
        allow_null=True,
        required=False,
    )
    city = serializers.CharField(
        allow_null=True,
        required=False,
    )
    country = serializers.CharField(
        allow_null=True,
        required=False,
    )
    state = serializers.CharField(allow_null=True, allow_blank=True, required=False)
    address = serializers.CharField(
        allow_null=True,
        required=False,
    )
    language = serializers.CharField(
        help_text="Language code",
        max_length=10,
        required=False,
    )
