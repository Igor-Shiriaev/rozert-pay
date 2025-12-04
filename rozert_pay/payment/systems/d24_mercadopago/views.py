from typing import Any

from drf_spectacular.utils import extend_schema
from rest_framework import serializers, viewsets
from rest_framework.decorators import action
from rest_framework.request import Request
from rest_framework.response import Response
from rozert_pay.common.const import TransactionExtraFields
from rozert_pay.common.helpers.validation_mexico import (
    validate_clabe,
    validate_mexican_curp,
)
from rozert_pay.payment.api_v1.serializers import (
    DepositTransactionRequestSerializer,
    WithdrawalTransactionRequestSerializer,
    user_data_serializer_mixin_factory,
)
from rozert_pay.payment.api_v1.serializers.user_data_serializers import (
    custom_user_data_serializer,
)
from rozert_pay.payment.api_v1.views import GenericPaymentSystemApiV1Mixin


class D24MercadoPagoTransactionExtraFields(TransactionExtraFields):
    MEXICAN_CURP = "mexican_curp"


class D24MercadoPagoDepositSerializer(  # type: ignore[misc]
    DepositTransactionRequestSerializer,
    user_data_serializer_mixin_factory(  # type: ignore[misc]
        "D24MercadoPagoDepositUserData",
        required_fields=["country", "phone", "email", "first_name", "last_name"],
    ),
):
    mexican_curp = serializers.CharField(
        required=True,
        max_length=18,
        min_length=18,
    )
    redirect_url = serializers.URLField(required=True)

    def validate_mexican_curp(self, value: str) -> str:
        try:
            return validate_mexican_curp(value)
        except ValueError as error:
            raise serializers.ValidationError(str(error))

    def _get_extra(self) -> dict[str, Any]:
        return {
            D24MercadoPagoTransactionExtraFields.MEXICAN_CURP: self.validated_data[
                "mexican_curp"
            ]
        }


class D24MercadoPagoWithdrawSerializer(  # type: ignore[misc]
    WithdrawalTransactionRequestSerializer,
):
    mexican_curp = serializers.CharField(
        required=True,
        max_length=18,
        min_length=18,
    )
    withdraw_to_account = serializers.CharField(
        required=True,
        max_length=18,
        min_length=18,
        help_text="CLABE",
    )
    user_data = custom_user_data_serializer(  # type: ignore[assignment]
        "D24MercadoPagoWithdrawUserData",
        required_fields=["country", "first_name", "last_name"],
    )

    def validate_mexican_curp(self, value: str) -> str:
        try:
            return validate_mexican_curp(value)
        except ValueError as error:
            raise serializers.ValidationError(str(error))

    def validate_withdraw_to_account(self, value: str) -> str:
        try:
            return validate_clabe(value)
        except ValueError as error:
            raise serializers.ValidationError(str(error))

    def _get_extra(self) -> dict[str, Any]:
        return {
            D24MercadoPagoTransactionExtraFields.MEXICAN_CURP: self.validated_data[
                "mexican_curp"
            ],
        }


@extend_schema(
    tags=["D24 MercadoPago"],
)
class D24MercadoPagoViewSet(  # type: ignore[misc]
    GenericPaymentSystemApiV1Mixin,
    viewsets.GenericViewSet,
):
    @extend_schema(
        operation_id="Create deposit transaction",
        request=D24MercadoPagoDepositSerializer,
    )
    @action(detail=False, methods=["post"])
    def deposit(self, request: Request) -> Response:
        return self._generic_deposit(
            request.data,
            serializer_class=D24MercadoPagoDepositSerializer,
        )

    @extend_schema(
        operation_id="Create withdrawal transaction",
        request=D24MercadoPagoWithdrawSerializer,
    )
    @action(detail=False, methods=["post"])
    def withdraw(self, request: Request) -> Response:
        return self._generic_withdraw(
            request.data,
            serializer_class=D24MercadoPagoWithdrawSerializer,
        )
