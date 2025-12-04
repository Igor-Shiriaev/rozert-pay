from typing import Any

from django.db.models import QuerySet
from drf_spectacular.utils import extend_schema
from rest_framework import viewsets
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.status import HTTP_201_CREATED
from rest_framework.throttling import SimpleRateThrottle
from rest_framework.views import APIView
from rest_framework.viewsets import mixins  # type: ignore
from rozert_pay.common import const, types
from rozert_pay.common.const import PaymentSystemType
from rozert_pay.payment import factories, tasks
from rozert_pay.payment import types as payment_types
from rozert_pay.payment.api_v1 import serializers
from rozert_pay.payment.api_v1.serializers import TransactionResponseSerializer
from rozert_pay.payment.models import (
    IncomingCallback,
    Merchant,
    PaymentSystem,
    PaymentTransaction,
    Wallet,
)
from rozert_pay.payment.services import base_classes, deposit_instructions, errors


@extend_schema(
    tags=["Wallet"],
)
class WalletViewSet(
    viewsets.GenericViewSet,
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
):
    request: types.AuthorizedRequest

    serializer_class = serializers.WalletSerializer
    permission_classes = []
    authentication_classes = []

    def get_queryset(self) -> QuerySet[Wallet]:
        if getattr(self, "swagger_fake_view", False):
            return Wallet.objects.none()
        return Wallet.objects.filter(merchant=self.request.auth.merchant)

    @extend_schema(summary="List wallets")
    def list(self, request: Request) -> Response:
        return super().list(request)

    @extend_schema(
        summary="Get wallet by ID",
    )
    def retrieve(self, request: Request, pk: int) -> Response:
        return super().retrieve(request, pk=pk)


class GenericPaymentSystemApiV1Mixin:
    # Should be first in MRO
    request: types.AuthorizedRequest

    permission_classes = []
    authentication_classes = []

    def get_serializer_context(self) -> dict[str, Any]:
        if getattr(self, "swagger_fake_view", False):
            return {}

        return {"merchant": Merchant.objects.get()}

    def _generic_deposit(
        self,
        data: dict[str, Any],
        serializer_class: type[
            serializers.DepositTransactionRequestSerializer
        ] = serializers.DepositTransactionRequestSerializer,
    ) -> Response:
        serializer: serializers.DepositTransactionRequestSerializer = serializer_class(
            data=data,
            context=self.get_serializer_context(),
        )
        serializer.is_valid(raise_exception=True)
        instance = serializer.create(serializer.validated_data)
        return Response(
            TransactionResponseSerializer(
                instance=instance,
            ).data,
            status=HTTP_201_CREATED,
        )

    def _generic_withdraw(
        self,
        data: dict[str, Any],
        serializer_class: type[serializers.WithdrawalTransactionRequestSerializer],
    ) -> Response:
        serializer = serializer_class(
            data=data,
            context=self.get_serializer_context(),
        )
        serializer.is_valid(raise_exception=True)
        trx = serializer.create(serializer.validated_data)
        response_data = TransactionResponseSerializer(instance=trx).data
        return Response(response_data, status=201)

    def _generic_create_instruction(
        self,
        *,
        request: Request,
        account_creator: deposit_instructions.TAccountCreator,
        sandbox_client_cls: type[
            base_classes.BaseSandboxClientMixin[payment_types.T_Credentials]
        ],
        system_type: const.PaymentSystemType,
        serializer_class: type[
            serializers.RequestInstructionSerializer
        ] = serializers.RequestInstructionSerializer,
    ) -> Response:
        """
        Creates instruction for user.
        account_creator must be function which just creates account and returns it.
        All additional logic is performed in create_deposit_instruction
        """
        serializer = serializer_class(
            data=request.data,
        )
        serializer.is_valid(raise_exception=True)

        assert request.auth and isinstance(request.auth, types.AuthData)

        result = deposit_instructions.create_deposit_account_instruction(
            customer_id=serializer.validated_data["customer_id"],
            wallet_uuid=serializer.validated_data["wallet_id"],
            merchant=request.auth.merchant,
            account_creator=account_creator,
            sandbox_client_cls=sandbox_client_cls,
            system_type=system_type,
        )
        if isinstance(result, errors.Error):
            raise ValidationError

        s = serializers.DepositAccountInstructionResponseSerializer(
            data={
                "type": const.InstructionType.INSTRUCTION_DEPOSIT_ACCOUNT,
                "deposit_account": result.deposit_account_number,
                "customer_id": result.customer.uuid,
            }
        )
        s.is_valid(raise_exception=True)
        return Response(s.data)


@extend_schema(
    tags=["Transactions"],
)
class TransactionViewSet(
    GenericPaymentSystemApiV1Mixin,
    viewsets.GenericViewSet,
    mixins.ListModelMixin,
    mixins.CreateModelMixin,
    mixins.RetrieveModelMixin,
):
    request: types.AuthorizedRequest
    lookup_field = "uuid"
    serializer_class = serializers.TransactionResponseSerializer
    permission_classes = []
    authentication_classes = []

    def get_queryset(self) -> QuerySet[PaymentTransaction]:
        if getattr(self, "swagger_fake_view", False):
            return PaymentTransaction.objects.none()

        return PaymentTransaction.objects.filter(
            wallet__wallet__merchant=self.request.auth.merchant
        )

    @extend_schema(
        exclude=True,
    )
    def create(self, request: Request) -> Response:
        return self._generic_deposit(request.data)

    @extend_schema(
        summary="List transactions",
    )
    def list(self, request: Request) -> Response:
        return super().list(request)

    @extend_schema(
        summary="Get transaction by ID",
    )
    def retrieve(self, request: Request, **kwargs) -> Response:  # type: ignore[no-untyped-def]
        return super().retrieve(request, **kwargs)


class CallbackThrottle(SimpleRateThrottle):
    scope = "callback"
    rate = "100/minute"

    def get_cache_key(self, request: Request, view: APIView) -> str:
        # system parameter from URL
        return view.kwargs["system"]

    def get_rate(self) -> str | None:
        return "1/minute"


@extend_schema(
    exclude=True,
)
class CallbackView(APIView):
    throttle_classes = [CallbackThrottle]
    authentication_classes = []

    def post(self, request: Request, system: str) -> Response:
        db_system: PaymentSystem = PaymentSystem.objects.get(slug=system)
        cb = IncomingCallback.objects.create(
            system=db_system,
            body=request.body.decode(),
            get_params=request.query_params,
            ip=request.META.get("HTTP_X_REAL_IP")
            or request.META.get("REMOTE_ADDR", ""),
            headers={key.lower(): value for key, value in request.headers.items()},
        )
        result = tasks.handle_incoming_callback(cb.id)
        return result


@extend_schema(
    exclude=True,
)
class RedirectView(APIView):
    throttle_classes = [CallbackThrottle]
    authentication_classes = []

    def post(self, request: Request, system: str) -> Response:
        controller = factories.get_payment_system_controller_by_type(
            PaymentSystemType(system)
        )
        return controller.handle_redirect(request)
