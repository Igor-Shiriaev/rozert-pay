import logging
import typing as ty
from decimal import Decimal
from typing import Any, cast

from django.db import transaction
from django.utils.translation import gettext as _
from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers
from rozert_pay.common import const
from rozert_pay.common.const import TransactionType
from rozert_pay.payment.api_v1.serializers.user_data_serializers import (
    UserDataSerializer,
    UserDataSerializerOptional,
)
from rozert_pay.payment.factories import get_payment_system_controller
from rozert_pay.payment.models import (
    CurrencyWallet,
    DepositAccount,
    PaymentTransaction,
    Wallet,
)
from rozert_pay.payment.services import db_services

logger = logging.getLogger(__name__)


class BalanceSerializer(serializers.Serializer):
    currency = serializers.CharField()
    operational_balance = serializers.DecimalField(max_digits=15, decimal_places=2)
    frozen_balance = serializers.DecimalField(max_digits=15, decimal_places=2)
    pending_balance = serializers.DecimalField(max_digits=15, decimal_places=2)
    available_balance = serializers.DecimalField(max_digits=15, decimal_places=2)


class WalletSerializer(serializers.Serializer):
    id = serializers.CharField(read_only=True, source="uuid")
    created_at = serializers.DateTimeField(read_only=True)
    updated_at = serializers.DateTimeField(read_only=True)
    balances = serializers.SerializerMethodField()

    @extend_schema_field(field=BalanceSerializer(many=True))
    def get_balances(self, obj: Wallet) -> dict[str, ty.Any]:
        return BalanceSerializer(obj.currencywallet_set.all(), many=True).data


class RequestInstructionSerializer(serializers.Serializer):
    customer_id = serializers.CharField(
        required=True,
        help_text="Unique customer identificator",
    )
    wallet_id = serializers.UUIDField(
        required=True,
        help_text="Merchant wallet ID",
    )


class InstructionSerializer(serializers.Serializer):
    type = serializers.ChoiceField(
        choices=const.InstructionType.choices,
        help_text="""
Instruction type:

* **instruction_file** - File should be downloaded from `link` and given to user.
  User makes deposit according to instruction in file.

* **instruction_qr_code** - QR code should be shown to user. QR code in response is base64 encoded.

* **instruction_reference** - Reference number should be shown to user. User makes deposit using this reference number.
        """,
    )
    link = serializers.URLField(
        required=False,
    )
    qr_code = serializers.CharField(
        help_text="Base64 encoded QR code",
        required=False,
    )
    reference = serializers.CharField(
        help_text="Reference number for deposit. For: INSTRUCTION_REFERENCE type.",
        required=False,
    )
    deposit_account = serializers.CharField(
        help_text="Deposit account number for customer",
        required=False,
    )

    def validate(self, attrs: dict[str, ty.Any]) -> dict[str, ty.Any]:
        if attrs["type"] == const.InstructionType.INSTRUCTION_FILE:
            if not attrs.get("link"):
                raise serializers.ValidationError(
                    {"link": _("This field is required.")}
                )
        elif attrs["type"] == const.InstructionType.INSTRUCTION_QR_CODE:
            if not attrs.get("qr_code"):
                raise serializers.ValidationError(
                    {"qr_code": _("This field is required.")}
                )
        elif attrs["type"] == const.InstructionType.INSTRUCTION_DEPOSIT_ACCOUNT:
            if not attrs.get("deposit_account"):
                raise serializers.ValidationError(
                    {"deposit_account": _("This field is required.")}
                )
        elif attrs["type"] == const.InstructionType.INSTRUCTION_REFERENCE:
            if not attrs.get("reference"):
                raise serializers.ValidationError(
                    {"reference": _("This field is required.")}
                )
        else:
            raise serializers.ValidationError({"type": _("Invalid instruction type.")})
        return attrs


class DepositAccountInstructionResponseSerializer(serializers.Serializer):
    deposit_account = serializers.CharField(
        help_text="Deposit account number for customer",
        required=True,
    )
    customer_id = serializers.UUIDField(
        help_text="Customer ID on Rozert side",
        required=True,
    )


class CommonTransactionSerializerMixin:
    validated_data: dict[str, ty.Any]
    context: dict[str, ty.Any]

    def to_representation(self, instance: PaymentTransaction) -> dict[str, ty.Any]:
        ret = super().to_representation(instance)  # type: ignore[misc]
        ret["wallet_id"] = str(instance.wallet.wallet.uuid)
        return ret

    def common_transaction_validation(self, attrs: dict[str, Any]) -> Wallet:
        wallet_id: str = attrs["wallet_id"]
        context_merchant_id: int = self.context["merchant"].id
        amount: Decimal = attrs["amount"]

        wallet = Wallet.objects.filter(uuid=wallet_id).first()
        if not wallet:
            raise serializers.ValidationError({"wallet_id": _("Wallet not found")})

        if wallet.merchant_id != context_merchant_id:
            logger.error(
                "merchant requested wallet he does not own",
                extra={
                    "wallet_id": wallet_id,
                    "merchant_id": context_merchant_id,
                },
            )
            raise serializers.ValidationError({"wallet_id": _("Wallet not found")})

        if amount <= 0:
            raise serializers.ValidationError(
                {"amount": _("Amount must be greater than 0.")}
            )

        return wallet


class DepositTransactionRequestSerializer(  # type: ignore[misc]
    serializers.Serializer, CommonTransactionSerializerMixin
):
    wallet_id = serializers.UUIDField(
        help_text="Wallet ID. Will be provided by rozert."
    )

    # TODO: check customer_id in response. Check deposit response
    # TODO: split to external customer id and customer id
    customer_id = serializers.CharField(
        required=False,
        allow_null=True,
        allow_blank=True,
        help_text="External customer id",
    )
    amount = serializers.DecimalField(max_digits=12, decimal_places=2)
    currency = serializers.CharField(max_length=3)
    redirect_url = serializers.URLField(
        required=False,
        allow_null=True,
        allow_blank=True,
        help_text="Redirect URL for payment system to redirect user after payment.",
    )
    callback_url = serializers.URLField(
        required=False,
        allow_null=True,
        allow_blank=True,
        help_text="Callback url for payment system",
    )

    @transaction.atomic
    def validate(self, attrs: dict[str, ty.Any]) -> dict[str, ty.Any]:
        wallet = self.common_transaction_validation(attrs)

        attrs["type"] = TransactionType.DEPOSIT

        if ps := get_payment_system_controller(wallet.system):
            ps.validate_transaction_attrs(attrs, self.context)

        return attrs

    @transaction.atomic
    def create(self, validated_data: dict[str, ty.Any]) -> PaymentTransaction:
        *_, trx = db_services.create_transaction(
            wallet_id=validated_data["wallet_id"],
            amount=validated_data["amount"],
            currency=validated_data["currency"],
            callback_url=validated_data.get("callback_url"),
            redirect_url=validated_data.get("redirect_url"),
            type=TransactionType.DEPOSIT,
            merchant_id=self.context["merchant"].id,
            user_data=validated_data.get("user_data"),
            card_data=validated_data.get("card"),
            customer_id=validated_data.get("customer_id"),
            extra=self._get_extra(),
            customer_external_account_number=None,
        )

        controller = get_payment_system_controller(trx.system)
        assert controller
        controller.on_db_transaction_created_via_api(trx)
        return trx

    def _get_extra(self) -> dict[str, Any]:
        return {f: self.validated_data[f] for f in self._get_extra_fields()}

    def _get_extra_fields(self) -> list[str]:
        return []


class WithdrawalTransactionRequestSerializer(  # type: ignore[misc]
    serializers.Serializer, CommonTransactionSerializerMixin
):
    wallet_id = serializers.UUIDField()

    customer_id = serializers.CharField(
        required=False,
        allow_null=True,
        allow_blank=True,
        help_text="Customer ID. Required for deposits for: SPEI_STP",
    )
    amount = serializers.DecimalField(max_digits=12, decimal_places=2)
    currency = serializers.CharField(max_length=3)
    withdraw_to_account = serializers.CharField()
    redirect_url = serializers.URLField(
        required=False,
        allow_null=True,
        allow_blank=True,
        help_text="Redirect URL for payment system to redirect user after payment.",
    )
    callback_url = serializers.URLField(
        required=False,
        allow_null=True,
        allow_blank=True,
        help_text="Callback url for payment system",
    )
    user_data = UserDataSerializerOptional(allow_null=True, required=False)

    @transaction.atomic
    def validate(self, attrs: dict[str, ty.Any]) -> dict[str, ty.Any]:
        wallet = self.common_transaction_validation(attrs)

        if not wallet.allow_negative_balances:
            currency_wallet = (
                CurrencyWallet.objects.select_for_update()
                .filter(wallet=wallet, currency=attrs.get("currency"))
                .first()
            )

            if (
                not currency_wallet
                or currency_wallet.available_balance < attrs["amount"]
            ):
                raise serializers.ValidationError({"amount": _("Insufficient funds.")})

        if ps := get_payment_system_controller(wallet.system):
            ps.validate_transaction_attrs(attrs, self.context)

        return attrs

    @transaction.atomic
    def create(self, validated_data: dict[str, ty.Any]) -> PaymentTransaction:
        wallet, currency_wallet, trx = db_services.create_transaction(
            wallet_id=validated_data["wallet_id"],
            amount=validated_data["amount"],
            currency=validated_data["currency"],
            callback_url=validated_data.get("callback_url"),
            redirect_url=validated_data.get("redirect_url"),
            type=TransactionType.WITHDRAWAL,
            merchant_id=self.context["merchant"].id,
            user_data=validated_data.get("user_data"),
            customer_external_account_number=validated_data.get("withdraw_to_account"),
            card_data=validated_data.get("card"),
            customer_id=validated_data.get("customer_id"),
            extra=self._get_extra(),
        )

        self.on_transaction_created(cast("db_services.LockedTransaction", trx))

        controller = get_payment_system_controller(trx.system)
        assert controller
        controller.on_db_transaction_created_via_api(trx)

        return trx

    def on_transaction_created(self, trx: "db_services.LockedTransaction") -> None:
        """Hook for subclasses to perform actions after transaction creation."""
        pass

    def _get_extra(self) -> dict[str, Any]:
        return {f: self.validated_data[f] for f in self._get_extra_fields()}

    def _get_extra_fields(self) -> list[str]:
        return []


class FormDataSerializer(serializers.Serializer):
    action_url = serializers.URLField(
        help_text="URL to send form data to / redirect user."
    )
    method = serializers.ChoiceField(
        choices=["get", "post"],
        help_text="Method to send form data. "
        "If get - user should be redirected, if post - "
        "form data from `fields` should be submitted.",
    )
    fields = serializers.DictField(
        help_text="Form fields to send to payment system. In case of POST method"
    )  # type: ignore[assignment]


class TransactionResponseSerializer(serializers.Serializer):
    id = serializers.CharField(source="uuid")

    status = serializers.ChoiceField(choices=const.TransactionStatus.choices)
    decline_code = serializers.CharField()
    decline_reason = serializers.CharField()
    created_at = serializers.DateTimeField()
    updated_at = serializers.DateTimeField()
    instruction = InstructionSerializer(
        required=False,
        allow_null=True,
        help_text=f"Instruction for customer",
    )
    callback_url = serializers.URLField(
        required=False,
        allow_null=True,
        allow_blank=True,
        help_text="Callback URL for payment system to notify about transaction status change.",
    )
    customer_id = serializers.CharField(
        required=False,
        allow_null=True,
        allow_blank=True,
        help_text="Internal customer ID",
    )
    external_customer_id = serializers.CharField(
        required=False,
        allow_null=True,
        allow_blank=True,
        help_text="External customer ID (provided by merchant)",
    )
    type = serializers.ChoiceField(choices=const.TransactionType.choices)

    currency = serializers.CharField()
    amount = serializers.DecimalField(max_digits=12, decimal_places=2)

    form = FormDataSerializer(
        required=False,
        allow_null=True,
        help_text="Form data for redirecting user to payment system. If presented, merchant customer should be "
        "redirected or form data must be submitted.",
    )
    external_account_id = serializers.CharField(
        required=False,
        allow_null=True,
        help_text="External account of user performed deposit. Payment system specific.",
    )
    user_data = UserDataSerializer(allow_null=True, required=False)

    card_token = serializers.CharField(
        required=False,
        allow_null=True,
        help_text="For card payment systems, this is the token of the card used for deposit."
        "You should store this token and use it for withdrawals when needed.",
    )

    def to_representation(self, instance: PaymentTransaction) -> dict[str, ty.Any]:
        ret = super().to_representation(instance)
        ret["wallet_id"] = str(instance.wallet.wallet.uuid)
        if instance.customer_card_id:
            assert instance.customer_card
            ret["card_token"] = str(instance.customer_card.uuid)

        if instance.customer_id:
            assert instance.customer
            ret["customer_id"] = str(instance.customer.uuid)
            ret["external_customer_id"] = str(instance.customer.external_id)

        if instance.customer_external_account_id and instance.customer_external_account:
            ret["external_account_id"] = str(
                instance.customer_external_account.unique_account_number
            )

        return ret


class BaseAccountSerializer(serializers.ModelSerializer):
    deposit_account = serializers.SerializerMethodField(
        help_text="Deposit account for customer. "
        "Ask customer to make deposit using this account."
    )
    wallet_id = serializers.UUIDField()

    def to_representation(self, instance: DepositAccount) -> dict[str, ty.Any]:
        ret = super().to_representation(instance)
        ret["wallet_id"] = str(instance.wallet.uuid)
        return ret

    def get_deposit_account(self, obj: DepositAccount) -> str:
        raise NotImplementedError

    class Meta:
        model = DepositAccount
        read_only_fields = (
            "id",
            "created_at",
            "deposit_account",
        )
        fields = (
            *read_only_fields,
            "wallet_id",
            "customer_id",
        )
