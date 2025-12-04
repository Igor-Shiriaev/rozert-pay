import hashlib
import json
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Literal, cast, overload
from uuid import UUID

from django.db.models import QuerySet
from rozert_pay.common import const
from rozert_pay.payment import entities, models, types
from rozert_pay.payment.entities import CardData, UserData
from rozert_pay.payment.models import (
    CurrencyWallet,
    CustomerCard,
    CustomerExternalPaymentSystemAccount,
    PaymentTransaction,
    Wallet,
)
from rozert_pay.payment.services import customers

if TYPE_CHECKING:  # pragma: no cover

    class LockedTransaction(PaymentTransaction):
        _is_transaction_locked_for_update: bool


@overload
def get_transaction(
    *,
    for_update: Literal[True],
    trx_id: int | None = None,
    join_wallet: bool = False,
    system_type: const.PaymentSystemType | None = None,
    trx_uuid: UUID | None = None,
    id_in_payment_system: str | None = None,
) -> "LockedTransaction":
    ...


@overload
def get_transaction(
    *,
    for_update: Literal[False],
    trx_id: int | None = None,
    join_wallet: bool = False,
    system_type: const.PaymentSystemType | None = None,
    trx_uuid: UUID | None = None,
    id_in_payment_system: str | None = None,
) -> PaymentTransaction:
    ...


def get_transaction(
    *,
    for_update: bool,
    # TODO: use types.TransactionId here
    trx_id: int | None = None,
    join_wallet: bool = False,
    system_type: const.PaymentSystemType | None = None,
    trx_uuid: UUID | None = None,
    id_in_payment_system: str | None = None,
) -> PaymentTransaction:
    assert trx_id or trx_uuid or id_in_payment_system
    if id_in_payment_system:
        # Index (system_type, id_in_payment_system) should be used
        assert system_type

    qs = PaymentTransaction.objects.all()
    if for_update:
        qs = qs.select_for_update()

    if trx_id:
        qs = qs.filter(id=trx_id)

    if trx_uuid:
        qs = qs.filter(uuid=trx_uuid)

    if join_wallet:
        qs = qs.select_related("wallet")

    if id_in_payment_system:
        qs = qs.filter(
            id_in_payment_system=id_in_payment_system,
            system_type=system_type,
        )

    trx = qs.get()

    if for_update:
        cast("LockedTransaction", trx)._is_transaction_locked_for_update = True
    return trx


def create_transaction(
    wallet_id: str | int,
    merchant_id: int,
    currency: str,
    amount: Decimal,
    type: const.TransactionType,
    callback_url: str | None,
    redirect_url: str | None,
    customer_external_account_number: str | None,
    user_data: dict[str, Any] | None,
    card_data: dict[str, Any] | None,
    customer_id: types.ExternalCustomerId | None = None,
    extra: dict[str, Any] | None = None,
    id_in_payment_system: str | None = None,

    customer_instruction: models.CustomerDepositInstruction | None = None,
) -> tuple[Wallet, CurrencyWallet, PaymentTransaction]:
    """
    Create a transaction in the database.
    Creates a wallet for currency if it does not exist.
    Returned CurrencyWallet is locked for update.
    """
    wallet_qs = Wallet.objects.select_related("system").filter(
        merchant_id=merchant_id,
    )
    if isinstance(wallet_id, (str, UUID)):
        wallet = wallet_qs.get(uuid=wallet_id)
    else:
        wallet = wallet_qs.get(id=wallet_id)

    system_type = wallet.system.type

    customer_account: models.CustomerExternalPaymentSystemAccount | None = None

    customer: models.Customer | None = None
    if customer_id:
        customer = customers.get_or_create_customer(
            external_identity=customer_id,
            user_data=UserData(**user_data) if user_data else None,
        )

    if customer_external_account_number:
        customer_account = find_customer_external_account_by_number(
            account_number=customer_external_account_number,
            system_type=system_type,
        )
        if not customer_account:
            assert customer
            customer_account = (
                CustomerExternalPaymentSystemAccount.objects.get_or_create(
                    system_type=system_type,
                    wallet=wallet,
                    customer_id=customer.id,
                    unique_account_number=customer_external_account_number,
                )[0]
            )
        else:
            customer = customer_account.customer

    if customer_instruction:
        assert customer_instruction.wallet == wallet
        if customer:
            assert customer_instruction.customer == customer

    currency_wallet = (
        CurrencyWallet.objects.filter(
            wallet=wallet,
            currency=currency,
        )
        .select_for_update()
        .first()
    )
    if not currency_wallet:
        currency_wallet = CurrencyWallet.objects.create(
            wallet=wallet,
            currency=currency,
        )

    assert currency_wallet.currency == currency

    # Create customer card if presented
    customer_card: models.CustomerCard | None = None
    if card_data:
        assert customer
        if (card_token := card_data.pop("card_token", None)) and card_token is not None:
            assert (
                not card_data
            ), "if card_token is set, card_data must contain only card_token"
            customer_card = get_card_by_token(customer.external_id, card_token)
        else:
            customer_card = create_card(customer=customer, data=CardData(**card_data))

    return (
        wallet,
        currency_wallet,
        PaymentTransaction.objects.create(
            wallet=currency_wallet,
            amount=amount,
            type=type,
            currency=currency,
            system_type=wallet.system.type,
            callback_url=callback_url,
            redirect_url=redirect_url,
            customer_id=customer.id if customer else None,
            customer_card=customer_card,
            customer_external_account=customer_account,
            customer_instruction=customer_instruction,
            id_in_payment_system=id_in_payment_system,
            extra={
                "user_data": json.loads(UserData(**user_data).model_dump_json())
                if user_data
                else None,
                **(extra or {}),
            },
        ),
    )


def save_extra_field(trx_id: types.TransactionId, field: str, value: Any) -> None:
    PaymentTransaction.objects.filter(id=trx_id).update(
        extra={field: value}
    )


def create_card(
    *,
    customer: models.Customer,
    data: entities.CardData,
) -> models.CustomerCard:
    unique_identity = (
        hashlib.sha512(data.card_num.get_secret_value().encode()).hexdigest().lower()
    )

    card, _ = models.CustomerCard.objects.update_or_create(
        unique_identity=unique_identity,
        customer=customer,
        defaults={
            "card_data": data.to_dict(),
        },
    )
    return card


def get_card_by_token(
    customer_external_id: str,
    card_token: str,
) -> models.CustomerCard:
    return CustomerCard.objects.get(
        customer__external_id=customer_external_id,
        uuid=card_token,
    )


def get_wallet(
    merchant: models.Merchant,
    wallet_uuid: str | UUID,
) -> Wallet:
    return Wallet.objects.get(
        merchant=merchant,
        uuid=wallet_uuid,
    )


def lock_currency_wallet(wallet_id: types.CurrencyWalletId) -> CurrencyWallet:
    return CurrencyWallet.objects.select_for_update().get(id=wallet_id)


def create_customer_external_payment_system_account(
    *,
    external_customer_id: str,
    account_number: str,
    system_type: const.PaymentSystemType,
    wallet_id: types.WalletId,
) -> models.CustomerExternalPaymentSystemAccount:
    customer, _ = models.Customer.objects.get_or_create(
        external_id=external_customer_id,
    )
    return models.CustomerExternalPaymentSystemAccount.objects.create(
        unique_account_number=account_number,
        wallet_id=wallet_id,
        system_type=system_type,
        customer_id=customer.id,
        active=True,
    )


def create_customer_deposit_instruction(
    *,
    system_type: const.PaymentSystemType,
    external_customer_id: types.ExternalCustomerId,
    deposit_account_number: str,
    wallet: models.Wallet,
) -> models.CustomerDepositInstruction:
    return models.CustomerDepositInstruction.objects.create(
        system_type=system_type,
        customer=models.Customer.objects.get_or_create(
            external_id=external_customer_id,
        )[0],
        deposit_account_number=deposit_account_number,
        wallet=wallet,
    )


def filter_customer_external_payment_system_accounts(
    *,
    customer_external_id: str,
    system_type: const.PaymentSystemType,
    merchant_id: int | None,
) -> QuerySet[CustomerExternalPaymentSystemAccount]:
    qs = CustomerExternalPaymentSystemAccount.objects.filter(
        customer__external_id=customer_external_id,
        active=True,
        system_type=system_type,
    )

    if merchant_id:
        qs = qs.filter(wallet__merchant_id=merchant_id)

    return qs


def find_customer_external_account_by_number(
    *,
    account_number: str,
    system_type: const.PaymentSystemType,
) -> CustomerExternalPaymentSystemAccount | None:
    wallets = list(
        CustomerExternalPaymentSystemAccount.objects.filter(
            unique_account_number=account_number,
            active=True,
            system_type=system_type,
        ).select_related("customer", "wallet", "wallet__merchant")
    )
    assert (
        len(wallets) <= 1
    ), f"More than one wallet found for account number {account_number}"
    if wallets:
        return wallets[0]
    return None


def find_deposit_instruction_by_account(
    *,
    system_type: const.PaymentSystemType,
    deposit_account_number: str,
) -> models.CustomerDepositInstruction | None:
    # Uses unique index
    results = list(
        models.CustomerDepositInstruction.objects.filter(
            system_type=system_type,
            deposit_account_number=deposit_account_number,
        )
    )
    assert (
        len(results) <= 1
    ), f"More than one deposit instruction found for account number {deposit_account_number}"
    if results:
        return results[0]
    return None
