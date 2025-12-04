import typing as ty
from typing import cast
from uuid import UUID

from rozert_pay.common import const
from rozert_pay.payment import models, types
from rozert_pay.payment.services import base_classes, db_services, errors, event_logs

__all__ = [
    "create_deposit_account_instruction",
]


class _TAccount(ty.Protocol):
    wallet_account: str
    customer_uuid: UUID


class TAccountCreator(ty.Protocol):
    def __call__(
        self,
        *,
        external_customer_id: types.ExternalCustomerId,
        wallet: models.Wallet,
        creds: types.T_Credentials,
    ) -> str | errors.Error:
        pass


@errors.wrap_errors
def create_deposit_account_instruction(
    *,
    customer_id: types.ExternalCustomerId,
    wallet_uuid: UUID,
    merchant: models.Merchant,
    account_creator: TAccountCreator,
    sandbox_client_cls: type[base_classes.BaseSandboxClientMixin[types.T_Credentials]],
    system_type: const.PaymentSystemType,
) -> models.CustomerDepositInstruction | errors.Error:
    instructions_in_db = list(
        models.CustomerDepositInstruction.objects.filter(
            wallet__uuid=wallet_uuid,
            wallet__merchant=merchant,
            customer__external_id=customer_id,
            system_type=system_type,
        ).select_related("customer")
    )
    assert (
        len(instructions_in_db) <= 1
    ), f"Expected at most one deposit instruction, but found {instructions_in_db}"

    if instructions_in_db:
        return instructions_in_db[0]

    wallet = db_services.get_wallet(
        merchant=merchant,
        wallet_uuid=wallet_uuid,
    )

    customer_wallet_account = account_creator(
        external_customer_id=customer_id,
        wallet=wallet,
        creds=sandbox_client_cls.credentials_cls(**wallet.credentials),
    )
    if isinstance(customer_wallet_account, errors.Error):
        return customer_wallet_account

    customer_instruction = db_services.create_customer_deposit_instruction(
        system_type=system_type,
        external_customer_id=customer_id,
        deposit_account_number=customer_wallet_account,
        wallet=wallet,
    )

    event_logs.create_event_log(
        event_type=const.EventType.CREATE_DEPOSIT_INSTRUCTION,
        description="Created new deposit instruction",
        extra={
            "customer_id": str(customer_instruction.customer_id),
            "deposit_account": customer_instruction.deposit_account_number,
        },
        system_type=system_type,
        customer_id=cast(types.CustomerId, customer_instruction.customer_id),
        merchant_id=merchant.id,
    )

    if wallet.merchant.sandbox:
        sandbox_client_cls.post_create_instruction(customer_instruction)

    return customer_instruction
