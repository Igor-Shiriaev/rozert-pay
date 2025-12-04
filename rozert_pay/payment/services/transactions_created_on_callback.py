import contextlib
import typing as ty
from typing import Generator, Optional, cast

from rozert_pay.common import const
from rozert_pay.common.const import CallbackType
from rozert_pay.payment.entities import Money
from rozert_pay.payment.services import db_services, errors
from rozert_pay.payment.systems import base_controller

ERROR_CODE_NO_CUSTOMER_INSTRUCTION = errors.ErrorCode("no_customer_instruction_found")


@contextlib.contextmanager
def process_transaction_creation_on_callback(
    *,
    deposit_instruction_account_number: str,
    deposited_from_account_number: Optional[str],
    system_type: const.PaymentSystemType,
    controller: base_controller.PaymentSystemController,  # type: ignore[type-arg]
    amount: Money,
    id_in_payment_system: str,
) -> Generator[ty.Union["db_services.LockedTransaction", errors.Error], None, None]:
    customer_instruction = db_services.find_deposit_instruction_by_account(
        system_type=system_type,
        deposit_account_number=deposit_instruction_account_number,
    )
    if not customer_instruction:
        yield errors.Error(
            "No customer instruction found", code=ERROR_CODE_NO_CUSTOMER_INSTRUCTION
        )
        return

    assert customer_instruction

    customer = customer_instruction.customer

    _, _, trx = db_services.create_transaction(
        wallet_id=customer_instruction.wallet_id,
        merchant_id=customer_instruction.wallet.merchant_id,
        currency=amount.currency,
        amount=amount.value,
        type=const.TransactionType.DEPOSIT,
        customer_id=customer.external_id,
        customer_external_account_number=deposited_from_account_number,
        customer_instruction=customer_instruction,
        callback_url=None,
        redirect_url=None,
        user_data=None,
        card_data=None,
        id_in_payment_system=id_in_payment_system,
    )

    controller.create_callback(
        trx_id=trx.id,
        callback_type=CallbackType.TRANSACTION_UPDATED,
    )

    yield cast("db_services.LockedTransaction", trx)
