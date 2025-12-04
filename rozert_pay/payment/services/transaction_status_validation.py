import contextlib
import typing as ty
from decimal import Decimal
from typing import cast

from django.conf import settings
from rozert_pay.common import const
from rozert_pay.payment import entities
from rozert_pay.payment.models import PaymentTransaction
from rozert_pay.payment.services import db_services, errors


class CleanRemoteTransactionStatus(entities.RemoteTransactionStatus):
    # Type to ensure remote status is properly validated in all necessary places
    pass


def validate_remote_transaction_status(
    transaction: PaymentTransaction | None,
    remote_status: entities.RemoteTransactionStatus,
) -> CleanRemoteTransactionStatus | errors.Error:
    if not transaction:
        raise ValueError("Transaction is not provided")

    if remote_status.operation_status != const.TransactionStatus.PENDING:
        if (
            not transaction.id_in_payment_system
            and not remote_status.id_in_payment_system
        ):
            return errors.Error("Transaction ID in payment system is not provided")

    if remote_status.operation_status in [
        const.TransactionStatus.FAILED,
    ]:
        if not remote_status.decline_code:
            return errors.Error(
                "Decline code is not provided for failed/refunded final status"
            )

    if err := _validate_status(transaction, remote_status):
        return err
    if err := _validate_amounts(transaction, remote_status):
        return err

    return cast(CleanRemoteTransactionStatus, remote_status)


def _validate_status(
    transaction: PaymentTransaction, remote_status: entities.RemoteTransactionStatus
) -> errors.Error | None:
    if transaction.status != const.TransactionStatus.PENDING:
        if (
            transaction.status != remote_status.operation_status
            and not __disable_final_status_validation
        ):
            return errors.Error(
                f"Final transaction status mismatch: {transaction.status} != {remote_status.operation_status}"
            )

    return None


__disable_final_status_validation = False


@contextlib.contextmanager
def disable_final_status_validation() -> ty.Generator[None, None, None]:
    assert not settings.IS_PRODUCTION
    global __disable_final_status_validation
    __disable_final_status_validation = True
    try:
        yield
    finally:
        __disable_final_status_validation = False


def is_final_status_validation_enabled() -> bool:
    return not __disable_final_status_validation


class TransactionAmountValidation:
    @classmethod
    def bypass_amount_validation_for_transaction(
        cls,
        trx: "db_services.LockedTransaction",
        bypass_amount_validation_for: list[const.TransactionType],
    ) -> None:
        if not bypass_amount_validation_for:
            return

        assert trx.type in bypass_amount_validation_for
        trx.extra[
            const.TransactionExtraFields.BYPASS_AMOUNT_VALIDATION_FOR
        ] = bypass_amount_validation_for
        trx.save_extra()


def _validate_amounts(
    transaction: PaymentTransaction,
    remote_status: entities.RemoteTransactionStatus,
) -> errors.Error | None:
    should_validate = (
        transaction.type == const.TransactionType.DEPOSIT
        and remote_status.operation_status == const.TransactionStatus.SUCCESS
    ) or (
        transaction.type == const.TransactionType.WITHDRAWAL
        and remote_status.operation_status
        in [const.TransactionStatus.SUCCESS, const.TransactionStatus.FAILED]
    )

    if not should_validate:
        return None

    bypass_amount_validation = transaction.type in transaction.extra.get(
        const.TransactionExtraFields.BYPASS_AMOUNT_VALIDATION_FOR, []
    )
    if bypass_amount_validation:
        return None

    if not remote_status.remote_amount:
        return errors.Error("Remote amount is not provided")

    try:
        if abs((transaction.money - remote_status.remote_amount).value) >= Decimal(
            "0.01"
        ):
            return errors.Error(
                f"Amount mismatch: {transaction.amount} != {remote_status.remote_amount.value}"
            )
    except AssertionError as e:
        return errors.Error(str(e))

    return None


def bypass_validation(
    remote_status: entities.RemoteTransactionStatus,
) -> CleanRemoteTransactionStatus:
    """
    Use this method with caution, only if transaction was not really executed (i.e. fail by timeout)
    """
    return cast(CleanRemoteTransactionStatus, remote_status)
