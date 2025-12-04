import datetime
import logging
import time
import typing as ty
from datetime import timedelta

from django.db import connection, transaction
from django.utils import timezone
from django.utils.crypto import constant_time_compare
from rozert_pay.common import const
from rozert_pay.common.const import EventType, TransactionStatus
from rozert_pay.payment import entities, tasks, types
from rozert_pay.payment.models import CurrencyWallet, Wallet
from rozert_pay.payment.services import db_services, event_logs

logger = logging.getLogger(__name__)


def schedule_periodic_status_checks(
    trx: "db_services.LockedTransaction",
    until: datetime.datetime | None = None,
    schedule_check_immediately: bool = False,
) -> None:
    # tasks.check_status is the task which checks statuses
    until = until or timezone.now() + timedelta(
        seconds=trx.system.deposit_allowed_ttl_seconds
    )
    trx.check_status_until = until
    trx.save(update_fields=["check_status_until", "updated_at"])

    if schedule_check_immediately:
        tasks.check_status.delay(trx.id)


def handle_chargeback(
    trx: "db_services.LockedTransaction",
) -> None:
    ...


def handle_refund(
    trx: "db_services.LockedTransaction",
    refund_amount: entities.Money,
) -> None:
    ...


def handle_chargeback_reversal(
    trx: "db_services.LockedTransaction",
) -> None:
    ...


def validate_signature_for_callback(
    payment_system: const.PaymentSystemType,
    creds_cls: ty.Type[types.T_Credentials],
    signature_from_request: str,
    signature_for_creds_callable: ty.Callable[[types.T_Credentials], str],
) -> bool:
    logger.info(
        "validate signature",
        extra={
            "payment_system": payment_system,
        },
    )

    wallets: list[Wallet] = list(
        Wallet.objects.filter(
            system__type=payment_system,
        )
    )
    all_creds = []

    for w in wallets:
        try:
            all_creds.append(creds_cls(**w.credentials))
        except Exception:
            logger.exception(
                "Failed to parse credentials",
                extra={
                    "wallet_id": w.id,
                },
            )

    if not any(
        [
            constant_time_compare(
                signature_for_creds_callable(credentials),
                signature_from_request,
            )
            for credentials in all_creds
        ]
    ):
        return False
    return True


@transaction.atomic
def revert_to_pending(
    trx_id: types.TransactionId | "db_services.LockedTransaction",
) -> None:
    if isinstance(trx_id, int):
        trx = db_services.get_transaction(
            for_update=True,
            trx_id=trx_id,
            join_wallet=True,
        )
    else:
        assert isinstance(trx_id, db_services.PaymentTransaction)
        trx = trx_id
        # Lock wallet explicitly if the transaction object is passed directly
        CurrencyWallet.objects.select_for_update().get(id=trx.wallet_id)

    assert trx.status in [TransactionStatus.SUCCESS, TransactionStatus.FAILED]

    trx.status = TransactionStatus.PENDING
    trx.save(update_fields=["status", "updated_at"])

    event_logs.create_transaction_log(
        trx_id=trx.id,
        event_type=EventType.REVERT_TO_INITIAL,
        description=f"Transaction reverted to initial status from {trx.status}",
        extra={},
    )


def save_id_in_payment_system(
    trx: "db_services.LockedTransaction",
    remote_id_in_payment_system: str | None,
    save: bool = False,
) -> None:
    # Check/save id_in_payment_system
    if trx.id_in_payment_system is None:
        trx.id_in_payment_system = remote_id_in_payment_system
        if save:
            trx.save(update_fields=["id_in_payment_system", "updated_at"])

    elif remote_id_in_payment_system:
        assert trx.id_in_payment_system == remote_id_in_payment_system, (
            trx.id_in_payment_system,
            remote_id_in_payment_system,
        )


def stop_periodic_status_checks(trx: "db_services.LockedTransaction") -> None:
    assert connection.in_atomic_block
    trx.check_status_until = None
    trx.save(update_fields=["check_status_until", "updated_at"])


class TransactionPeriodicCheckService:
    @classmethod
    def _get_next_check_datetime(
        cls, trx_extra: dict[str, ty.Any]
    ) -> datetime.datetime:
        count_checks: int = trx_extra.get(
            const.TransactionExtraFields.COUNT_STATUS_CHECKS_SCHEDULED, 0
        )
        last_status_check_ts: float | None = trx_extra.get(
            const.TransactionExtraFields.LAST_STATUS_CHECK_SCHEDULE
        )
        last_status_check: datetime.datetime | None = (
            timezone.make_aware(datetime.datetime.fromtimestamp(last_status_check_ts))
            if last_status_check_ts
            else None
        )

        if not last_status_check:
            return timezone.now()

        CHECKS_EACH_MINUTE = 5
        CHECKS_EACH_5_MINUTES = CHECKS_EACH_MINUTE + 6
        CHECKS_EACH_15_MINUTES = CHECKS_EACH_5_MINUTES + 4

        if count_checks <= CHECKS_EACH_MINUTE:
            return last_status_check + timedelta(minutes=1)

        if count_checks <= CHECKS_EACH_5_MINUTES:
            return last_status_check + timedelta(minutes=5)

        if count_checks <= CHECKS_EACH_15_MINUTES:
            return last_status_check + timedelta(minutes=15)

        return last_status_check + timedelta(hours=1)

    @classmethod
    def _on_check_scheduled(cls, trx: "db_services.LockedTransaction") -> None:
        count_checks: int = trx.extra.get(
            const.TransactionExtraFields.COUNT_STATUS_CHECKS_SCHEDULED, 0
        )

        trx.extra[const.TransactionExtraFields.COUNT_STATUS_CHECKS_SCHEDULED] = (
            count_checks + 1
        )
        trx.extra[const.TransactionExtraFields.LAST_STATUS_CHECK_SCHEDULE] = time.time()
        trx.save_extra()

    @classmethod
    def should_schedule_check_task_immediately(
        cls, trx_id: types.TransactionId, trx_extra: dict[str, ty.Any]
    ) -> bool:
        if cls._get_next_check_datetime(trx_extra) <= timezone.now():
            with transaction.atomic():
                locked_trx = db_services.get_transaction(for_update=True, trx_id=trx_id)
                cls._on_check_scheduled(locked_trx)
            return True
        return False
