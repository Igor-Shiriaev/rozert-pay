import contextlib
import logging
import typing as ty

from django.db import transaction
from rozert_pay.common import const
from rozert_pay.common.const import TransactionStatus
from rozert_pay.payment import models
from rozert_pay.payment.services import db_services, errors, transaction_processing
from rozert_pay.payment.systems import base_controller

logger = logging.getLogger(__name__)


@contextlib.contextmanager
def execute_withdraw_query_and_schedule_status_checks(
    trx: "models.PaymentTransaction",
    controller: "base_controller.PaymentSystemController[ty.Any, ty.Any]",
    schedule_periodic_checks: bool = True,
    schedule_check_immediately: bool = True,
) -> ty.Generator["db_services.LockedTransaction", None, None]:
    # TODO: idempotency
    client = controller.get_client(trx)
    original_trx = trx

    try:
        response = client.withdraw()
    except errors.SafeFlowInterruptionError as e:
        logger.exception(f"Error executing withdraw request: {e.__class__}")
        with transaction.atomic():
            trx = db_services.get_transaction(trx_id=trx.id, for_update=True)
            controller.fail_transaction(
                trx,
                decline_code=const.TransactionDeclineCodes.NO_OPERATION_PERFORMED,
                decline_reason=e.reason,
            )
            return

    with transaction.atomic():
        trx = db_services.get_transaction(trx_id=trx.id, for_update=True)

    if response.status in [TransactionStatus.PENDING, TransactionStatus.SUCCESS]:
        assert response.id_in_payment_system
    trx.id_in_payment_system = response.id_in_payment_system
    trx.save(update_fields=["id_in_payment_system", "updated_at"])

    if response.status == const.TransactionStatus.FAILED:
        assert response.decline_code

        controller.fail_transaction(
            trx=trx,
            decline_code=response.decline_code,
            decline_reason=response.decline_reason,
        )

    original_trx.refresh_from_db()

    if schedule_periodic_checks:
        transaction_processing.schedule_periodic_status_checks(
            trx=trx,
            schedule_check_immediately=schedule_check_immediately,
        )

    with transaction.atomic():
        yield trx
