import traceback
import typing as ty

from rozert_pay.common import const
from rozert_pay.payment import models, types
from rozert_pay.payment.models import EventLog


def create_event_log(
    *,
    event_type: const.EventType,
    description: str,
    extra: dict[str, ty.Any],
    system_type: const.PaymentSystemType,
    merchant_id: types.MerchantID | None,
    customer_id: types.CustomerId | None = None,
) -> models.EventLog:
    return EventLog.objects.create(
        event_type=event_type,
        description=description,
        extra=extra,
        system_type=system_type,
        merchant_id=merchant_id,
        customer_id=customer_id,
    )


def create_transaction_log(
    *,
    trx_id: types.TransactionId,
    event_type: const.EventType,
    description: str,
    extra: dict[str, ty.Any],
    trace: bool = False,
) -> models.PaymentTransactionEventLog:
    if trace:
        extra["trace"] = traceback.format_exc(limit=30)
    return models.PaymentTransactionEventLog.objects.create(
        transaction_id=trx_id,
        event_type=event_type,
        extra={},
        description=description,
        request_id=None,
    )
