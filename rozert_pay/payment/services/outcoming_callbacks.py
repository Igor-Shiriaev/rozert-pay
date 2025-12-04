import typing as ty

from django.db import transaction
from django.db.models import QuerySet
from rozert_pay.account.models import User
from rozert_pay.common import const
from rozert_pay.payment import models, tasks
from rozert_pay.payment.services import event_logs


def retry_outcoming_callback(
    item_or_qs: models.OutcomingCallback | QuerySet[models.OutcomingCallback],
    action_user: User | None,
    message_user: ty.Callable[[str], None],
) -> None:
    callbacks: ty.Iterable[models.OutcomingCallback]
    if isinstance(item_or_qs, models.OutcomingCallback):
        callbacks = [item_or_qs]
    else:
        callbacks = item_or_qs

    count_retry = 0
    count_skipped = 0

    for obj in callbacks:
        with transaction.atomic():
            cb: models.OutcomingCallback = (
                models.OutcomingCallback.objects.select_for_update().get(id=obj.id)
            )
            if cb.status == const.CallbackStatus.SUCCESS:
                count_skipped += 1
                continue

            count_retry += 1
            cb.current_attempt = 0
            cb.logs = cb.logs or ""
            cb.logs += f"\n\n---\nRetry scheduled by user {action_user}\n"
            cb.error = ""
            cb.status = const.CallbackStatus.PENDING
            cb.save()
            event_logs.create_transaction_log(
                trx_id=cb.get_transaction_id(),
                event_type=const.EventType.CALLBACK_RETRY_REQUESTED,
                extra={
                    "message": f"Callback retry requested by {action_user}",
                },
                description=f"Callback retry requested by {action_user}",
            )
            tasks.send_callback.apply_async(
                args=(cb.id,), queue=const.CeleryQueue.LOW_PRIORITY
            )

    message_user(
        f"Callbacks are queued for retry: retried = {count_retry}, skipped because status success = {count_skipped}",
    )
    return
