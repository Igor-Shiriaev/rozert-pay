import base64
import hashlib
import hmac
import json
import logging
from datetime import timedelta
from itertools import groupby
from typing import Any, Literal, TypedDict, cast, overload

import requests
from celery import Task
from celery.exceptions import MaxRetriesExceededError
from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.db import transaction
from django.http import HttpResponse
from django.utils import timezone
from rest_framework.response import Response
from rozert_pay.account.models import User
from rozert_pay.celery_app import app
from rozert_pay.common import const, slack
from rozert_pay.common.const import (
    CeleryQueue,
    EventType,
    TransactionDeclineCodes,
    TransactionStatus,
    TransactionType,
)
from rozert_pay.common.helpers.log_utils import LogWriter
from rozert_pay.payment import entities
from rozert_pay.payment import types
from rozert_pay.payment import types as payment_types
from rozert_pay.payment.entities import RemoteTransactionStatus
from rozert_pay.payment.factories import get_payment_system_controller
from rozert_pay.payment.models import (
    IncomingCallback,
    OutcomingCallback,
    PaymentSystem,
    PaymentTransaction,
    PaymentTransactionEventLog,
)
from rozert_pay.payment.services import (
    db_services,
    errors,
    event_logs,
    transaction_processing,
    transaction_status_validation,
)
from rozert_pay.payment.services.context import global_context
from rozert_pay.payment.services.transaction_processing import (
    TransactionPeriodicCheckService,
)

logger = logging.getLogger(__name__)


@app.task
def process_transaction(transaction_id: str) -> None:
    # NOTE: Don't forget to update `select_related` and `prefetch_related`
    # by adding entities that you use further in processing
    # in order to avoid N+1 queries
    trx: PaymentTransaction = PaymentTransaction.objects.select_related(
        "wallet__wallet__merchant",
        "customer",
    ).get(id=transaction_id)
    controller = get_payment_system_controller(trx.system)
    if not controller:
        logger.error("Unsupported payment system", extra={"system": trx.system})
        return

    if trx.is_sandbox:
        client_cls = controller.sandbox_client_cls
        controller.create_log(
            trx_id=trx.id,
            event_type=EventType.IMPORTANT,
            extra={
                "message": f"Transaction is in sandbox mode, using {client_cls} client",
            },
            description="!!! Transaction is in sandbox mode",
        )

    if trx.type == TransactionType.DEPOSIT:
        controller.run_deposit(trx.id)
    elif trx.type == TransactionType.WITHDRAWAL:
        controller.run_withdraw(trx.id)
    else:
        raise NotImplementedError  # pragma: no cover


@app.task(queue=CeleryQueue.LOW_PRIORITY)
@transaction.atomic
def task_fail_by_timeout(transaction_id: int, ttl_seconds: int) -> None:
    trx = db_services.get_transaction(trx_id=transaction_id, for_update=True)
    if (timezone.now() - trx.created_at).total_seconds() > ttl_seconds:
        controller = get_payment_system_controller(trx.system)
        if not controller:  # pragma: no cover
            logger.error("Unsupported payment system", extra={"system": trx.system})
            return

        if trx.status != TransactionStatus.PENDING:
            logger.info("Transaction has final status")
            return

        controller.sync_remote_status_with_transaction(
            trx=trx,
            remote_status=transaction_status_validation.bypass_validation(
                RemoteTransactionStatus(
                    operation_status=const.TransactionStatus.FAILED,
                    raw_data={
                        "message": "declined_by_timeout",
                    },
                    decline_code=TransactionDeclineCodes.USER_HAS_NOT_FINISHED_FLOW,
                    decline_reason="Too long execution for transaction",
                )
            ),
        )
    else:
        logger.error("task_fail_by_timeout received but cant fail transaction")


@app.task(queue=CeleryQueue.LOW_PRIORITY)
def task_periodic_fail_old_transactions() -> None:
    for system in PaymentSystem.objects.all():
        # Process deposits
        ttl_sec = system.deposit_allowed_ttl_seconds

        for trx in PaymentTransaction.objects.filter(
            status=const.TransactionStatus.PENDING,
            type=const.TransactionType.DEPOSIT,
            created_at__lt=timezone.now() - timedelta(seconds=ttl_sec),
        ).select_related("wallet__wallet"):
            assert trx.type == const.TransactionType.DEPOSIT
            assert trx.created_at < timezone.now() - timedelta(seconds=ttl_sec)

            event_logs.create_transaction_log(
                event_type=EventType.INFO,
                trx_id=trx.id,
                description=f"Fail transaction by ttl ({ttl_sec=})",
                extra={},
            )

            task_fail_by_timeout.delay(
                transaction_id=trx.id,
                ttl_seconds=ttl_sec,
            )


@app.task(
    bind=True,
    acks_late=True,
    soft_time_limit=30,
    time_limit=30,
)
@transaction.atomic
def send_callback(self: Task, callback_id: str) -> None:  # type: ignore[type-arg]
    cb: OutcomingCallback | None = (
        OutcomingCallback.objects.select_related(
            "transaction__wallet__wallet__merchant",
        )
        .select_for_update(of=("self",))
        .filter(id=callback_id)
        .last()
    )
    if not cb:
        logger.info(
            "No callback found for sending, maybe was cancelled",
            extra={
                "callback_id": callback_id,
            },
        )
        return

    log_writer = LogWriter()

    log_writer.write("---")
    log_writer.write(f"Send callback - attempt {cb.current_attempt}/{cb.max_attempts}")

    def _on_exit() -> None:
        cb.logs = (cb.logs or "") + "\n" + log_writer.to_string()
        cb.save()
        return None

    if cb.status != const.CallbackStatus.PENDING:  # pragma: no cover
        log_writer.write("Trying to send callback with final status")
        logger.warning(
            "Trying to send callback with final status",
            extra={
                "callback_id": cb.id,
                "status": cb.status,
            },
        )
        return _on_exit()

    body = json.dumps(cb.body).encode()
    transaction = cb.transaction
    merchant = transaction.wallet.wallet.merchant
    secret_key = merchant.secret_key.encode()
    expected_signature = base64.b64encode(
        hmac.new(secret_key, body, hashlib.sha256).digest()
    ).decode()

    system = get_payment_system_controller(transaction.system)
    if not system:  # pragma: no cover
        log_writer.write("Unsupported payment system")
        logger.error("Unsupported payment system", extra={"system": transaction.system})
        return _on_exit()

    event_log: dict[str, Any] = {
        "body": body.decode(),
        "signature": expected_signature,
    }
    error = None

    try:
        resp = requests.post(
            url=cb.target,
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-Signature": expected_signature,
            },
            timeout=30,
        )
    except Exception as e:
        event_log["error"] = str(e)
        error = str(e)
        log_writer.write(f"Error during callback sending: {e}")
        logger.warning(
            "Error during callback sending",
            extra={
                "callback_id": cb.id,
                "error": str(e),
            },
            exc_info=True,
        )
    else:
        event_log["response"] = {
            "status_code": resp.status_code,
            "text": resp.text,
        }
        log_writer.write(f"Response: {resp.status_code} {resp.text[:100]}")
        if not resp.ok:
            log_writer.write(
                "Bad response during callback sending, retrying...",
            )
            logger.warning(
                "bad response during sending callback",
                extra={
                    "callback_id": cb.id,
                    "status_code": resp.status_code,
                    "text": resp.text[:100],
                },
            )
            error = f"Bad response: {resp.status_code} {resp.text[:100]}"
        else:
            log_writer.write("Callback sent")
            logger.info(
                "callback sent",
                extra={
                    "callback_id": cb.id,
                    "status_code": resp.status_code,
                    "text": resp.text[:100],
                },
            )

    cb.error = error
    cb.last_attempt_at = timezone.now()
    cb.current_attempt = cb.current_attempt + 1

    system.create_log(
        trx_id=transaction.id,
        event_type=EventType.CALLBACK_SENDING_ATTEMPT,
        extra=event_log,
        description=f"Attempt to send callback: {cb.current_attempt} / {cb.max_attempts}",
    )
    if error is None:
        cb.status = const.CallbackStatus.SUCCESS
        cb.save()
        return _on_exit()

    if cb.current_attempt <= cb.max_attempts:
        logger.info(
            "retrying callback",
            extra={
                "callback_id": cb.id,
                "current_attempt": cb.current_attempt,
                "max_attempts": cb.max_attempts,
                "countdown": 2**cb.current_attempt,
            },
        )
        try:
            self.retry(
                countdown=2**cb.current_attempt,
                max_retries=cb.max_attempts,
                throw=False,
            )
            log_writer.write("Callback retry scheduled")
        except MaxRetriesExceededError:
            logger.exception("")
            cb.status = const.CallbackStatus.FAILED
            cb.save()
            log_writer.write("Callback retries limit exceeded")
        return _on_exit()

    log_writer.write("Callback retries limit exceeded")
    cb.status = const.CallbackStatus.FAILED
    cb.save()
    return _on_exit()


@overload
def handle_incoming_callback(
    cb_id: int,
    is_retry: Literal[True],
    retry_user: User | AnonymousUser,
    *,
    is_sandbox: bool = False,
) -> Response:
    ...


@overload
def handle_incoming_callback(
    cb_id: int,
    is_retry: Literal[False] = False,
    retry_user: None = None,
    *,
    is_sandbox: bool = False,
) -> Response:
    ...


def handle_incoming_callback(
    cb_id: int,
    is_retry: bool = False,
    retry_user: User | AnonymousUser | None = None,
    *,
    is_sandbox: bool = False,
) -> HttpResponse:
    with global_context(
        incoming_callback_id=cb_id,
    ):
        # Check and cleanup callback processing fields if is_retry
        with transaction.atomic():
            cb: IncomingCallback = IncomingCallback.objects.select_for_update().get(
                id=cb_id
            )

            if is_retry:
                assert retry_user
                assert not isinstance(retry_user, AnonymousUser)
                cb = IncomingCallback.objects.select_for_update().get(id=cb.id)
                cb.status = const.CallbackStatus.PENDING
                cb.traceback = None
                cb.error = None
                cb.error_type = None
                cb.save()

        controller = get_payment_system_controller(cb.system)
        if not controller:  # pragma: no cover
            logger.error(
                "Unsupported payment system",
                extra={
                    "system": cb.system,
                    "callback_id": cb.id,
                },
            )
            return Response()

        r = controller.parse_callback(cb, is_sandbox=is_sandbox)
        if isinstance(r, Response):
            return r
        assert isinstance(r, type(None))
        cb.refresh_from_db()
        return controller.build_callback_response(cb)


@app.task(queue=CeleryQueue.LOW_PRIORITY)
def check_pending_transaction_status() -> None:
    for (
        trx_id,
        trx_extra,
    ) in PaymentTransaction.objects.transactions_for_periodic_status_check().values_list(
        "id", "extra"
    ):
        if TransactionPeriodicCheckService.should_schedule_check_task_immediately(
            types.TransactionId(trx_id), trx_extra
        ):
            check_status.delay(trx_id)


# TODO: naming
@app.task(queue=CeleryQueue.LOW_PRIORITY)
def check_status(transaction_id: int) -> None:
    with transaction.atomic():
        locked_trx = db_services.get_transaction(trx_id=transaction_id, for_update=True)

        # TODO: check status even for final transactions

        # Here we stop check only for success and failed statuses.
        # If chageback received, it is usually done via callbacks.
        if locked_trx.status in [
            TransactionStatus.SUCCESS,
            TransactionStatus.FAILED,
        ]:
            logger.info(
                "Transaction is in final status",
                extra={
                    "transaction_id": transaction_id,
                    "status": locked_trx.status,
                },
            )
            return

        controller = get_payment_system_controller(locked_trx.system)
        if not controller:  # pragma: no cover
            logger.error(
                "Unsupported payment system", extra={"system": locked_trx.system}
            )
            return

        # Case when transaction is stuck in processing state for too long
        if (
            locked_trx.check_status_until
            and timezone.now() > locked_trx.check_status_until
        ):
            # Should stop transaction checking if status not final
            if locked_trx.is_deposit:
                # If deposit - fail transaction because of timeout
                controller.fail_transaction(
                    trx=locked_trx,
                    decline_code=const.TransactionDeclineCodes.DEPOSIT_NOT_PROCESSED_IN_TIME,
                )
                locked_trx.save()
            elif locked_trx.is_withdrawal:
                # If withdrawal - stop checking
                event_logs.create_transaction_log(
                    trx_id=locked_trx.id,
                    event_type=EventType.WITHDRAWAL_STUCK_IN_PROCESSING,
                    description="Withdrawal stuck in processing state",
                    extra={},
                )
            else:  # pragma: no cover
                raise RuntimeError

            locked_trx.check_status_until = None
            locked_trx.save(update_fields=["check_status_until", "updated_at"])
            return

    trx = cast(PaymentTransaction, locked_trx)
    del locked_trx

    # Check transaction status with remote.
    remote_status = controller.get_client(trx).get_transaction_status()

    if isinstance(remote_status, errors.Error):
        return

    status_or_err = transaction_status_validation.validate_remote_transaction_status(
        transaction=trx,
        remote_status=remote_status,
    )

    # TODO: check case when final status mismatches
    with transaction.atomic():
        locked_trx = db_services.get_transaction(trx_id=transaction_id, for_update=True)

        if isinstance(status_or_err, errors.Error):  # pragma: no cover
            # In this case we can't do much, so stop checking
            transaction_processing.stop_periodic_status_checks(locked_trx)

            event_logs.create_transaction_log(
                trx_id=locked_trx.id,
                event_type=EventType.ERROR,
                description=f"Stop validating remote status for transaction: {status_or_err}",
                extra={
                    "remote_status": remote_status.model_dump(),
                },
            )

            logger.error(
                f"Error validating remote status for transaction: {status_or_err}",
                extra={
                    "transaction": locked_trx,
                    "error": status_or_err,
                },
                exc_info=True,
            )
            return

        controller.sync_remote_status_with_transaction(
            remote_status=status_or_err,
            trx=locked_trx,
        )

        if trx.status != TransactionStatus.PENDING:
            trx.check_status_until = None
            trx.save(update_fields=["check_status_until", "updated_at"])


@app.task(queue=CeleryQueue.HIGH_PRIORITY)
def run_deposit_finalization(trx_id: payment_types.TransactionId) -> None:
    trx = PaymentTransaction.objects.get(id=trx_id)
    controller = get_payment_system_controller(trx.system)
    controller.run_deposit_finalization(trx_id)


@app.task(queue=CeleryQueue.LOW_PRIORITY)
@transaction.atomic
def sandbox_approve_transaction(trx_id: int) -> None:
    trx = db_services.get_transaction(trx_id=trx_id, for_update=True)
    if not trx.is_sandbox:
        raise RuntimeError

    controller = get_payment_system_controller(trx.system)
    assert controller

    controller.sync_remote_status_with_transaction(
        trx_id=trx_id,
        remote_status=transaction_status_validation.bypass_validation(
            entities.RemoteTransactionStatus(
                operation_status=TransactionStatus.SUCCESS,
                raw_data={"message": "THIS IS FAKE SANDBOX RESPONSE!"},
                id_in_payment_system=trx.id_in_payment_system,
                transaction_id=trx.id,
                remote_amount=trx.money,
            )
        ),
    )


class LogCleanupResult(TypedDict):
    found: int
    deleted: int
    message: str
    found_ids: list[int]


@app.task
def task_periodic_cleanup_duplicate_logs(
    full_cleanup: bool = False,
) -> None:
    qs = PaymentTransaction.objects.all()
    if not full_cleanup:
        qs = qs.filter(
            created_at__gte=timezone.now() - timedelta(days=5),
        )

    for trx_id in qs.values_list("id", flat=True):
        task_cleanup_duplicate_logs.delay(trx_id)


@app.task(queue=CeleryQueue.SERVICE)
def task_cleanup_duplicate_logs(
    transaction_id: int,
) -> LogCleanupResult:
    logs_qs = PaymentTransactionEventLog.objects.filter(
        event_type=EventType.EXTERNAL_API_REQUEST,
        transaction_id=transaction_id,
    ).order_by("transaction_id", "created_at")

    all_logs_data = list(
        logs_qs.values("id", "transaction_id", "description", "created_at", "extra")
    )

    if not all_logs_data:
        return {
            "found": 0,
            "deleted": 0,
            "message": "No logs to clean up in the given timeframe.",
            "found_ids": [],
        }

    logs_to_delete_ids: set[int] = set()

    keyfunc = lambda log: (  # noqa: E731
        log["transaction_id"],
        log["description"],
        json.dumps(
            log.get("extra", {}).get("response", {}).get("text", {}), sort_keys=True
        ),
    )

    for key, group in groupby(sorted(all_logs_data, key=keyfunc), key=keyfunc):
        group_logs = list(group)
        if len(group_logs) <= 1:
            continue

        group_logs.sort(key=lambda x: x["created_at"], reverse=True)

        ids_to_delete = {log["id"] for log in group_logs[1:]}
        logs_to_delete_ids.update(ids_to_delete)

    if not logs_to_delete_ids:
        return {
            "found": 0,
            "deleted": 0,
            "message": "No duplicates found.",
            "found_ids": [],
        }

    sorted_ids_to_delete = sorted(list(logs_to_delete_ids))
    logger.info(
        f"Deleting {len(sorted_ids_to_delete)} duplicate event logs.",
        extra={"deleted_log_ids": sorted_ids_to_delete},
    )
    deleted_count, _ = PaymentTransactionEventLog.objects.filter(
        id__in=logs_to_delete_ids
    ).delete()

    result_message = (
        f"Found {len(sorted_ids_to_delete)} duplicates."
        f" Deleted {deleted_count} entries."
    )

    return {
        "found": len(sorted_ids_to_delete),
        "deleted": deleted_count,
        "message": result_message,
        "found_ids": sorted_ids_to_delete,
    }


@app.task(queue=CeleryQueue.LOW_PRIORITY)
def notify_unexpected_callback_for_expired_transaction(
    transaction_id: int,
    transaction_uuid: str,
) -> None:
    admin_url = f"{settings.EXTERNAL_ROZERT_HOST}/admin/payment/paymenttransaction/{str(transaction_id)}/change/"

    message = (
        f"Transaction *<{admin_url}|{transaction_uuid}>* received an unexpected callback "
        f"after being marked as expired (rozert_d24_mercadopago)"
    )

    slack.slack_client.send_message(
        channel=settings.SLACK_UNEXPRECTED_NOTIFY_CHANNEL, text=message
    )

    event_logs.create_transaction_log(
        trx_id=types.TransactionId(transaction_id),
        event_type=EventType.INFO,
        description="Slack notification sent for unexpected callback on expired transaction",
        extra={
            "channel": settings.SLACK_UNEXPRECTED_NOTIFY_CHANNEL,
            "message": message,
        },
    )

    logger.info(
        "Sent Slack notification for unexpected callback on expired transaction",
        extra={
            "transaction_id": transaction_id,
            "transaction_uuid": transaction_uuid,
            "channel": settings.SLACK_UNEXPRECTED_NOTIFY_CHANNEL,
        },
    )
