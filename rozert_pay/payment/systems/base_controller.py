import abc
import logging
import re
import traceback
import typing as ty
import warnings
from datetime import timedelta
from typing import TYPE_CHECKING, Any, Callable, Generic, Optional, Type, cast, final

from django.conf import settings
from django.db import transaction
from django.http import HttpResponse
from django.utils import timezone
from django.utils.crypto import constant_time_compare
from pydantic import BaseModel
from rest_framework.request import Request
from rest_framework.response import Response
from rozert_pay.common import const
from rozert_pay.common.const import (
    CallbackStatus,
    CallbackType,
    CeleryQueue,
    EventType,
    TransactionExtraFields,
    TransactionStatus,
    TransactionType,
)
from rozert_pay.common.helpers import celery_utils
from rozert_pay.common.helpers.celery_utils import execute_on_commit
from rozert_pay.common.helpers.log_utils import LogWriter
from rozert_pay.payment import entities, tasks, types
from rozert_pay.payment.entities import RemoteTransactionStatus
from rozert_pay.payment.models import (
    IncomingCallback,
    OutcomingCallback,
    PaymentSystem,
    PaymentTransaction,
    Wallet,
)
from rozert_pay.payment.services import (
    base_classes,
    db_services,
    errors,
    event_logs,
    transaction_actualization,
    transaction_processing,
    transaction_set_status,
    transaction_status_validation,
)
from rozert_pay.payment.services.errors import Error
from rozert_pay.payment.services.transaction_status_validation import (
    CleanRemoteTransactionStatus,
)
from rozert_pay.payment.types import T_Client, T_SandboxClient

if TYPE_CHECKING:  # pragma: no cover
    from rozert_pay.payment.services.db_services import LockedTransaction

logger = logging.getLogger(__name__)


class PaymentSystemController(Generic[T_Client, T_SandboxClient]):
    client_cls: Type[T_Client]
    sandbox_client_cls: Type[T_SandboxClient]
    default_credentials: BaseModel
    transaction_actualizer_cls: Type[
        transaction_actualization.BaseTransactionActualizer[ty.Any]
    ]

    def __init__(
        self,
        *,
        payment_system: const.PaymentSystemType,
        default_credentials: dict[str, Any],
        transaction_actualizer_cls: type[
            transaction_actualization.BaseTransactionActualizer[ty.Any]
        ] = transaction_actualization.DEFAULT_ACTUALIZER_CLS,
        transaction_setter_cls: type[
            transaction_set_status.BaseTransactionSetter[ty.Any]
        ] = transaction_set_status.DEFAULT_TRANSACTION_SETTER,
        # If presented, it allows transition for final statuses for deposits or withdrawals.
        # Be supercareful with withdrawal transitions, if there's some error - user will be able
        # to withdraw multiple times!
        allow_transition_success_to_failed_for: list[TransactionType] | None = None,
        allow_transition_failed_to_success_for: list[TransactionType] | None = None,
        # Allows to bypass amount validation for some transaction types
        bypass_amount_validation_for: list[TransactionType] | None = None,
    ) -> None:
        self.payment_system = payment_system
        self.allow_transition_success_to_failed_for = (
            allow_transition_success_to_failed_for
        )
        self.allow_transition_failed_to_success_for = (
            allow_transition_failed_to_success_for
        )

        assert issubclass(
            self.sandbox_client_cls, self.client_cls
        ), f"{self.sandbox_client_cls} must be subclass of {self.client_cls}"
        assert issubclass(
            self.sandbox_client_cls, base_classes.BaseSandboxClientMixin
        ), f"{self.sandbox_client_cls} must be subclass of BaseSandboxClientMixin"
        self.default_credentials = self.client_cls.parse_and_validate_credentials(
            default_credentials
        )
        self.transaction_actualizer_cls = transaction_actualizer_cls
        self.transaction_setter_cls = transaction_setter_cls
        self.bypass_amount_validation_for = bypass_amount_validation_for

    @property
    def db_system(self) -> PaymentSystem:
        return PaymentSystem.objects.get(type=self.payment_system)

    @property
    def ip_whitelist(self) -> list[str]:
        return self.db_system.ip_whitelist

    def get_client(self, trx: PaymentTransaction) -> T_Client | T_SandboxClient:
        client_cls = trx.is_sandbox and self.sandbox_client_cls or self.client_cls

        return client_cls(
            trx_id=trx.id,
            timeout=trx.system.client_request_timeout,
        )

    @final
    def run_deposit(self, trx_id: types.TransactionId) -> None:
        try:
            with transaction.atomic():
                trx: PaymentTransaction = (
                    PaymentTransaction.objects.select_for_update(of=("self",))
                    .select_related(
                        "wallet__wallet__system",
                        "wallet__wallet__merchant",
                    )
                    .get(id=trx_id)
                )
                assert trx.currency == "MXN"

                if trx.status != TransactionStatus.PENDING:
                    logger.info(
                        "Transaction is not in initial status",
                    )
                    return

                if trx.type != TransactionType.DEPOSIT:
                    logger.error(
                        "Transaction is not a deposit",
                    )
                    return

            client = self.get_client(trx)
            self._run_deposit(trx_id, client=client)

            if trx.is_sandbox:
                ty.cast(T_SandboxClient, client).post_deposit_request()

        except Exception as e:
            logger.exception(
                "Error during deposit processing", extra={"trx_id": trx_id}
            )
            self.create_log(
                trx_id=trx_id,
                event_type=const.EventType.ERROR,
                extra={"message": str(e)},
                description=f"Error during deposit processing: {e}",
            )
            with transaction.atomic():
                locked_trx = db_services.get_transaction(trx_id=trx_id, for_update=True)
                self.fail_transaction(
                    locked_trx, const.TransactionDeclineCodes.INTERNAL_ERROR
                )
            return

    def _run_deposit(
        self, trx_id: types.TransactionId, client: T_SandboxClient | T_Client
    ) -> None:  # pragma: no cover
        """
        This method should perform after-deposit operations:

        * Saving redirect data/instructions
        * Perform some payment system specific operations

        This method called outside transaction.
        If using transaction, don't make any HTTP calls inside transactions to prevent
        useless locking for a long time
        """
        raise NotImplementedError

    @final
    def run_deposit_finalization(self, trx_id: types.TransactionId) -> None:
        try:
            with transaction.atomic():
                trx = db_services.get_transaction(trx_id=trx_id, for_update=True)
                if trx.type != const.TransactionType.DEPOSIT:
                    logger.error(
                        "Transaction is not a deposit",
                    )
                    return

                if (
                    trx.extra.get(TransactionExtraFields.IS_FINALIZATION_PERFORMED)
                    and trx.extra[TransactionExtraFields.IS_FINALIZATION_PERFORMED]
                ):
                    logger.warning("Finalization already performed")
                    return

                # Check and set flag that finalization performed.
                # This makes method idempotent.
                trx.extra[TransactionExtraFields.IS_FINALIZATION_PERFORMED] = True
                trx.save_extra()

            response = self.get_client(trx).deposit_finalize()

            with transaction.atomic():
                trx = db_services.get_transaction(trx_id=trx_id, for_update=True)

                self._on_deposit_finalization_response_received(response, trx)

                if response.status == const.TransactionStatus.FAILED:
                    assert response.decline_code
                    self.fail_transaction(
                        trx=trx,
                        decline_code=response.decline_code,
                        decline_reason=response.decline_reason,
                    )

                transaction_processing.schedule_periodic_status_checks(
                    trx,
                    timezone.now()
                    + timedelta(
                        seconds=self.db_system.deposit_allowed_ttl_seconds,
                    ),
                    schedule_check_immediately=True,
                )
        except Exception as e:
            logger.exception(
                "Error during deposit finalization", extra={"trx_id": trx_id}
            )
            event_logs.create_transaction_log(
                trx_id=trx_id,
                event_type=const.EventType.ERROR,
                extra={"message": str(e)},
                description=f"Error during deposit finalization: {e}",
                trace=True,
            )
            with transaction.atomic():
                locked_trx = db_services.get_transaction(trx_id=trx_id, for_update=True)
                self.fail_transaction(
                    locked_trx, const.TransactionDeclineCodes.INTERNAL_ERROR
                )
            return

    def _on_deposit_finalization_response_received(
        self,
        response: entities.PaymentClientDepositFinalizeResponse,
        locked_trx: "LockedTransaction",
    ) -> None:
        """
        This method is called after deposit finalization response is received.
        It should perform any payment-system specific operations.
        Called inside transaction.
        """
        pass

    @transaction.atomic
    def sync_remote_status_with_transaction(
        self,
        *,
        remote_status: CleanRemoteTransactionStatus,
        trx_id: int | None = None,
        trx: Optional["LockedTransaction"] = None,
        # BE CAREFUL WITH THIS FLAG!
        allow_transition_from_final_statuses: bool = False,
    ) -> None:
        """
        Synchronizes transaction with remote status.

        On commit creates callback.
        """
        assert trx or trx_id
        if not trx:
            trx = db_services.get_transaction(
                trx_id=trx_id,
                for_update=True,
                join_wallet=True,
            )

        trx_id = trx.id

        assert trx
        self._before_sync_remote_status_with_transaction(trx, remote_status)

        # Transaction in correct status
        if trx.status == remote_status.operation_status:
            if remote_status.operation_status == TransactionStatus.PENDING:
                transaction_processing.save_id_in_payment_system(
                    trx,
                    remote_status.id_in_payment_system,
                    save=True,
                )
            return

        # Transaction is in final status
        if trx.status != TransactionStatus.PENDING:
            if trx.status == remote_status.operation_status:
                # All good here
                return

            event_logs.create_transaction_log(
                event_type=EventType.ERROR,
                description="Transaction status mismatch!",
                extra={
                    "transaction_status": trx.status,
                    "received_status": remote_status.operation_status,
                },
                trx_id=trx_id,
            )

            # If final status transition allowed, don't stop processing but revert status to initial
            if allow_transition_from_final_statuses:
                transaction_processing.revert_to_pending(trx)
                assert trx.status == TransactionStatus.PENDING
            else:
                if transaction_status_validation.is_final_status_validation_enabled():
                    assert trx.status == remote_status.operation_status
                return

        transaction_processing.save_id_in_payment_system(
            trx, remote_status.id_in_payment_system
        )

        # Check/save decline code/reason
        if remote_status.operation_status == TransactionStatus.FAILED:
            if trx.decline_code is None:
                trx.decline_code = remote_status.decline_code
            elif remote_status.decline_code:
                assert trx.decline_code == remote_status.decline_code, (
                    trx.decline_code,
                    remote_status.decline_code,
                )

            if trx.decline_reason is None:
                trx.decline_reason = remote_status.decline_reason
            elif remote_status.decline_reason:
                assert trx.decline_reason == remote_status.decline_reason, (
                    trx.decline_reason,
                    remote_status.decline_reason,
                )
        else:
            trx.decline_code = trx.decline_reason = None

        trx.status = remote_status.operation_status
        trx.save()

        transaction.on_commit(
            lambda: self.create_callback(
                trx_id=trx_id,
                callback_type=CallbackType.TRANSACTION_UPDATED,
            )
        )
        if trx.status != TransactionStatus.PENDING:
            assert trx.status == remote_status.operation_status, (
                f"{trx.status} != {remote_status.operation_status}",
            )

        db_services.lock_currency_wallet(cast(types.CurrencyWalletId, trx.wallet_id))

        assert trx.status == remote_status.operation_status

        # Handle success/failed cases for deposit/withdrawalsm
        if trx.status == TransactionStatus.SUCCESS:
            if trx.type == TransactionType.DEPOSIT:
                return

            # Successfull payout - decrease hold balance
            elif trx.type == TransactionType.WITHDRAWAL:
                return
            else:
                raise RuntimeError

        elif trx.status == TransactionStatus.FAILED:
            if trx.type == TransactionType.WITHDRAWAL:
                return
            elif trx.type == TransactionType.DEPOSIT:
                pass
            else:
                raise RuntimeError
        elif trx.status == TransactionStatus.PENDING:
            # Special case when transaction was in final status, but reverted to initial.
            # Do nothing in this case.
            assert remote_status.operation_status == TransactionStatus.PENDING
            assert allow_transition_from_final_statuses
        else:
            raise RuntimeError(f"Unknown remote transaction status: {trx.status}")

    def _before_sync_remote_status_with_transaction(
        self, trx: "LockedTransaction", remote_status: CleanRemoteTransactionStatus
    ) -> None:
        pass

    def validate_transaction_attrs(
        self, attrs: dict[str, Any], context: dict[str, Any]
    ) -> None:
        pass

    @classmethod
    def create_log(
        self,
        *,
        trx_id: types.TransactionId,
        event_type: EventType,
        description: str,
        extra: dict[str, Any],
        trace: bool = False,
    ) -> None:
        warnings.warn(
            "PaymentSystemController.create_log is deprecated, use event_logs.create_transaction_log instead",
            DeprecationWarning,
        )
        event_logs.create_transaction_log(
            trx_id=trx_id,
            event_type=event_type,
            description=description,
            extra=extra,
            trace=trace,
        )

    def create_callback(
        self,
        trx_id: types.TransactionId,
        callback_type: CallbackType,
        stop_previous_callbacks: bool = True,
    ) -> None:
        if stop_previous_callbacks:
            OutcomingCallback.objects.filter(
                transaction_id=trx_id,
                status=CallbackStatus.PENDING,
            ).delete()

        from rozert_pay.payment.api_v1.serializers import TransactionResponseSerializer

        trx: PaymentTransaction = PaymentTransaction.objects.get(id=trx_id)
        data = TransactionResponseSerializer(instance=trx).data

        target_url = trx.callback_url or trx.wallet.wallet.default_callback_url

        if not target_url:
            self.create_log(
                trx_id=trx_id,
                event_type=EventType.ERROR,
                extra={
                    "message": "Cant send callback because no callback_url / wallet.default_callback_url is set",
                },
                description="Cant send callback because no callback_url / wallet.default_callback_url is set",
            )
            return

        cb = OutcomingCallback.objects.create(
            transaction_id=trx_id,
            callback_type=callback_type,
            target=target_url,
            body=data,
        )

        # execute_on_commit(
        #     lambda: tasks.send_callback.apply_async(
        #         kwargs=dict(
        #             callback_id=cb.id,
        #         ),
        #         queue=CeleryQueue.NORMAL_PRIORITY,
        #     )
        # )

    @final
    def parse_callback(
        self, _cb: IncomingCallback, is_sandbox: bool = False
    ) -> Response | None:
        with transaction.atomic():
            cb: IncomingCallback = IncomingCallback.objects.select_for_update(
                of=("self",)
            ).get(id=_cb.id)

            try:
                if (
                    settings.IS_PRODUCTION
                    and self.db_system.ip_whitelist_enabled
                    and cb.ip not in self.ip_whitelist
                ):
                    self._fail_callback(
                        cb,
                        error=f"IP not in whitelist: {cb.ip}",
                        error_type=const.IncomingCallbackError.IP_NOT_WHITELISTED,
                    )
                    return None

                if secret := _cb.system.callback_secret_key:
                    secret_key = _cb.headers.get("x-secret-key") or ""
                    if not secret_key:
                        if s := re.search(
                            "Bearer (.+)",
                            _cb.headers.get("authorization", ""),
                            re.IGNORECASE,
                        ):
                            secret_key = s.group(1)

                    if not constant_time_compare(
                        secret_key,
                        secret,
                    ):
                        self._fail_callback(
                            cb,
                            error="Invalid secret key",
                            error_type=const.IncomingCallbackError.AUTHORIZATION_ERROR,
                        )
                        return None

                if not self._is_callback_signature_valid(cb):
                    self._fail_callback(
                        cb,
                        error="Signature is invalid",
                        error_type=const.IncomingCallbackError.INVALID_SIGNATURE,
                    )
                    return None

                remote_transaction_status = self._parse_callback(cb)
                if isinstance(remote_transaction_status, Error):
                    self._fail_callback(
                        cb,
                        error=str(remote_transaction_status),
                        error_type=const.IncomingCallbackError.PARSING_ERROR,
                    )
                    return None
                elif isinstance(remote_transaction_status, Response):
                    return remote_transaction_status

                assert isinstance(remote_transaction_status, RemoteTransactionStatus)
                assert (
                    remote_transaction_status.transaction_id
                ), "No transaction_id in parsed callback"
                cb.transaction_id = remote_transaction_status.transaction_id
                cb.remote_transaction_status = remote_transaction_status.model_dump()

                if err := self._validate_parsed_callback(cb):
                    self._fail_callback(
                        cb,
                        error=err,
                        error_type=const.IncomingCallbackError.VALIDATION_ERROR,
                    )
                    return None

                # All is good
                cb.status = CallbackStatus.SUCCESS
                cb.error = None
                cb.traceback = None
                cb.save()
                remote_status = RemoteTransactionStatus(**cb.remote_transaction_status)

                assert cb.transaction

                # Maybe revert final status `SUCCESS` to `PENDING`, if controller allows that
                if (
                    cb.transaction.status == TransactionStatus.SUCCESS
                    and remote_status.operation_status == TransactionStatus.FAILED
                    and self.allow_transition_success_to_failed_for
                ):
                    if (
                        cb.transaction.type
                        in self.allow_transition_success_to_failed_for
                    ):
                        transaction_processing.revert_to_pending(
                            cb.get_transaction_id()
                        )
                        cb.transaction.refresh_from_db()

                # Maybe revert final status `FAILED` to `PENDING`, if controller allows that
                if (
                    cb.transaction.status == TransactionStatus.FAILED
                    and remote_status.operation_status == TransactionStatus.SUCCESS
                    and self.allow_transition_failed_to_success_for
                ):
                    if (
                        cb.transaction.type
                        in self.allow_transition_failed_to_success_for
                    ):
                        transaction_processing.revert_to_pending(
                            cb.get_transaction_id()
                        )
                        cb.transaction.refresh_from_db()

                clean_remote_status = (
                    transaction_status_validation.validate_remote_transaction_status(
                        transaction=cb.transaction,
                        remote_status=remote_status,
                    )
                )
                if isinstance(clean_remote_status, errors.Error):
                    self._fail_callback(
                        cb,
                        error=clean_remote_status,
                        error_type=const.IncomingCallbackError.VALIDATION_ERROR,
                    )
                    return None

                assert cb.transaction, "Transaction is None"

                if is_sandbox and not cb.transaction.is_sandbox:
                    raise RuntimeError(
                        "Sandbox callback received for non-sandbox transaction"
                    )

                # Update transaction status
                self.sync_remote_status_with_transaction(
                    trx_id=cb.transaction_id,
                    remote_status=clean_remote_status,
                )
            except Exception as e:
                logger.exception("Error parsing callback")  # pragma: no cover
                self._fail_callback(
                    cb,
                    error=f"Error parsing callback: {e}",
                    error_type=const.IncomingCallbackError.UNKNOWN_ERROR,
                )

            return None

    def build_callback_response(self, cb: IncomingCallback) -> HttpResponse:
        return Response()

    @abc.abstractmethod
    def _parse_callback(
        self, cb: IncomingCallback
    ) -> RemoteTransactionStatus | Response:
        """
        This method is called inside transaction.
        It should not perform any HTTP requests inside.
        Consider using celery tasks for HTTP request actions.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def _is_callback_signature_valid(self, cb: IncomingCallback) -> bool:
        pass

    def _validate_parsed_callback(self, cb: IncomingCallback) -> None | Error:
        if not cb.transaction_id:
            return Error("Transaction ID is required")

        if not cb.remote_transaction_status:
            return Error("Remote transaction status is required")

        try:
            RemoteTransactionStatus(
                **ty.cast(dict[str, Any], cb.remote_transaction_status)
            )
        except Exception as e:
            return Error(f"Error parsing remote transaction status: {e}")

        return None

    def _fail_callback(
        self,
        cb: IncomingCallback,
        error: str | Error,
        error_type: const.IncomingCallbackError,
    ) -> None:
        cb.status = CallbackStatus.FAILED
        cb.error = str(error)
        cb.error_type = error_type
        cb.traceback = traceback.format_exc()
        cb.save()

        logger.error(
            f"Callback failed: {error_type}",
            extra={
                "callback_id": cb.id,
                "error": error,
                "error_type": error_type,
            },
        )
        return None

    def on_db_transaction_created_via_api(self, trx: PaymentTransaction) -> None:
        if b := self.bypass_amount_validation_for:
            transaction_status_validation.TransactionAmountValidation.bypass_amount_validation_for_transaction(
                # TODO: fix typing, create_transaction can return locked transaction and can change signature.
                cast("db_services.LockedTransaction", trx),
                b,
            )

        celery_utils.execute_on_commit(
            lambda: tasks.process_transaction.apply_async(
                args=(trx.id,),
                queue=CeleryQueue.HIGH_PRIORITY,
            )
        )

    def run_withdraw(self, transaction_id: types.TransactionId) -> None:
        try:
            trx = db_services.get_transaction(
                trx_id=transaction_id,
                for_update=False,
            )

            if trx.status != TransactionStatus.PENDING:
                logger.info(
                    "Transaction is not in initial status",
                )
                return

            if trx.type != TransactionType.WITHDRAWAL:
                logger.error(
                    "Transaction is not a withdrawal",
                )
                return

            client = self.get_client(trx)
            self._run_withdraw(trx, client=client)
            if trx.is_sandbox:
                ty.cast(T_SandboxClient, client).post_withdraw_request()

        except Exception as e:
            logger.exception(
                "Error during withdrawal processing", extra={"trx_id": transaction_id}
            )
            self.create_log(
                trx_id=transaction_id,
                event_type=const.EventType.ERROR,
                extra={
                    "message": str(e),
                },
                description=f"Error during withdrawal processing: {e}",
                trace=True,
            )
            return

    def _run_withdraw(
        self, trx: PaymentTransaction, client: T_SandboxClient | T_Client
    ) -> None:  # pragma: no cover
        """
        This method should perform withdraw request and any payment-system
        specific operations.

        This method is called outside transaction.

        If using transaction.atomic, don't make any HTTP calls inside atomic blocks to prevent
        useless locking for a long time

        TODO: idempotency checks/after withdraw status check
        """
        raise NotImplementedError

    def fail_transaction(
        self,
        trx: "LockedTransaction",
        decline_code: str,
        decline_reason: str | None = None,
    ) -> None:
        """
        Fails transaction with specific decline_code
        """
        self.sync_remote_status_with_transaction(
            trx=trx,
            remote_status=transaction_status_validation.bypass_validation(
                RemoteTransactionStatus(
                    operation_status=const.TransactionStatus.FAILED,
                    raw_data={},
                    decline_code=decline_code,
                    decline_reason=decline_reason,
                )
            ),
        )

    @final
    def get_action_on_credentials_change(
        self,
    ) -> (
        Callable[[Wallet, dict[str, Any], dict[str, Any], LogWriter], None | Error]
        | None
    ):
        """
        If method returns not None, it should return function (wallet, old_creds, new_creds) -> Error | None
        which will be called in admin on each system credentials change
        This function should perform some action on credentials change.
        For example register webhooks for new creds.

        To implement, you should override _get_action_on_credentials_change method
        """

        # Handle all exceptions to errors
        action = self._get_action_on_credentials_change()
        return action and errors.wrap_errors(action)

    def _get_action_on_credentials_change(
        self,
    ) -> (
        Callable[[Wallet, dict[str, Any], dict[str, Any], LogWriter], None | Error]
        | None
    ):
        return None

    def handle_redirect(
        self,
        request: Request,
    ) -> Response:
        # See deposit_services.handle_deposit_redirect as example
        raise NotImplementedError

    def get_operation_ttl_seconds(self, trx: PaymentTransaction) -> timedelta:
        if trx.type == TransactionType.DEPOSIT:
            return timedelta(seconds=trx.system.deposit_allowed_ttl_seconds)
        elif trx.type == TransactionType.WITHDRAWAL:
            return timedelta(seconds=trx.system.withdrawal_allowed_ttl_seconds)
        else:
            raise RuntimeError
