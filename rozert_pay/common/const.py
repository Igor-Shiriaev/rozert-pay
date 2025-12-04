from pathlib import Path

from django.db.models import TextChoices


class TransactionType(TextChoices):
    DEPOSIT = "deposit", "Deposit"
    WITHDRAWAL = "withdrawal", "Withdrawal"


class TransactionStatus(TextChoices):
    PENDING = "pending", "Pending"
    SUCCESS = "success", "Success"
    FAILED = "failed", "Failed"


class TransactionDeclineCodes(TextChoices):
    USER_HAS_NOT_FINISHED_FLOW = (
        "USER_HAS_NOT_FINISHED_FLOW",
        "User has not finished flow",
    )
    INTERNAL_ERROR = "INTERNAL_ERROR", "Internal error"
    DEPOSIT_NOT_PROCESSED_IN_TIME = (
        "DEPOSIT_NOT_PROCESSED_IN_TIME",
        "Deposit not processed in time",
    )
    NO_OPERATION_PERFORMED = "NO_OPERATION_PERFORMED", "No operation performed"
    TRANSACTION_NOT_FOUND = "TRANSACTION_NOT_FOUND", "Transaction not found"

    # For our system declines, when we 100% sure no payout requests was sent
    SYSTEM_DECLINE = "system_decline", "System decline"


class EventType(TextChoices):
    ERROR = "error", "Error"
    CALLBACK_SENDING_ATTEMPT = "callback_sending_attempt", "Callback Sending Attempt"
    EXTERNAL_API_REQUEST = "external_api_request", "External API Request"
    CALLBACK_RETRY_REQUESTED = "callback_retry_requested", "Callback Retry Requested"

    IMPORTANT = "important", "!!! Important !!!"

    TRANSACTION_ACTUALIZATION = (
        "transaction_actualization",
        "Transaction Actualization (Admin)",
    )
    TRANSACTION_SET_STATUS = "transaction_set_status", "Transaction Set Status (Admin)"
    WITHDRAWAL_STUCK_IN_PROCESSING = (
        "withdrawal_stuck_in_processing",
        "Withdrawal Stuck in Processing",
    )

    INFO = "info", "Info"
    CUSTOMER_REDIRECT_RECEIVED = (
        "customer_redirect_received",
        "Customer Redirect Received",
    )
    CREATE_DEPOSIT_INSTRUCTION = (
        "create_deposit_instruction",
        "Create Deposit Instruction",
    )
    REVERT_TO_INITIAL = "revert_to_initial", "Revert to Initial Status"

    DECLINED_BY_LIMIT = "declined_by_limit", "Declined by Limit"
    DEBUG = "debug", "Debug messages"

    DECLINED_BY_RISK_LIST = "declined_by_risk_list", "Declined by Risk List"


class CallbackType(TextChoices):
    DEPOSIT_ACCOUNT_CREATED = "deposit_account_created", "Deposit Account Created"
    DEPOSIT_RECEIVED = "deposit_received", "Deposit Received"
    TRANSACTION_UPDATED = "transaction_updated", "Transaction Updated"


class CallbackStatus(TextChoices):
    SUCCESS = "success", "Success"
    FAILED = "failed", "Failed"
    PENDING = "pending", "Pending"


class ACLLevel(TextChoices):
    READ = "read", "Read"
    WRITE = "write", "Write"


class PaymentSystemType(TextChoices):
    D24_MERCADOPAGO = "d24_mercadopago", "D24 MercadoPago"


class CeleryQueue(TextChoices):
    HIGH_PRIORITY = "high", "High"
    NORMAL_PRIORITY = "normal", "Normal"
    LOW_PRIORITY = "low", "Low"

    # For service, cleanup tasks
    SERVICE = "service", "Service"


class InstructionType(TextChoices):
    INSTRUCTION_FILE = "instruction_file", "Instruction File"
    INSTRUCTION_QR_CODE = "instruction_qr_code", "Instruction QR Code"
    INSTRUCTION_DEPOSIT_ACCOUNT = (
        "instruction_deposit_account",
        "Instruction Deposit Account",
    )
    INSTRUCTION_REFERENCE = "instruction_reference", "Instruction Reference"


class IncomingCallbackError(TextChoices):
    IP_NOT_WHITELISTED = "ip_not_whitelisted", "IP not whitelisted"
    INVALID_SIGNATURE = "invalid_signature", "Invalid signature"
    PARSING_ERROR = "parsing_error", "Parsing error"
    VALIDATION_ERROR = "validation_error", "Validation error"
    UNKNOWN_ERROR = "unknown_error", "Unknown error"
    AUTHORIZATION_ERROR = "authorization_error", "Authorization error"


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class Permissions:
    CAN_ACTUALIZE_TRANSACTION = "can_actualize_transaction"
    CAN_SET_TRANSACTION_STATUS = "can_set_transaction_status"


class TransactionExtraFields:
    IS_FINALIZATION_PERFORMED = "is_finalization_performed"

    BYPASS_AMOUNT_VALIDATION_FOR = "bypass_amount_validation_for"

    # Periodic status check fields
    COUNT_STATUS_CHECKS_SCHEDULED = "count_status_checks_scheduled"
    LAST_STATUS_CHECK_SCHEDULE = "last_status_check_schedule"

    # Data received in redirect request. I.e. PaRes for 3DS
    REDIRECT_RECEIVED_DATA = "redirect_received_data"


CARD_EXPIRATION_REGEXP = r"^(0[1-9]|1[0-2])/(\d{2}|\d{4})$"
