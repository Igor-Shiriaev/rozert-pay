from dataclasses import dataclass
import datetime
from decimal import Decimal
from typing import Any, Literal, Optional, Union

import pydantic
from pydantic import BaseModel, Field, SecretStr
from rozert_pay.common import const
from rozert_pay.common.const import TransactionStatus
from typing import Callable, TypeVar

T_Callable = TypeVar('T_Callable', bound=Callable)


def _check_currency_compatibility(func: T_Callable) -> T_Callable:
    def wrapper(self, other: Optional['Money']):    # type: ignore
        if func.__name__ in ('__eq__', '__ne__') and not isinstance(other, self.__class__):
            return False
        assert isinstance(other, self.__class__), f'Incorrect value {other} of type {type(other)}'
        assert other.currency == self.currency, f'Other currency {other.currency} is not equal to {self.currency}'
        return func(self, other)
    return wrapper  # type: ignore


@dataclass
class Money:
    value: Decimal
    currency: str

    def __neg__(self):      # type: ignore
        return self.__class__(
            value=-self.value,
            currency=self.currency
        )

    @_check_currency_compatibility
    def __add__(self, other: 'Money') -> 'Money':
        return self.__class__(
            value=self.value + other.value,
            currency=self.currency
        )

    @_check_currency_compatibility
    def __sub__(self, other: 'Money') -> 'Money':
        return self.__class__(
            value=self.value - other.value,
            currency=self.currency
        )

    def __mul__(self, other: Union['Money', int, float, Decimal]) -> 'Money':
        if isinstance(other, (int, float, Decimal)):
            return self.__class__(
                value=self.value * Decimal(other),
                currency=self.currency
            )
        assert isinstance(other, self.__class__), str(other)
        assert other.currency == self.currency, 'Currency is not equal'
        return self.__class__(
            value=self.value * other.value,
            currency=self.currency
        )

    def __truediv__(self, other: Union['Money', int, float, Decimal]) -> 'Money':
        if isinstance(other, (int, float, Decimal)):
            return self.__class__(
                value=self.value / Decimal(other),
                currency=self.currency
            )
        assert isinstance(other, self.__class__), str(other)
        assert other.currency == self.currency, 'Currency is not equal'
        return self.__class__(
            value=self.value / other.value,
            currency=self.currency
        )

    def __floordiv__(self, other: Union['Money', int, float, Decimal]) -> 'Money':
        if isinstance(other, (int, float, Decimal)):
            return self.__class__(
                value=self.value // Decimal(other),
                currency=self.currency
            )
        assert isinstance(other, self.__class__), str(other)
        assert other.currency == self.currency, 'Currency is not equal'
        return self.__class__(
            value=self.value // other.value,
            currency=self.currency
        )

    def __bool__(self) -> bool:
        return bool(self.value)

    @_check_currency_compatibility
    def __lt__(self, other: 'Money') -> bool:
        return self.value < other.value

    @_check_currency_compatibility
    def __le__(self, other: 'Money') -> bool:
        return self.value <= other.value

    @_check_currency_compatibility
    def __eq__(self, other: Optional['Money']) -> bool: # type: ignore
        if other is None:
            return False
        return self.value == other.value

    @_check_currency_compatibility
    def __ne__(self, other: Optional['Money']) -> bool: # type: ignore
        if other is None:
            return False
        return self.value != other.value

    @_check_currency_compatibility
    def __gt__(self, other: 'Money') -> bool:
        return self.value > other.value

    @_check_currency_compatibility
    def __ge__(self, other: 'Money') -> bool:
        return self.value >= other.value

    def __abs__(self) -> 'Money':
        return self.__class__(  # type: ignore
            value=abs(self.value),
            currency=self.currency
        )

    def __json__(self) -> dict:
        return {
            'value': serialize_decimal(self.value),
            'currency': self.currency,
        }


class RemoteTransactionStatus(pydantic.BaseModel):
    operation_status: TransactionStatus
    raw_data: dict  # type: ignore[type-arg]
    id_in_payment_system: Optional[str] = None
    decline_code: Optional[str] = None
    decline_reason: Optional[str] = None
    redirect_form_data: Optional[dict] = None
    client_extra: Optional[dict] = None  # type: ignore[type-arg]
    remote_amount: Optional[Money] = None
    refund_amount: Optional[Money] = None

    transaction_id: Optional[int] = None

    # If payment system returns account identifier in response,
    # it should be presented here.
    external_account_id: Optional[str] = None

    @classmethod
    def initial(
        cls,
        *,
        raw_data: dict[str, Any],
        id_in_payment_system: Optional[str] = None,
        transaction_id: Optional[int] = None,
    ) -> "RemoteTransactionStatus":
        return cls(
            operation_status=TransactionStatus.PENDING,
            raw_data=raw_data,
            id_in_payment_system=id_in_payment_system,
            transaction_id=transaction_id,
        )


class UserData(BaseModel):
    email: Optional[str] = None
    phone: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    post_code: Optional[str] = None
    city: Optional[str] = None
    country: Optional[str] = None
    state: Optional[str] = None
    address: Optional[str] = None
    language: Optional[str] = None
    date_of_birth: Optional[datetime.date] = None
    ip_address: Optional[str] = None
    province: Optional[str] = None

    @property
    def full_name(self) -> str:
        assert self.first_name is not None
        assert self.last_name is not None
        return f"{self.first_name} {self.last_name}"


class PaymentClientWithdrawResponse(BaseModel):
    # status must be FAILED only if 100% sure that money are not sent to the user.
    # Otherwise it must be PENDING.
    status: Literal[TransactionStatus.PENDING, TransactionStatus.FAILED]
    id_in_payment_system: str | None
    raw_response: dict[str, Any]

    decline_code: Optional[str] = None
    decline_reason: Optional[str] = None

    def clean(self) -> None:
        if self.status == TransactionStatus.FAILED:
            assert (
                self.decline_code is not None
            ), "decline_code must be set if status is FAILED"


class PaymentClientDepositResponse(BaseModel):
    status: Literal[TransactionStatus.PENDING, TransactionStatus.FAILED]
    raw_response: dict[str, Any]

    id_in_payment_system: str | None = None
    decline_code: str | None = None
    decline_reason: str | None = None

    # Use this field to redirect customer to intermediate pages/send some forms
    customer_redirect_form_data: dict | None = None

    def clean(self) -> None:
        if self.status == TransactionStatus.FAILED:
            assert (
                self.decline_code is not None
            ), "decline_code must be set if status is FAILED"


class PaymentClientDepositFinalizeResponse(BaseModel):
    # Status can be FAILED / SUCCESS. We don't return PENDING status here.
    # Deposit approval must be checked with payment system via callbacks / status checks.
    status: Literal[
        TransactionStatus.FAILED, TransactionStatus.SUCCESS, TransactionStatus.PENDING
    ]
    raw_response: dict[str, Any]

    decline_code: Optional[str] = None
    decline_reason: Optional[str] = None

    # TODO: handle card token
    card_token: Optional[str] = None


class Webhook(BaseModel):
    id: str
    url: str
    raw_data: dict[str, Any] = pydantic.Field(repr=False)


class CardData(BaseModel):
    card_num: SecretStr
    card_expiration: str = Field(pattern=const.CARD_EXPIRATION_REGEXP)
    card_holder: str
    card_cvv: SecretStr | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "card_num": self.card_num.get_secret_value(),
            "card_cvv": self.card_cvv.get_secret_value() if self.card_cvv else None,
            "card_expiration": self.card_expiration,
            "card_holder": self.card_holder,
        }

    @property
    def expiry_month(self) -> str:
        return self.card_expiration.split("/")[0]

    @property
    def expiry_year(self) -> str:
        return self.card_expiration.split("/")[1]
