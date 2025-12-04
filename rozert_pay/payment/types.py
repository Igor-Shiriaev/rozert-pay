import typing as ty

import pydantic

if ty.TYPE_CHECKING:  # pragma: no cover
    from rozert_pay.payment.services import base_classes


T_Credentials = ty.TypeVar("T_Credentials", bound=pydantic.BaseModel)
T_Client = ty.TypeVar("T_Client", bound="base_classes.BasePaymentClient")  # type: ignore[type-arg]
T_SandboxClient = ty.TypeVar(
    "T_SandboxClient",
    bound="base_classes.BaseSandboxClientMixin",  # type: ignore[type-arg]
    contravariant=True,
)

CurrencyWalletId = ty.NewType("CurrencyWalletId", int)
CustomerWalletExtraKey = ty.NewType("CustomerWalletExtraKey", str)


WalletId = ty.NewType("WalletId", int)

ExternalCustomerId = ty.NewType("ExternalCustomerId", str)
CustomerId = ty.NewType("CustomerId", int)
MerchantID = ty.NewType("MerchantID", int)
TransactionId = ty.NewType("TransactionId", int)
