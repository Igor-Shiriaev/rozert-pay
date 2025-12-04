from django.core.validators import RegexValidator
from pydantic import BaseModel
from rest_framework import serializers
from rozert_pay.common import const
from rozert_pay.payment.models import PaymentTransaction


class _CardSerializer(serializers.Serializer):
    card_num = serializers.CharField(
        required=True,
        help_text="Card number",
        validators=[
            RegexValidator(
                regex=r"^\d{10,20}$",
                message="Incorrect card num",
            )
        ],
    )
    card_expiration = serializers.CharField(
        required=True,
        help_text="Card expiration date",
        validators=[
            RegexValidator(
                regex=const.CARD_EXPIRATION_REGEXP,
                message="Expiration date must be in MM/YY format.",
            )
        ],
    )
    card_holder = serializers.CharField(
        required=True,
        help_text="Card holder name",
    )
    card_cvv = serializers.CharField(
        required=True,
        help_text="Card CVV",
        validators=[
            RegexValidator(
                regex=r"^\d*$",
                message="CVV must be 3 digits.",
            )
        ],
        allow_null=True,
        allow_blank=True,
    )


class _CardNoCVVSerializer(_CardSerializer):
    card_cvv = None  # type: ignore[assignment]


class CardSerializerMixin(serializers.Serializer):
    card = _CardSerializer(
        required=True,
        help_text="Card details",
    )


class CardNoCVVSerializerMixin(serializers.Serializer):
    card = _CardNoCVVSerializer(
        required=True,
        help_text="Card details without CVV",
    )


class CardTokenSerializerMixin(serializers.Serializer):
    class _CardTokenSerialzer(serializers.Serializer):
        card_token = serializers.UUIDField()

    card = _CardTokenSerialzer()


class CardBrowserDataSerializerModel(BaseModel):
    accept_header: str = "text/html"
    javascript_enabled: bool = True
    java_enabled: bool = False
    language: str = "en"
    screen_height: int = 768
    screen_width: int = 1024
    time_difference: str = "+3"
    user_agent: str = "User-agent"
    color_depth: int = 48
    challenge_window_size: str = "04"


class CardBrowserDataSerializer(serializers.Serializer):
    EXTRA_FIELD = "browser_data"

    accept_header = serializers.CharField(max_length=255)
    javascript_enabled = serializers.BooleanField()
    java_enabled = serializers.BooleanField()
    language = serializers.CharField()
    screen_height = serializers.IntegerField()
    screen_width = serializers.IntegerField()
    time_difference = serializers.CharField()
    user_agent = serializers.CharField()
    # color_depth = serializers.IntegerField()

    @classmethod
    def from_trx(cls, trx: PaymentTransaction) -> CardBrowserDataSerializerModel:
        return CardBrowserDataSerializerModel(**trx.extra.get(cls.EXTRA_FIELD))
