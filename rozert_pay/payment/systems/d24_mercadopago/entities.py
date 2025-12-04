from pydantic import BaseModel, SecretStr


class D24Credentials(BaseModel):
    base_url: str = "https://api-stg.com"
    base_url_for_credit_cards: str = "https://cc-api-stg.com"
    deposit_signature_key: SecretStr = SecretStr("")
    cashout_login: str = ""
    cashout_pass: SecretStr = SecretStr("")
    cashout_signature_key: SecretStr = SecretStr("")
    x_login: str = ""
