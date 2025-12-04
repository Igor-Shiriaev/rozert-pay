from datetime import datetime

from django.utils import timezone


def calculate_clabe_check_digit(account_number: str) -> int:
    """See https://stpmex.zendesk.com/hc/en-us/articles/360014675872-Calculation-of-the-CLABE-account-verification-digit"""
    if len(account_number) != 17:
        raise ValueError("Account number must be 18 digits long")

    ponderation = [3, 7, 1] * 6

    step1 = [int(account_number[i]) * ponderation[i] for i in range(17)]
    step2 = [x % 10 for x in step1]
    A = sum(step2)
    A = A % 10
    B = 10 - A
    control_digit = B % 10
    return control_digit


def validate_mexican_curp(curp: str) -> str:
    if len(curp) != 18:
        raise ValueError("CURP must be 18 digits long")

    curp_birthdate = datetime.strptime(curp[4:10], "%y%m%d").date()

    if (timezone.now().date() - curp_birthdate).days // 365 < 18:
        raise ValueError("User must be at least 18 years old")
    return curp


def validate_clabe(clabe: str) -> str:
    if len(clabe) != 18:
        raise ValueError("CLABE must be 18 digits long")

    check_digit_to_verify = calculate_clabe_check_digit(clabe[:17])
    check_digit = int(clabe[17])
    if check_digit_to_verify != check_digit:
        raise ValueError("Invalid CLABE")
    return clabe
