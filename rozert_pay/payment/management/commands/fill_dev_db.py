import os
import uuid
from typing import Any

from django.core.management import BaseCommand

from rozert_pay.account.models import User
from rozert_pay.common import const
from rozert_pay.payment.models import (
    CurrencyWallet,
    Merchant,
    MerchantGroup,
    PaymentSystem,
    Wallet,
)


class Command(BaseCommand):
    help = "Fill database with development entities"

    def handle(self, *args: Any, **options: Any) -> None:
        self.stdout.write("Creating development entities...")

        # 1. Create admin user
        admin_email = "admin@example.com"
        admin_password = "admin123"
        admin_user, created = User.objects.get_or_create(
            email=admin_email,
            defaults={"is_staff": True, "is_superuser": True},
        )
        if created:
            admin_user.set_password(admin_password)
            admin_user.save()
            self.stdout.write(self.style.SUCCESS(
                f"Created admin user: {admin_email} / {admin_password}"
            ))
        else:
            self.stdout.write(f"Admin user already exists: {admin_email}")

        # 2. Create merchant group user
        mg_email = "merchant@example.com"
        mg_password = "merchant123"
        mg_user, created = User.objects.get_or_create(
            email=mg_email,
            defaults={"is_staff": False, "is_superuser": False},
        )
        if created:
            mg_user.set_password(mg_password)
            mg_user.save()
            self.stdout.write(self.style.SUCCESS(
                f"Created merchant user: {mg_email} / {mg_password}"
            ))
        else:
            self.stdout.write(f"Merchant user already exists: {mg_email}")

        # 3. Create merchant group
        merchant_group, created = MerchantGroup.objects.get_or_create(
            name="Dev Merchant Group",
            defaults={"user": mg_user},
        )
        if created:
            self.stdout.write(self.style.SUCCESS(
                f"Created merchant group: {merchant_group.name}"
            ))
        else:
            self.stdout.write(
                f"Merchant group already exists: {merchant_group.name}"
            )

        # 4. Create payment system
        payment_system, created = PaymentSystem.objects.get_or_create(
            type=const.PaymentSystemType.D24_MERCADOPAGO,
            defaults={
                "name": "D24 MercadoPago",
                "slug": "d24-mercadopago",
                "is_active": True,
                "ip_whitelist_enabled": False,
            },
        )
        if created:
            self.stdout.write(self.style.SUCCESS(
                f"Created payment system: {payment_system.name}"
            ))
        else:
            self.stdout.write(
                f"Payment system already exists: {payment_system.name}"
            )

        # 5. Create production merchant (sandbox=False to use real client)
        secret_key = f"dev_secret_{uuid.uuid4().hex[:16]}"
        merchant, created = Merchant.objects.get_or_create(
            name="Dev Merchant",
            defaults={
                "merchant_group": merchant_group,
                "secret_key": secret_key,
                "sandbox": False,
            },
        )
        if created:
            merchant.login_users.add(mg_user, admin_user)
            self.stdout.write(self.style.SUCCESS(
                f"Created merchant: {merchant.name} (secret: {secret_key})"
            ))
        else:
            self.stdout.write(f"Merchant already exists: {merchant.name}")

        # 6. Create wallet with D24 credentials from env
        credentials = {
            "base_url": "https://api-stg.com",
            "base_url_for_credit_cards": "https://cc-api-stg.com",
            "deposit_signature_key": "",
            "cashout_login": "",
            "cashout_pass": "",
            "cashout_signature_key": "",
            "x_login": "",
        }

        wallet, created = Wallet.objects.get_or_create(
            merchant=merchant,
            system=payment_system,
            defaults={
                "name": "Dev Wallet",
                "credentials": credentials,
            },
        )
        if created:
            self.stdout.write(self.style.SUCCESS(
                f"Created wallet: {wallet.name} (uuid: {wallet.uuid})"
            ))
        else:
            self.stdout.write(
                f"Wallet already exists: {wallet.name} (uuid: {wallet.uuid})"
            )

        # 7. Create currency wallet for MXN
        currency_wallet, created = CurrencyWallet.objects.get_or_create(
            wallet=wallet,
            currency="MXN",
            defaults={"operational_balance": 100000},
        )
        if created:
            self.stdout.write(self.style.SUCCESS(
                f"Created currency wallet: {currency_wallet.currency}"
            ))
        else:
            self.stdout.write(
                f"Currency wallet already exists: {currency_wallet.currency}"
            )

        # Summary
        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS("=" * 50))
        self.stdout.write(self.style.SUCCESS("Done!"))
        self.stdout.write(self.style.SUCCESS("=" * 50))
        self.stdout.write(f"  Wallet UUID: {wallet.uuid}")
        self.stdout.write(f"  Currency: {currency_wallet.currency}")
