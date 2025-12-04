"""
Define custom user model with email as unique identifier.
"""
from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import AbstractUser
from django.db import models


# Manager and QS
class UserManager(BaseUserManager["User"]):
    def create_user(self, email: str, password: str) -> "User":
        if not email:
            raise ValueError("Email is required")
        user = self.model(email=self.normalize_email(email))
        user.set_password(password)  # type: ignore
        user.save()
        return user  # type: ignore

    def create_superuser(self, email: str, password: str) -> "User":
        user = self.create_user(email, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user


class User(AbstractUser):
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []
    objects = UserManager()  # type: ignore

    email = models.EmailField(unique=True)
    username = None  # type: ignore

    def __str__(self) -> str:
        return self.email
