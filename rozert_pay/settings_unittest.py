import os

from .settings import *  # NOQA

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql_psycopg2",
        "NAME": "development",
        "USER": "development",
        "PASSWORD": "development",
        "HOST": os.environ.get("POSTGRES_HOST", "localhost"),
        "PORT": os.environ.get("POSTGRES_PORT", 5432),
    },
}

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": f"redis://{os.environ.get('REDIS_HOST', 'localhost')}:6379/1",
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
        },
    },
}

CELERY_TASK_ALWAYS_EAGER = True

IS_UNITTESTS = True

REST_FRAMEWORK["TEST_REQUEST_RENDERER_CLASSES"] = (  # type: ignore[assignment] # noqa
    "rest_framework.renderers.MultiPartRenderer",
    "rest_framework.renderers.JSONRenderer",
    "rest_framework.renderers.HTMLFormRenderer",
)
