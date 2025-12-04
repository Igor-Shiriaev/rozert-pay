import contextlib
import logging
import threading
import time
import typing as ty
from datetime import timedelta

from django.core.cache import caches
from django_redis.cache import RedisCache  # type: ignore[import-untyped]
from django_redis.client import DefaultClient  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)


CacheKey = ty.NewType("CacheKey", str)

T = ty.TypeVar("T")

_redis_client: DefaultClient = caches["default"].client._backend  # type: ignore[attr-defined]

# Don't use Django in memory cache, because it does unnecessary pickle operations
V = ty.TypedDict(
    "V",
    {
        "val": ty.Any,
        "expires": float,
        "created": float,
    },
)
_cache: dict[CacheKey, V] = {}

_locals = threading.local()


@contextlib.contextmanager
def disable_cache_for_thread() -> ty.Generator[None, None, None]:
    _locals.disable = True
    yield
    _locals.disable = False


def _memory_caching(
    key: CacheKey,
    tp: type[T],
    on_miss: ty.Callable[[], T] | None = None,
    ttl: timedelta | None = None,
) -> T | None:
    if getattr(_locals, "disable", False):
        return on_miss() if on_miss else None

    if on_miss:
        assert ttl

    if val := _cache.get(key):
        if val["expires"] > time.time():
            b = _redis_client.get(f"cache:last_invalidation_request:{key}")

            # If no last_invalidation_request in redis it means we can use cached value
            last_invalidation_request = float(b) if b else 0
            if val["created"] > last_invalidation_request:
                return val["val"]

        # key invalidated by some reason
        _cache.pop(key, None)  # pragma: no cover

    if on_miss:
        assert ttl
        real_val = on_miss()
        memory_cache_set(key, real_val, ttl)
        return real_val

    return None


def memory_cache_get(key: CacheKey, tp: type[T]) -> T | None:
    return _memory_caching(key, tp)


def memory_cache_get_set(
    key: CacheKey, tp: type[T], on_miss: ty.Callable[[], T], ttl: timedelta
) -> T:
    v = _memory_caching(
        key=key,
        tp=tp,
        on_miss=on_miss,
        ttl=ttl,
    )
    assert v is not None
    return v


def memory_cache_set(key: CacheKey, val: T, ttl: timedelta) -> None:
    _cache[key] = {
        "val": val,
        "expires": time.time() + ttl.total_seconds(),
        "created": time.time(),
    }


def memory_cache_invalidate(key: CacheKey) -> None:
    # Redis TTL should be enough for all processes to read this value and invalidate it's local caches.
    # I expect 1 day is enough.
    _redis_client.set(
        f"cache:last_invalidation_request:{key}",
        str(time.time()),
        timeout=timedelta(days=1).total_seconds(),
    )


class _CleanupCacheThread(threading.Thread):
    def __init__(self) -> None:
        super().__init__(daemon=True)

    def run(self) -> None:
        logger.info("Starting cleanup cache thread")
        while True:
            self._one_cycle()

    def _one_cycle(self, sleep: bool = True) -> None:
        try:
            for key, value in list(_cache.items()):
                if value["expires"] < time.time():
                    _cache.pop(key, None)

            if len(_cache) > 10000:
                logger.error(
                    "Too big cache!",
                    extra={
                        "keys_sample": list(_cache.keys())[:100],
                    },
                )
        except Exception:
            logger.exception("Error in cache cleanup thread")  # pragma: no cover
        finally:
            if sleep:
                time.sleep(60)


_CleanupCacheThread().start()


_redis_cache: RedisCache = caches["default"]


# Redis caching
def _redis_caching(
    key: CacheKey,
    tp: type[T],
    on_miss: ty.Callable[[], T] | None = None,
    ttl: timedelta | None = None,
) -> T | None:
    if getattr(_locals, "disable", False):
        return on_miss() if on_miss else None

    if on_miss:
        assert ttl

    if val := _redis_cache.get(key):
        return val

    if on_miss:
        assert ttl
        real_val = on_miss()
        memory_cache_set(key, real_val, ttl)
        return real_val

    return None


def redis_cache_set(key: CacheKey, val: T, ttl: timedelta) -> None:
    _redis_cache.set(key, val, timeout=ttl.total_seconds())


def redis_cache_get(key: CacheKey, tp: type[T]) -> T | None:
    return _redis_caching(key, tp)


def redis_cache_get_set(
    *,
    key: CacheKey,
    tp: type[T],
    on_miss: ty.Callable[[], T] | None = None,
    ttl: timedelta | None = None,
) -> T:
    v = _redis_caching(
        key=key,
        tp=tp,
        on_miss=on_miss,
        ttl=ttl,
    )
    assert v is not None
    return v
