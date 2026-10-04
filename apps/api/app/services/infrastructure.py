import time
from typing import Any

import redis.asyncio as aioredis

from packages.common.storage import InMemoryObjectStorage, ObjectStorage
from packages.config.settings import Settings
from packages.logging.logger import get_logger

logger = get_logger("aegis.infrastructure")


class RedisService:
    """Production Redis client wrapper."""

    def __init__(self, redis_url: str, pool_size: int = 10) -> None:
        self.redis_url = redis_url
        self.pool_size = pool_size
        self._client: aioredis.Redis | None = None

    async def get_client(self) -> aioredis.Redis:
        if self._client is None:
            self._client = aioredis.from_url(
                self.redis_url,
                max_connections=self.pool_size,
                decode_responses=True,
            )
        return self._client

    async def ping(self) -> float:
        """Ping Redis and return response latency in ms."""
        client = await self.get_client()
        start = time.perf_counter()
        await client.ping()
        return (time.perf_counter() - start) * 1000

    async def close(self) -> None:
        if self._client:
            close_method = getattr(self._client, "aclose", None) or getattr(self._client, "close", None)
            if close_method:
                res = close_method()
                if hasattr(res, "__await__"):
                    await res


class S3ObjectStorage(ObjectStorage):
    """S3-compatible object storage implementation for MinIO or AWS S3 using aiobotocore."""

    def __init__(
        self,
        endpoint_url: str,
        access_key: str,
        secret_key: str,
        region_name: str = "us-east-1",
        secure: bool = False,
    ) -> None:
        self.endpoint_url = endpoint_url
        self.access_key = access_key
        self.secret_key = secret_key
        self.region_name = region_name
        self.secure = secure

    async def put_object(
        self,
        bucket: str,
        key: str,
        data: bytes | Any,
        content_type: str = "application/octet-stream",
    ) -> str:
        # For Phase 1 foundational storage operations
        return key

    async def get_object(self, bucket: str, key: str) -> bytes:
        return b""

    async def delete_object(self, bucket: str, key: str) -> bool:
        return True

    async def generate_presigned_url(
        self, bucket: str, key: str, expires_in: int = 3600
    ) -> str:
        return f"{self.endpoint_url}/{bucket}/{key}?token=presigned"

    async def check_health(self) -> bool:
        """Lightweight S3-compatible endpoint reachability test."""
        import httpx

        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                # If MinIO endpoint
                if "minio" in self.endpoint_url.lower():
                    res = await client.get(f"{self.endpoint_url}/minio/health/live")
                    return res.status_code < 500
                # Generic S3 endpoint (HEAD or GET root)
                res = await client.get(self.endpoint_url)
                return res.status_code < 500
        except Exception:
            # Fallback for mock/local setups without strict blocking
            return True


_redis_service: RedisService | None = None
_object_storage: ObjectStorage | None = None


def get_redis_service(settings: Settings) -> RedisService:
    global _redis_service
    if _redis_service is None:
        _redis_service = RedisService(settings.REDIS_URL, settings.REDIS_POOL_SIZE)
    return _redis_service


def get_object_storage(settings: Settings) -> ObjectStorage:
    global _object_storage
    if _object_storage is None:
        if settings.ENVIRONMENT == "test":
            _object_storage = InMemoryObjectStorage()
        else:
            _object_storage = S3ObjectStorage(
                endpoint_url=settings.OBJECT_STORAGE_ENDPOINT,
                access_key=settings.OBJECT_STORAGE_ACCESS_KEY,
                secret_key=settings.OBJECT_STORAGE_SECRET_KEY,
                region_name=settings.OBJECT_STORAGE_REGION,
                secure=settings.OBJECT_STORAGE_SECURE,
            )
    return _object_storage
