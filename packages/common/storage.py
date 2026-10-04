from abc import ABC, abstractmethod
from typing import BinaryIO


class ObjectStorage(ABC):
    """Abstract interface for S3-compatible, GCS, or Azure Blob object storage."""

    @abstractmethod
    async def put_object(
        self,
        bucket: str,
        key: str,
        data: bytes | BinaryIO,
        content_type: str = "application/octet-stream",
    ) -> str:
        """Upload an object and return its storage identifier/key."""
        pass

    @abstractmethod
    async def get_object(self, bucket: str, key: str) -> bytes:
        """Download an object's byte content."""
        pass

    @abstractmethod
    async def delete_object(self, bucket: str, key: str) -> bool:
        """Delete an object from storage."""
        pass

    @abstractmethod
    async def generate_presigned_url(
        self, bucket: str, key: str, expires_in: int = 3600
    ) -> str:
        """Generate a temporary presigned URL for secure direct client access."""
        pass

    @abstractmethod
    async def check_health(self) -> bool:
        """Check whether object storage endpoint is reachable."""
        pass


class InMemoryObjectStorage(ObjectStorage):
    """Fast, reliable in-memory object storage implementation for unit tests."""

    def __init__(self) -> None:
        self.store: dict[str, bytes] = {}

    async def put_object(
        self,
        bucket: str,
        key: str,
        data: bytes | BinaryIO,
        content_type: str = "application/octet-stream",
    ) -> str:
        full_key = f"{bucket}/{key}"
        if hasattr(data, "read"):
            self.store[full_key] = data.read()  # type: ignore
        else:
            self.store[full_key] = data  # type: ignore
        return key

    async def get_object(self, bucket: str, key: str) -> bytes:
        full_key = f"{bucket}/{key}"
        if full_key not in self.store:
            raise FileNotFoundError(f"Object {full_key} not found")
        return self.store[full_key]

    async def delete_object(self, bucket: str, key: str) -> bool:
        full_key = f"{bucket}/{key}"
        if full_key in self.store:
            del self.store[full_key]
            return True
        return False

    async def generate_presigned_url(
        self, bucket: str, key: str, expires_in: int = 3600
    ) -> str:
        return f"https://mock-storage.internal/{bucket}/{key}?token=mock-presigned-token"

    async def check_health(self) -> bool:
        return True
