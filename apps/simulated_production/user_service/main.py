from fastapi import HTTPException
from pydantic import BaseModel

from packages.logging.logger import get_logger
from packages.service_runtime.base import create_simulated_service
from packages.service_runtime.metrics import USER_REQUESTS_TOTAL

logger = get_logger("service.user-service")
app = create_simulated_service(service_name="user-service", version="1.0.0")

# In-memory customer directory for simulation
USERS = {
    "usr_101": {"id": "usr_101", "name": "Alice Engineer", "tier": "enterprise", "active": True},
    "usr_102": {"id": "usr_102", "name": "Bob Reliability", "tier": "standard", "active": True},
}


class UserResponse(BaseModel):
    id: str
    name: str
    tier: str
    active: bool


@app.get("/users/{user_id}", response_model=UserResponse)
async def get_user(user_id: str) -> UserResponse:
    USER_REQUESTS_TOTAL.labels(service="user-service", operation="get_user").inc()
    if user_id not in USERS:
        logger.warning("User %s not found", user_id)
        raise HTTPException(status_code=404, detail="User not found")

    user_info = USERS[user_id]
    logger.info("Retrieved profile for user %s", user_id)
    return UserResponse(
        id=str(user_info["id"]),
        name=str(user_info["name"]),
        tier=str(user_info["tier"]),
        active=bool(user_info["active"]),
    )
