import json

import redis

from .config import REDIS_URL

r = redis.Redis.from_url(REDIS_URL)


def cache_profile(user_id: int, name: str, email: str, phone: str):
    # No TTL: the profile stays in Redis forever.
    r.set(f"profile:{user_id}", json.dumps({"name": name, "email": email, "phone": phone}))
