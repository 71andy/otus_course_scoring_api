import redis
from datetime import datetime


class Store:
    def __init__(self):
        self.redis = redis.StrictRedis(
            charset="utf-8", decode_responses=True, socket_timeout=2, socket_connect_timeout=2
        )
        self._cache = {}

    def get(self, key):
        try:
            value = self.redis.get(key)
            return value
        except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError):
            return None

    def set(self, key, value):
        try:
            return self.redis.set(key, value)
        except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError):
            return None

    def cache_get(self, key):
        if key in self._cache:
            dt = datetime.timestamp(datetime.utcnow()) - self._cache[key]["unix_time"]
            ttl = self._cache[key]["ttl"]
            if ttl == 0 or dt < ttl:
                return self._cache[key]["value"]
            else:
                del self._cache[key]

        return None

    def cache_set(self, key, value: int | float, time_to_live: int = 0):
        self._cache[key] = {
            "value": value,
            "ttl": time_to_live,
            "unix_time": datetime.timestamp(datetime.utcnow()),
        }
