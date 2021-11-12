from redis import Redis

from core import settings

redis = Redis(host=settings.config.redis_host,
              port=settings.config.redis_port)
