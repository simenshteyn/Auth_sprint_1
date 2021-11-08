from aioredis import Redis
from db import db


class UserService:
    def __init__(self, redis: Redis):
        self.redis = redis

    def create_user(self, username: str, password: str, email: str):
        pass

