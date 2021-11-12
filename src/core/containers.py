"""Containers module."""
import os

from dependency_injector import containers, providers
from redis import Redis

from services.user import UserService


class Container(containers.DeclarativeContainer):
    user_service = providers.Factory(
        UserService,
    )

    redis = providers.Factory(
        Redis, host=os.getenv('REDIS_HOST'), port=os.getenv('redis_port')
    )
