"""Containers module."""

from dependency_injector import containers, providers

from services.user import UserService


class Container(containers.DeclarativeContainer):
    user_service = providers.Factory(
        UserService,
    )
