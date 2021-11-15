from dependency_injector import containers, providers
from dependency_injector.ext import flask
from flask import Flask

from services.role import RoleService
from services.user import UserService
from services.permission import PermissionService


class Container(containers.DeclarativeContainer):
    app = flask.Application(Flask, __name__)

    wiring_config = containers.WiringConfiguration(
        packages=[
            'api.v1.routes',
            'api.v1.user.routes',
            'api.v1.role.routes',
            'api.v1.permission.routes'
        ],
    )

    user_service = providers.Factory(UserService)
    role_service = providers.Factory(RoleService)
    perm_service = providers.Factory(PermissionService)
