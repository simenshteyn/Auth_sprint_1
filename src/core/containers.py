from dependency_injector import containers, providers

from db.pg import db

from services.role import RoleService


class Container(containers.DeclarativeContainer):
    role_service = providers.Factory(
        RoleService,
        storage=db
    )
