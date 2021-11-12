from dependency_injector import containers, providers

from services.role import RoleService

# from db.pg import db


class Container(containers.DeclarativeContainer):
    wiring_config = containers.WiringConfiguration(packages=["api.v1.routes"])
    # role_service = providers.Factory(RoleService, db=db)
    role_service = providers.Factory(RoleService)

