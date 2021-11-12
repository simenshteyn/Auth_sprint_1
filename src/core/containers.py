from dependency_injector import containers, providers
from dependency_injector.ext import flask
from flask import Flask

from services.role import RoleService


class Container(containers.DeclarativeContainer):
    app = flask.Application(Flask, __name__)

    wiring_config = containers.WiringConfiguration(packages=["api.v1.routes"])

    role_service = providers.Factory(RoleService)
