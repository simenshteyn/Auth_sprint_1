from dependency_injector.wiring import inject, Provide
from flask import Blueprint, jsonify

from core.containers import Container
from services.role import RoleService

role = Blueprint('role', __name__, url_prefix='/role')


@role.route('/')
@inject
def get_roles(role_service: RoleService = Provide[Container.role_service]):
    role_list = role_service.get_roles_list()
    return jsonify(role_list)
