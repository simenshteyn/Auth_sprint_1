from dependency_injector.wiring import inject, Provide
from flask import Blueprint, jsonify

from core.containers import Container
from services.role import RoleService

v1 = Blueprint('v1', __name__, url_prefix='/v1')


@v1.route('/')
def index():
    return jsonify(result="Hello, World!")


@v1.route('/role')
@inject
def role(role_service: RoleService = Provide[Container.role_service]):
    role_list = role_service.get_roles_list()
    return jsonify(role_list)
