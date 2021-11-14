from http import HTTPStatus

from dependency_injector.wiring import inject, Provide
from flask import Blueprint, jsonify, make_response, request
from pydantic import BaseModel, ValidationError

from core.containers import Container
from core.utils import make_service_exception
from services.role import RoleService

role = Blueprint('role', __name__, url_prefix='/role')


class RoleCreationRequest(BaseModel):
    role_name: str


@role.route('/', methods=['GET'])
@inject
def get_roles(role_service: RoleService = Provide[Container.role_service]):
    role_list = role_service.get_roles_list()
    return jsonify(role_list)


@role.route('/', methods=['POST'])
@inject
def create_role(role_service: RoleService = Provide[Container.role_service]):
    request_json = request.json
    try:
        create_request = RoleCreationRequest(**request_json)
    except ValidationError as err:
        service_exception = make_service_exception(err)
        return make_response(
            jsonify(service_exception),
            HTTPStatus.BAD_REQUEST
        )

    try:
        uuid, role_name = role_service.create_role(create_request.role_name)
    except Exception as err:
        return make_response(jsonify(str(err)), HTTPStatus.BAD_REQUEST)

    return make_response(
        jsonify(uuid=uuid, role_name=role_name),
        HTTPStatus.OK
    )
