from http import HTTPStatus

from dependency_injector.wiring import inject, Provide
from flask import Blueprint, make_response, request, jsonify
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
        new_role = role_service.create_role(create_request.role_name)
    except Exception as err:
        return make_response(jsonify(str(err)), HTTPStatus.BAD_REQUEST)

    return make_response(
        jsonify(uuid=new_role.role_id, role_name=new_role.role_name),
        HTTPStatus.OK
    )


@role.route('/<uuid:role_uuid>', methods=['PATCH'])
@inject
def edit_role(role_uuid: str,
              role_service: RoleService = Provide[Container.role_service]):
    request_json = request.json
    try:
        edit_request = RoleCreationRequest(**request_json)
    except ValidationError as err:
        service_exception = make_service_exception(err)
        return make_response(
            jsonify(service_exception),
            HTTPStatus.BAD_REQUEST
        )
    try:
        edited_role = role_service.edit_role(
            role_id=role_uuid,
            role_name=edit_request.role_name
        )
    except Exception as err:
        return make_response(jsonify(str(err)), HTTPStatus.BAD_REQUEST)

    return make_response(
        jsonify(uuid=edited_role.role_id, role_name=edited_role.role_name),
        HTTPStatus.OK
    )


@role.route('/<uuid:role_uuid>', methods=['DELETE'])
@inject
def delete_role(role_uuid: str,
                role_service: RoleService = Provide[Container.role_service]):
    try:
        deleted_role = role_service.delete_role(role_id=role_uuid)
    except Exception as err:
        return make_response(jsonify(str(err)), HTTPStatus.BAD_REQUEST)
    return make_response(
        jsonify(uuid=deleted_role.role_id, role_name=deleted_role.role_name),
        HTTPStatus.OK
    )
