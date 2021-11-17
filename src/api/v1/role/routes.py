from http import HTTPStatus

from dependency_injector.wiring import inject, Provide
from flask import Blueprint, make_response, request, jsonify
from pydantic import BaseModel, ValidationError

from core.containers import Container
from core.utils import make_service_exception, ServiceException
from models.permission import Permission
from services.role import RoleService

role = Blueprint('role', __name__, url_prefix='/role')


class RoleCreationRequest(BaseModel):
    role_name: str


class PermissionSetRequest(BaseModel):
    permission_uuid: str


@role.route('/', methods=['GET'])
@inject
def get_roles(role_service: RoleService = Provide[Container.role_service]):
    role_list = role_service.get_roles_list()
    result = [{'uuid': role.role_id,
               'role_name': role.role_name} for role in role_list]
    return jsonify(result)


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
    except ServiceException as err:
        return make_response(jsonify(err), HTTPStatus.BAD_REQUEST)

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
    except ServiceException as err:
        return make_response(jsonify(err), HTTPStatus.BAD_REQUEST)

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
    except ServiceException as err:
        return make_response(jsonify(err), HTTPStatus.BAD_REQUEST)
    return make_response(
        jsonify(uuid=deleted_role.role_id, role_name=deleted_role.role_name),
        HTTPStatus.OK
    )


@role.route('/<uuid:role_uuid>/permissions', methods=['GET'])
@inject
def get_role_permissions(
        role_uuid: str,
        role_service: RoleService = Provide[Container.role_service]):
    perm_list = role_service.get_role_permissions(role_uuid)
    result = [{'uuid': perm.permission_id,
               'permission_name': perm.permission_name} for perm in perm_list]
    return jsonify(result)


@role.route('/<uuid:role_uuid>/permissions', methods=['POST'])
@inject
def set_role_permissions(
        role_uuid: str,
        role_service: RoleService = Provide[Container.role_service]):
    request_json = request.json
    try:
        set_request = PermissionSetRequest(**request_json)
    except ValidationError as err:
        service_exception = make_service_exception(err)
        return make_response(
            jsonify(service_exception),
            HTTPStatus.BAD_REQUEST
        )
    try:
        new_perm: Permission = role_service.set_role_permissions(
            role_id=role_uuid,
            perm_id=set_request.permission_uuid)
    except ServiceException as err:
        return make_response(jsonify(err), HTTPStatus.BAD_REQUEST)
    return make_response(
        jsonify(uuid=new_perm.permission_id,
                permission_name=new_perm.permission_name),
        HTTPStatus.OK
    )


@role.route('/<uuid:role_uuid>/permissions/<uuid:perm_uuid>',
            methods=['DELETE'])
@inject
def remove_role_permissions(
        role_uuid: str,
        perm_uuid: str,
        role_service: RoleService = Provide[Container.role_service]):
    try:
        deleted_perm: Permission = role_service.remove_role_permissions(
            role_id=role_uuid,
            perm_id=perm_uuid
        )
    except ServiceException as err:
        return make_response(jsonify(err), HTTPStatus.BAD_REQUEST)
    return make_response(
        jsonify(uuid=deleted_perm.permission_id,
                permission_name=deleted_perm.permission_name),
        HTTPStatus.OK
    )
