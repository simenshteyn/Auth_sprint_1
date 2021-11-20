from http import HTTPStatus

from dependency_injector.wiring import Provide, inject
from flask import Blueprint, Response, jsonify, make_response, request
from flask_jwt_extended import jwt_required

from core.containers import Container
from core.utils import ServiceException, authenticate
from models.permission import Permission
from services.role import RoleService

role = Blueprint('role', __name__, url_prefix='/role')


# @role.route('/', methods=['GET'])
# @inject
# def get_roles(role_service: RoleService = Provide[Container.role_service]):
#     try:
#         role_list = role_service.get_roles_list()
#     except ServiceException as err:
#         return make_response(jsonify(err), HTTPStatus.BAD_REQUEST)
#     result = [{'uuid': role.role_id,
#                'role_name': role.role_name} for role in role_list]
#     return jsonify(result)
@role.route('/', methods=['GET'])
@jwt_required()
@authenticate()
@inject
def get_roles(user_id: str,
              role_service: RoleService = Provide[Container.role_service]):
    try:
        is_permitted = role_service.check_authorization(user_id)
        if is_permitted:
            role_list = role_service.get_roles_list()
            result = [{'uuid': role.role_id,
                       'role_name': role.role_name} for role in role_list]
            return jsonify(result)
        else:
            error_code = 'NOT_PERMITTED'
            message = 'Have no permission to get roles'
            return make_response(
                jsonify(error_code=error_code, message=message),
                HTTPStatus.BAD_REQUEST
            )
    except ServiceException as err:
        return make_response(jsonify(err), HTTPStatus.BAD_REQUEST)


@role.route('/', methods=['POST'])
@inject
def create_role(role_service: RoleService = Provide[Container.role_service]):
    create_request = role_service.validate_role_request(request)
    if isinstance(create_request, Response):
        return create_request
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
    edit_request = role_service.validate_role_request(request)
    if isinstance(edit_request, Response):
        return edit_request
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
    try:
        perm_list = role_service.get_role_permissions(role_uuid)
    except ServiceException as err:
        return make_response(jsonify(err), HTTPStatus.BAD_REQUEST)
    result = [{'uuid': perm.permission_id,
               'permission_name': perm.permission_name} for perm in perm_list]
    return jsonify(result)


@role.route('/<uuid:role_uuid>/permissions', methods=['POST'])
@inject
def set_role_permissions(
        role_uuid: str,
        role_service: RoleService = Provide[Container.role_service]):
    set_request = role_service.validate_perm_request(request)
    if isinstance(set_request, Response):
        return set_request
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
