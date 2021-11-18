from http import HTTPStatus

from dependency_injector.wiring import inject, Provide
from flask import Blueprint, make_response, request, jsonify, Response

from core.containers import Container
from core.utils import ServiceException
from services.permission import PermissionService

permission = Blueprint('permission', __name__, url_prefix='/permission')


@permission.route('/', methods=['GET'])
@inject
def get_permissions(
        perm_service: PermissionService = Provide[Container.perm_service]):
    try:
        perm_list = perm_service.get_permission_list()
    except ServiceException as err:
        return make_response(jsonify(err), HTTPStatus.BAD_REQUEST)
    result = [{'uuid': perm.permission_id,
               'permission_name': perm.permission_name} for perm in perm_list]
    return jsonify(result)


@permission.route('/', methods=['POST'])
@inject
def create_permission(
        perm_service: PermissionService = Provide[Container.perm_service]):
    create_request = perm_service.validate_request(request)
    if isinstance(create_request, Response):
        return create_request
    try:
        new_perm = perm_service.create_permission(
            create_request.permission_name
        )
    except ServiceException as err:
        return make_response(jsonify(err), HTTPStatus.BAD_REQUEST)

    return make_response(
        jsonify(uuid=new_perm.permission_id,
                permission_name=new_perm.permission_name),
        HTTPStatus.OK
    )


@permission.route('/<uuid:perm_uuid>', methods=['PATCH'])
@inject
def edit_permission(perm_uuid: str,
                    perm_service: PermissionService = Provide[
                        Container.perm_service]):
    edit_request = perm_service.validate_request(request)
    if isinstance(edit_request, Response):
        return edit_request
    try:
        edited_perm = perm_service.edit_permission(
            permission_id=perm_uuid,
            permission_name=edit_request.permission_name
        )
    except ServiceException as err:
        return make_response(jsonify(err), HTTPStatus.BAD_REQUEST)
    return make_response(
        jsonify(uuid=edited_perm.permission_id,
                permission_name=edited_perm.permission_name),
        HTTPStatus.OK
    )


@permission.route('/<uuid:perm_uuid>', methods=['DELETE'])
@inject
def delete_permission(perm_uuid: str,
                      perm_service: PermissionService = Provide[
                          Container.perm_service]):
    try:
        deleted_perm = perm_service.delete_permission(permission_id=perm_uuid)
    except ServiceException as err:
        return make_response(jsonify(err), HTTPStatus.BAD_REQUEST)
    return make_response(
        jsonify(uuid=deleted_perm.permission_id,
                permission_name=deleted_perm.permission_name),
        HTTPStatus.OK
    )
