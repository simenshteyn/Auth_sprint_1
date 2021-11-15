from http import HTTPStatus

from dependency_injector.wiring import inject, Provide
from flask import Blueprint, make_response, request, jsonify
from pydantic import BaseModel, ValidationError

from core.containers import Container
from core.utils import make_service_exception
from services.permission import PermissionService

permission = Blueprint('permission', __name__, url_prefix='/permission')


class PermissionCreationRequest(BaseModel):
    permission_name: str


@permission.route('/', methods=['GET'])
@inject
def get_permissions(
        perm_service: PermissionService = Provide[Container.perm_service]):
    perm_list = perm_service.get_permission_list()
    result = [{'uuid': perm.permission_id,
               'permission_name': perm.permission_name} for perm in perm_list]
    return jsonify(result)


@permission.route('/', methods=['POST'])
@inject
def create_permission(
        perm_service: PermissionService = Provide[Container.perm_service]):
    request_json = request.json
    try:
        create_request = PermissionCreationRequest(**request_json)
    except ValidationError as err:
        service_exception = make_service_exception(err)
        return make_response(
            jsonify(service_exception),
            HTTPStatus.BAD_REQUEST
        )

    try:
        new_perm = perm_service.create_permission(
            create_request.permission_name
        )
    except Exception as err:
        return make_response(jsonify(str(err)), HTTPStatus.BAD_REQUEST)

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
    request_json = request.json
    try:
        edit_request = PermissionCreationRequest(**request_json)
    except ValidationError as err:
        service_exception = make_service_exception(err)
        return make_response(
            jsonify(service_exception),
            HTTPStatus.BAD_REQUEST
        )
    try:
        edited_perm = perm_service.edit_permission(
            permission_id=perm_uuid,
            permission_name=edit_request.permission_name
        )
    except Exception as err:
        return make_response(jsonify(str(err)), HTTPStatus.BAD_REQUEST)

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
    except Exception as err:
        return make_response(jsonify(str(err)), HTTPStatus.BAD_REQUEST)
    return make_response(
        jsonify(uuid=deleted_perm.permission_id,
                permission_name=deleted_perm.permission_name),
        HTTPStatus.OK
    )
