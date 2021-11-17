from http import HTTPStatus

from flask import Blueprint, jsonify, make_response
from dependency_injector.wiring import inject, Provide
from flask_jwt_extended import jwt_required, get_jwt

from models.permission import Permission
from models.role import Role
from services.user import UserService
from core.containers import Container

from flask import request
from pydantic import BaseModel, constr, EmailStr, ValidationError

from core.utils import make_service_exception, ServiceException, \
    authenticate
from services.user_perms import UserPermsService
from services.user_role import UserRoleService

user = Blueprint('user', __name__, url_prefix='/user')


class LoginRequest(BaseModel):
    username: constr(min_length=1, strip_whitespace=True, to_lower=True)
    password: constr(min_length=1, strip_whitespace=True)


class SignupRequest(LoginRequest):
    email: EmailStr


class ModifyRequest(LoginRequest):
    pass


@user.route('/signup', methods=["POST"])
@inject
def signup(user_service: UserService = Provide[Container.user_service]):
    """ Creates a new user and returns it's access and refresh tokens """
    request_json = request.json
    try:
        signup_request = SignupRequest(**request_json)
    except ValidationError as err:
        service_exception = make_service_exception(err)
        return make_response(
            jsonify(service_exception),
            HTTPStatus.BAD_REQUEST)

    user_info = {'user-agent': request.headers.get('User-Agent')}

    try:
        access_token, refresh_token = user_service.create_user(
            signup_request.username,
            signup_request.password,
            signup_request.email,
            user_info)
    except ServiceException as err:
        return make_response(jsonify(err), HTTPStatus.BAD_REQUEST)

    return make_response(
        jsonify(access_token=access_token, refresh_token=refresh_token),
        HTTPStatus.OK)


@user.route('/auth', methods=["POST"])
@inject
def login(user_service: UserService = Provide[Container.user_service]):
    """ Log user in using username and password.
        Return a newly generated pair of tokens.
     """
    request_json = request.json
    try:
        login_request = LoginRequest(**request_json)
    except ValidationError as err:
        service_exception = make_service_exception(err)
        return make_response(
            jsonify(service_exception),
            HTTPStatus.BAD_REQUEST)

    user_info = {'user-agent': request.headers.get('User-Agent')}

    try:
        access_token, refresh_token = user_service.login(
            login_request.username,
            login_request.password,
            user_info)
    except ServiceException as err:
        return make_response(jsonify(err), HTTPStatus.BAD_REQUEST)

    return make_response(
        jsonify(access_token=access_token, refresh_token=refresh_token),
        HTTPStatus.OK)


@user.route('/auth', methods=["PUT"])
@jwt_required(refresh=True)
@inject
def refresh(user_service: UserService = Provide[Container.user_service]):
    jwt = get_jwt()
    refresh_token = request.headers['Authorization'].split().pop(-1)

    if 'user_id' not in jwt:
        return make_response(
            jsonify(error_mode='IDENTITY_MISSING',
                    message="User id not found in decrypted content"),
            HTTPStatus.BAD_REQUEST)

    try:
        access_token, refresh_token = user_service.refresh(
            user_id=jwt['user_id'],
            refresh_token=refresh_token)
    except ServiceException as err:
        return make_response(jsonify(err), HTTPStatus.BAD_REQUEST)

    return make_response(jsonify(access_token=access_token,
                                 refresh_token=refresh_token))


@user.route('/auth/logout', methods=["POST"])
@jwt_required()
@authenticate()
@inject
def logout(user_id: str,
           user_service: UserService = Provide[Container.user_service]):
    access_token = request.headers['Authorization'].split().pop(-1)
    request_json = request.json
    refresh_token = request_json['refresh_token']

    try:
        access_token, refresh_token = user_service.logout(
            user_id=user_id,
            access_token=access_token,
            refresh_token=refresh_token
        )
    except ServiceException as err:
        return make_response(jsonify(err), HTTPStatus.BAD_REQUEST)

    return make_response(jsonify(access_token=access_token,
                                 refresh_token=refresh_token))


@user.route('/auth', methods=["PATCH"])
@jwt_required()
@authenticate()
@inject
def modify(
        user_id: str,
        user_service: UserService = Provide[Container.user_service]):
    request_json = request.json

    try:
        modify_request = ModifyRequest(**request_json)
    except ValidationError as err:
        service_exception = make_service_exception(err)
        return make_response(
            jsonify(service_exception),
            HTTPStatus.BAD_REQUEST)

    try:
        user_service.modify(user_id, modify_request.username,
                            modify_request.password)
    except ServiceException as err:
        return make_response(jsonify(err), 400)

    return make_response({}, HTTPStatus.ACCEPTED)


@user.route('/auth', methods=["GET"])
@jwt_required()
@authenticate()
@inject
def auth_history(user_id: str,
                 user_service: UserService = Provide[Container.user_service]
                 ):
    try:
        history = user_service.get_auth_history(user_id)
    except ServiceException as err:
        return make_response(jsonify(err), 400)

    return make_response(jsonify(history), HTTPStatus.OK)


class UserRoleAssignRequest(BaseModel):
    role_uuid: str


@user.route('/<uuid:user_uuid>/roles', methods=['POST'])
@inject
def assign_user_role(
        user_uuid: str,
        user_role_service: UserRoleService = Provide[
            Container.user_role_service]):
    request_json = request.json
    try:
        set_request = UserRoleAssignRequest(**request_json)
    except ValidationError as err:
        service_exception = make_service_exception(err)
        return make_response(
            jsonify(service_exception),
            HTTPStatus.BAD_REQUEST
        )
    try:
        new_role: Role = user_role_service.assign_user_role(
            user_id=user_uuid,
            role_id=set_request.role_uuid)
    except ServiceException as err:
        return make_response(jsonify(err), HTTPStatus.BAD_REQUEST)
    return make_response(
        jsonify(uuid=new_role.role_id,
                role_name=new_role.role_name),
        HTTPStatus.OK
    )


@user.route('/<uuid:user_uuid>/roles', methods=['GET'])
@inject
def get_user_roles_list(
        user_uuid: str,
        user_role_service: UserRoleService = Provide[
            Container.user_role_service]):
    try:
        roles_list = user_role_service.get_user_roles_list(user_uuid)
    except ServiceException as err:
        return make_response(jsonify(err), HTTPStatus.BAD_REQUEST)
    result = [{'uuid': role.role_id,
               'role_name': role.role_name} for role in roles_list]
    return jsonify(result)


@user.route('/<uuid:user_uuid>/roles/<uuid:role_uuid>', methods=['DELETE'])
@inject
def remove_role_from_user(user_uuid: str,
                          role_uuid: str,
                          user_role_service: UserRoleService = Provide[
                              Container.user_role_service]):
    try:
        role = user_role_service.remove_role_from_user(user_id=user_uuid,
                                                       role_id=role_uuid)
    except ServiceException as err:
        return make_response(jsonify(err), HTTPStatus.BAD_REQUEST)
    return make_response(
        jsonify(uuid=role.role_id, role_name=role.role_name), HTTPStatus.OK
    )


@user.route('/<uuid:user_uuid>/permissions', methods=['GET'])
@inject
def get_user_perms_list(
        user_uuid: str,
        user_perm_service: UserPermsService = Provide[
            Container.user_perm_service]):
    try:
        perms_list: list[Permission] = user_perm_service.get_user_perms_list(
            user_uuid)
    except ServiceException as err:
        return make_response(jsonify(err), HTTPStatus.BAD_REQUEST)
    result = [{'uuid': perm.permission_id,
               'permission_name': perm.permission_name} for perm in perms_list]
    return jsonify(result)


@user.route('/<uuid:user_uuid>/permissions/<uuid:perm_uuid>', methods=['GET'])
@inject
def check_user_perm(
        user_uuid: str,
        perm_uuid: str,
        user_perm_service: UserPermsService = Provide[
            Container.user_perm_service]):
    try:
        is_permitted = user_perm_service.check_user_perm(user_uuid, perm_uuid)
    except ServiceException as err:
        return make_response(jsonify(err), HTTPStatus.BAD_REQUEST)
    return jsonify(user_uuid=user_uuid,
                   permission_uuid=perm_uuid,
                   is_permitted=is_permitted)
