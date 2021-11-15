from http import HTTPStatus

from flask import Blueprint, jsonify, make_response
from dependency_injector.wiring import inject, Provide
from flask_jwt_extended import jwt_required, get_jwt

from services.user import UserService
from core.containers import Container

from flask import request
from pydantic import BaseModel, constr, EmailStr, ValidationError

from core.utils import make_service_exception, ServiceException

user = Blueprint('user', __name__, url_prefix='/user')


class SignupRequest(BaseModel):
    username: constr(min_length=1, strip_whitespace=True, to_lower=True)
    password: constr(min_length=1, strip_whitespace=True)
    email: EmailStr


class LoginRequest(BaseModel):
    username: constr(min_length=1, strip_whitespace=True, to_lower=True)
    password: constr(min_length=1, strip_whitespace=True)


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
