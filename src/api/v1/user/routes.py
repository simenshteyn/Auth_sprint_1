from http import HTTPStatus

from flask import Blueprint, jsonify, make_response
from dependency_injector.wiring import inject, Provide

from services.user import UserService
from core.containers import Container

from flask import request
from pydantic import BaseModel, constr, EmailStr, ValidationError

from utils import make_service_exception

user = Blueprint('user', __name__, url_prefix='/user')


class SignupRequest(BaseModel):
    username: constr(min_length=1, strip_whitespace=True, to_lower=True)
    password: constr(min_length=1, strip_whitespace=True)
    email: EmailStr


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
    except Exception as err:
        return make_response(jsonify(str(err)), HTTPStatus.BAD_REQUEST)

    return make_response(
        jsonify(access_token=access_token, refresh_token=refresh_token),
        HTTPStatus.OK)
