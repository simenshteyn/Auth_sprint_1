from http import HTTPStatus

from flask import Blueprint, jsonify, make_response, Response
from dependency_injector.wiring import inject, Provide
from pydantic.error_wrappers import ErrorWrapper

from services.user import UserService
from containers import Container

from flask import request
from pydantic import BaseModel, constr, EmailStr, ValidationError
from flask_pydantic import validate

from utils import eprint

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
        # TODO: rewrite or extract
        first_error = err.errors().pop()
        error_field = first_error.get("loc")[0]
        error_reason = first_error.get("type").split(".")[-1]
        response_data = {"error_code": f"{error_field}_{error_reason}".upper(),
                         "message": f"{error_field} is {error_reason}"}
        return make_response(jsonify(response_data), HTTPStatus.BAD_REQUEST)

    user_info = {'user-agent': request.headers.get('User-Agent')}

    eprint("validated", request_json)

    try:
        access_token, refresh_token = user_service.create_user(
            signup_request.username,
            signup_request.password,
            signup_request.email,
            user_info)
    except Exception as err:
        return make_response(jsonify(err), HTTPStatus.BAD_REQUEST)

    return make_response(jsonify(access_token=access_token, refresh_token=refresh_token), HTTPStatus.OK)


