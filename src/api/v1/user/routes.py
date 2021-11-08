from flask import Blueprint, jsonify
from dependency_injector.wiring import inject, Provide

from services.user import UserService
from containers import Container

user = Blueprint('user', __name__, url_prefix='/user')


@user.route('/')
def index():
    return jsonify(result="Hello user")


@user.route('/signup', methods=["POST"])
@inject
def signup(user_service: UserService = Provide[Container.user_service]):
    user_service.create_user('test', 'test', 'test')
    return jsonify(result="Signup")


@user.route('/auth', methods=["POST"])
def auth():
    return jsonify(result="auth")
