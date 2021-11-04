from flask import Blueprint, jsonify

v1 = Blueprint('v1', __name__, url_prefix='/v1')


@v1.route('/')
def index():
    return jsonify(result="Hello, World!")
