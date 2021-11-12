import os

from flask import Flask
from flask_jwt_extended import JWTManager

from api.common import api
from api.v1 import routes
from db import init_db

from containers import Container
from services.user import UserService

app = Flask(__name__)

app.register_blueprint(api, url_prefix='/api')

app.container = Container()

app.container.wire(
    modules=[
        "api.v1.user.routes",
        "services.user",
    ],
)

app.config["JWT_SECRET_KEY"] = "0KX6d4z_crU"
jwt = JWTManager(app)

init_db(app)
# TODO: do we really need this or its automatic as described in app_context' comment?
#  app.app_context().push()

# TODO: figure where this needs to be run
# db.create_all()

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8000, debug=True, reloader_interval=1)
