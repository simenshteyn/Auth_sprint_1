import os

from api.common import api
from core.containers import Container
from db.pg import PG_URI, db
from flask_jwt_extended import JWTManager


def create_app():
    container = Container()
    app = container.app()
    app.container = container
    app.config['SQLALCHEMY_DATABASE_URI'] = PG_URI
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.register_blueprint(api, url_prefix='/api')

    app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
    JWTManager(app)

    return app


if __name__ == '__main__':
    application = create_app()
    db.init_app(application)
    application.run(host="0.0.0.0", port=8000, debug=True)
