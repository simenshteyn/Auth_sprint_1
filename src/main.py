from flask import Flask
from api.common import api
from core.containers import Container
from db.pg import init_db


def create_app() -> Flask:
    container = Container()
    app = Flask(__name__)
    app.container = container
    app.register_blueprint(api, url_prefix='/api')
    init_db(app)
    return app


if __name__ == '__main__':
    app = create_app()
    app.run(host="0.0.0.0", port=8000, debug=True)
