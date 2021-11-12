from flask import Flask
from api.common import api
from core.containers import Container
from db.pg import init_db


def create_app():
    app = Flask(__name__)
    init_db(app)
    app.container = Container()
    app.register_blueprint(api, url_prefix='/api')
    return app


if __name__ == '__main__':
    application = create_app()
    application.run(host="0.0.0.0", port=8000, debug=True)
