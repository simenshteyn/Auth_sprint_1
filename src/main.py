from flask import Flask
from api.common import api
from db import init_db

from containers import Container

app = Flask(__name__)

app.register_blueprint(api, url_prefix='/api')

app.container = Container()

init_db(app)
# TODO: do we really need this or its automatic as described in app_context' comment?
#  app.app_context().push()

# TODO: figure where this needs to be run
# db.create_all()

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8000, debug=True)
