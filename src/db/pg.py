from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from core.settings import config

db = SQLAlchemy()


def init_db(app: Flask):
    app.config['SQLALCHEMY_DATABASE_URI'] = \
        'postgresql://{pg_user}:{pg_pass}@{pg_host}/{pg_dbname}'.format(
            pg_user=config.pg_user,
            pg_pass=config.pg_pass,
            pg_host=config.pg_host,
            pg_dbname=config.pg_dbname
        )

    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
