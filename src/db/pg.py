from flask_sqlalchemy import SQLAlchemy

from core.settings import config

db = SQLAlchemy()

PG_URI = 'postgresql://{pg_user}:{pg_pass}@{pg_host}/{pg_dbname}'.format(
    pg_user=config.pg_user,
    pg_pass=config.pg_pass,
    pg_host=config.pg_host,
    pg_dbname=config.pg_dbname
)


# import os
# from flask import Flask
# from flask_sqlalchemy import SQLAlchemy
#
# db = SQLAlchemy()
#
#
# def init_db(app: Flask):
#     dsl = {
#         'pg_host': os.getenv('POSTGRES_HOST'),
#         'pg_port': os.getenv('POSTGRES_PORT'),
#         'pg_dbname': os.getenv('POSTGRES_DB'),
#         'pg_user': os.getenv('POSTGRES_USER'),
#         'pg_pass': os.getenv('POSTGRES_PASSWORD'),
#     }
#
#     app.config['SQLALCHEMY_DATABASE_URI'] = (
#         'postgresql://{pg_user}:{pg_pass}@{pg_host}:{pg_port}/{pg_dbname}'
#         .format(**dsl)
#     )
#
#     # SQLALCHEMY_TRACK_MODIFICATIONS adds significant overhead and will be
#     # disabled by default in the future.
#     # Signalling
#     # (https://flask-sqlalchemy.palletsprojects.com/en/master/signals/)
#     # won't be supported.
#     app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
#
#     db.init_app(app)
