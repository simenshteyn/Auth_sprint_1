from flask_sqlalchemy import SQLAlchemy

from db.pg import db


class RoleService:

    def __init__(self):
        self.storage = db

    def get_roles_list(self):
        role_list = [
            {'uuid': 'some-uuid', 'role_name': 'subscriber'},
            {'uuid': 'other-uuid', 'role_name': 'editor'}
        ]
        return role_list
