from flask import jsonify
from flask_sqlalchemy import SQLAlchemy


class RoleService:
    def __init__(self, storage: SQLAlchemy):
        self.storage = storage

    def get_roles_list(self):
        role_list = [
            {'uuid': 'some-uuid', 'role_name': 'subscriber'},
            {'uuid': 'other-uuid', 'role_name': 'editor'}
        ]
        return role_list
