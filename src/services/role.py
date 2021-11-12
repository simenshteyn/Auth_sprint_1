from models.role import Role
from db.pg import db


class RoleService:
    def __init__(self):
        pass

    def get_roles_list(self):
        # Example:
        # new_role = Role(role_name='subscriber')
        # db.session.add(new_role)
        # db.session.commit()
        return Role.query.all()
