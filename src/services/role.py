from core.utils import ServiceException
from models.role import Role
from db.pg import db


class RoleService:
    def __init__(self):
        pass

    def get_roles_list(self):
        return Role.query.all()

    def create_role(self, role_name: str):
        existing_role: Role = Role.query.filter(
            Role.role_name == role_name).first()

        if existing_role:
            error_code = 'ROLE_EXISTS'
            message = 'Role with than name already exists'
            raise ServiceException(error_code=error_code, message=message)

        new_role = Role(role_name=role_name)
        db.session.add(new_role)
        db.session.commit()
        return new_role.role_id, new_role.role_name
