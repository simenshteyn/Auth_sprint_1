from core.utils import ServiceException
from models.role import Role
from db.pg import db


class RoleService:
    def __init__(self):
        pass

    def get_roles_list(self) -> list[Role]:
        return Role.query.all()

    def create_role(self, role_name: str) -> Role:
        existing_role: Role = Role.query.filter(
            Role.role_name == role_name).first()

        if existing_role:
            error_code = 'ROLE_EXISTS'
            message = 'Role with than name already exists'
            raise ServiceException(error_code=error_code, message=message)

        new_role = Role(role_name=role_name)
        db.session.add(new_role)
        db.session.commit()
        return new_role

    def edit_role(self, role_id: str, role_name: str) -> Role:
        existing_role: Role = Role.query.filter(
            Role.role_id == role_id).first()

        if not existing_role:
            error_code = 'ROLE_NOT_FOUND'
            message = 'Role with that UUID not found'
            raise ServiceException(error_code=error_code, message=message)

        existing_role.role_name = role_name
        db.session.commit()
        return existing_role

    def delete_role(self, role_id: str) -> Role:
        existing_role: Role = Role.query.filter(
            Role.role_id == role_id).first()

        if not existing_role:
            error_code = 'ROLE_NOT_FOUND'
            message = 'Role with that UUID not found'
            raise ServiceException(error_code=error_code, message=message)

        db.session.delete(existing_role)
        db.session.commit()
        return existing_role
