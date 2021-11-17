from core.utils import ServiceException
from db.pg import db
from models.role import Role
from models.roles_owners import RoleOwner
from models.user import User


class UserRoleService:
    def __init__(self):
        pass

    def get_user_roles_list(self, user_id: str) -> list[Role]:
        existing_user: User = User.query.get(user_id)
        if not existing_user:
            error_code = 'USER_NOT_FOUND'
            message = 'Unknown user UUID'
            raise ServiceException(error_code=error_code, message=message)

        existing_role_ownership = RoleOwner.query.filter(
            RoleOwner.owner_id == user_id).all()

        role_ids = [ro.role_id for ro in existing_role_ownership]
        roles = [Role.query.get(role_id) for role_id in role_ids]
        return roles

    def assign_user_role(self, user_id: str, role_id: str) -> Role:
        existing_user: User = User.query.get(user_id)
        if not existing_user:
            error_code = 'USER_NOT_FOUND'
            message = 'Unknown user UUID'
            raise ServiceException(error_code=error_code, message=message)

        existing_role: Role = Role.query.get(role_id)
        if not existing_role:
            error_code = 'ROLE_NOT_FOUND'
            message = 'Unknown role UUID'
            raise ServiceException(error_code=error_code, message=message)

        existing_role_ownership: RoleOwner = RoleOwner.query.filter(
            RoleOwner.role_id == role_id).filter(
            RoleOwner.owner_id == user_id).first()
        if existing_role_ownership:
            error_code = 'ROLE_EXISTS'
            message = 'User already owns this role'
            raise ServiceException(error_code=error_code, message=message)

        new_role_ownership = RoleOwner(owner_id=user_id, role_id=role_id)
        db.session.add(new_role_ownership)
        db.session.commit()

        new_role: Role = Role.query.get(role_id)
        return new_role

    def remove_role_from_user(self, user_id: str, role_id: str):
        existing_user: User = User.query.get(user_id)
        if not existing_user:
            error_code = 'USER_NOT_FOUND'
            message = 'Unknown user UUID'
            raise ServiceException(error_code=error_code, message=message)

        existing_role: Role = Role.query.get(role_id)
        if not existing_role:
            error_code = 'ROLE_NOT_FOUND'
            message = 'Unknown role UUID'
            raise ServiceException(error_code=error_code, message=message)

        existing_role_ownership: RoleOwner = RoleOwner.query.filter(
            RoleOwner.role_id == role_id).filter(
            RoleOwner.owner_id == user_id).first()
        if not existing_role_ownership:
            error_code = 'NO_ROLE_OWNERSHIP'
            message = 'User has no ownership over this role'
            raise ServiceException(error_code=error_code, message=message)
        role = Role.query.get(role_id)
        db.session.delete(existing_role_ownership)
        db.session.commit()
        return role
