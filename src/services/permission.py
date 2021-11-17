from core.utils import ServiceException
from models.permission import Permission
from db.pg import db


class PermissionService:
    def __init__(self):
        pass

    def get_permission_list(self) -> list[Permission]:
        return Permission.query.all()

    def create_permission(self, permission_name: str) -> Permission:
        existing_permission: Permission = Permission.query.filter(
            Permission.permission_name == permission_name).first()

        if existing_permission:
            error_code = 'PERMISSION_EXISTS'
            message = 'Permission with than name already exists'
            raise ServiceException(error_code=error_code, message=message)

        new_permission = Permission(permission_name=permission_name)
        db.session.add(new_permission)
        db.session.commit()
        return new_permission

    def edit_permission(self, permission_id: str,
                        permission_name: str) -> Permission:
        existing_permission: Permission = Permission.query.filter(
            Permission.permission_id == permission_id).first()

        if not existing_permission:
            error_code = 'PERMISSION_NOT_FOUND'
            message = 'Permission with that UUID not found'
            raise ServiceException(error_code=error_code, message=message)

        existing_permission.permission_name = permission_name
        db.session.commit()
        return existing_permission

    def delete_permission(self, permission_id: str) -> Permission:
        existing_permission: Permission = Permission.query.filter(
            Permission.permission_id == permission_id).first()

        if not existing_permission:
            error_code = 'PERMISSION_NOT_FOUND'
            message = 'Permission with that UUID not found'
            raise ServiceException(error_code=error_code, message=message)

        db.session.delete(existing_permission)
        db.session.commit()
        return existing_permission