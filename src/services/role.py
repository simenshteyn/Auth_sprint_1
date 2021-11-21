from typing import Union

from flask import Request, Response

from core.settings import config
from core.utils import ServiceException
from db.pg import db
from models.permission import Permission, PermissionSetRequest
from models.role import Role, RoleCreationRequest
from models.role_permissions import RolePermission
from models.roles_owners import RoleOwner
from models.user import User
from services.base import BaseService


class RoleService(BaseService):
    def __init__(self):
        pass

    def get_roles_list(self) -> list[Role]:
        """Show all roles in list form. """
        return Role.query.all()

    def create_role(self, role_name: str) -> Role:
        """Create role with unique name, UUID is auto generated. """
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
        """Edit existing role by UUID with new name. Returns edited Role. """
        existing_role: Role = Role.query.get(role_id)

        if not existing_role:
            error_code = 'ROLE_NOT_FOUND'
            message = 'Role with that UUID not found'
            raise ServiceException(error_code=error_code, message=message)

        existing_role.role_name = role_name
        db.session.commit()
        return existing_role

    def delete_role(self, role_id: str) -> Role:
        """Remove existing role with UUID. Returns deleted Role."""
        existing_role: Role = Role.query.filter(
            Role.role_id == role_id).first()
        if not existing_role:
            error_code = 'ROLE_NOT_FOUND'
            message = 'Role with that UUID not found'
            raise ServiceException(error_code=error_code, message=message)

        db.session.delete(existing_role)
        db.session.commit()
        return existing_role

    def get_role_permissions(self, role_id: str) -> list[Permission]:
        """Show list of Permissions assigned to role by Role UUID. """
        existing_role: Role = Role.query.filter(
            Role.role_id == role_id).first()
        if not existing_role:
            error_code = 'ROLE_NOT_FOUND'
            message = 'Role with that UUID not found'
            raise ServiceException(error_code=error_code, message=message)
        role_perms = RolePermission.query.filter(
            RolePermission.role_id == role_id).all()
        perm_ids = [rp.permission_id for rp in role_perms]
        perms = [Permission.query.get(perm_id) for perm_id in perm_ids]
        return perms

    def set_role_permissions(self, role_id: str,
                             perm_id: str) -> Permission:
        """Assign Permission to Role by UUIDs. Returns assigned Permission. """
        existing_role_perm: RolePermission = RolePermission.query.filter(
            RolePermission.role_id == role_id).filter(
            RolePermission.permission_id == perm_id).first()
        if existing_role_perm:
            error_code = 'ROLE_PERMISSION_EXISTS'
            message = 'Permission for Role with that UUID already exists'
            raise ServiceException(error_code=error_code, message=message)
        rp = RolePermission(role_id=role_id, permission_id=perm_id)
        db.session.add(rp)
        db.session.commit()
        perm: Permission = Permission.query.get(rp.permission_id)
        return perm

    def remove_role_permissions(self, role_id: str,
                                perm_id: str) -> Permission:
        """Remove Permission from Role by UUID. Return removed Permission. """
        existing_role_perm: RolePermission = RolePermission.query.filter(
            RolePermission.role_id == role_id,
            RolePermission.permission_id == perm_id).first()
        if not existing_role_perm:
            error_code = 'ROLE_PERMISSION_NOT_FOUND'
            message = 'Permission for Role with that UUID not found'
            raise ServiceException(error_code=error_code, message=message)
        perm: Permission = Permission.query.get(perm_id)
        db.session.delete(existing_role_perm)
        db.session.commit()
        return perm

    def validate_role_request(
            self, request: Request) -> Union[RoleCreationRequest, Response]:
        """Validate role creation request"""
        return self._validate(request, RoleCreationRequest)

    def validate_perm_request(
            self, request: Request) -> Union[PermissionSetRequest, Response]:
        """Valide permission setting request. """
        return self._validate(request, PermissionSetRequest)

    def check_superuser_authorization(
            self,
            user_id: str,
            role_name: str = config.service_admin_role) -> None:
        """Check if user has access to work with roles (superadmin role). """
        existing_user: User = User.query.get(user_id)
        if not existing_user:
            error_code = 'USER_NOT_FOUND'
            message = 'Unknown user UUID'
            raise ServiceException(error_code=error_code, message=message)

        existing_superuser_role: Role = Role.query.filter(
            Role.role_name == role_name).first()
        if not existing_superuser_role:
            error_code = 'ROLE_NOT_FOUND'
            message = 'Role not found'
            raise ServiceException(error_code=error_code, message=message)

        existing_role_ownership: RoleOwner = RoleOwner.query.filter(
            RoleOwner.owner_id == user_id,
            RoleOwner.role_id == existing_superuser_role.role_id).first()
        if not existing_role_ownership:
            error_code = 'NOT_PERMITTED'
            message = 'This operation requires superuser'
            raise ServiceException(error_code=error_code, message=message)
