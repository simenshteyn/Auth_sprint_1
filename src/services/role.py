from http import HTTPStatus
from typing import Union

from flask import Request, make_response, jsonify, Response
from pydantic import ValidationError

from core.utils import ServiceException, make_service_exception
from models.permission import Permission, PermissionSetRequest
from models.role import Role, RoleCreationRequest
from db.pg import db
from models.role_permissions import RolePermission


class RoleService:
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
        request_json = request.json
        try:
            create_request = RoleCreationRequest(**request_json)
        except ValidationError as err:
            service_exception = make_service_exception(err)
            return make_response(
                jsonify(service_exception),
                HTTPStatus.BAD_REQUEST
            )
        return create_request

    def validate_perm_request(
            self, request: Request) -> Union[PermissionSetRequest, Response]:
        """Valide permission setting request. """
        request_json = request.json
        try:
            set_request = PermissionSetRequest(**request_json)
        except ValidationError as err:
            service_exception = make_service_exception(err)
            return make_response(
                jsonify(service_exception),
                HTTPStatus.BAD_REQUEST
            )
        return set_request
