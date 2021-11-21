from http import HTTPStatus
from typing import Union

from flask import Request, Response, jsonify, make_response
from pydantic import BaseModel, ValidationError

from core.settings import config
from core.utils import make_service_exception, ServiceException
from models.role import Role
from models.roles_owners import RoleOwner
from models.user import User


class BaseService:
    def _validate(
            self, request: Request, model: BaseModel
            ) -> Union[BaseModel, Response]:
        request_json = request.json
        try:
            create_request = model(**request_json)
        except ValidationError as err:
            service_exception = make_service_exception(err)
            return make_response(
                jsonify(service_exception),
                HTTPStatus.BAD_REQUEST
            )
        return create_request

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
