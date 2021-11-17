from core.utils import ServiceException
from models.permission import Permission
from models.role_permissions import RolePermission
from models.roles_owners import RoleOwner
from models.user import User


class UserPermsService:
    def __init__(self):
        pass

    def get_user_perms_list(self, user_id: str) -> list[Permission]:
        """Get User list of Permissions. """
        existing_user: User = User.query.get(user_id)
        if not existing_user:
            error_code = 'USER_NOT_FOUND'
            message = 'Unknown user UUID'
            raise ServiceException(error_code=error_code, message=message)

        existing_role_ownership = RoleOwner.query.filter(
            RoleOwner.owner_id == user_id).all()
        if not existing_role_ownership:
            return []

        role_ids = [ro.role_id for ro in existing_role_ownership]

        existing_rps = [
            RolePermission.query.filter(RolePermission.role_id == r_id).all()
            for
            r_id in role_ids]
        rp_list = [val for sublist in existing_rps for val in sublist]
        rp_list = list(set(rp_list))
        return [Permission.query.get(rp.permission_id) for rp in rp_list]

    def check_user_perm(self, user_id: str, perm_id: str) -> bool:
        """Check if User with given UUID have Permission with given UUID. """
        existing_permission: Permission = Permission.query.filter(
            Permission.permission_id == perm_id).first()
        if not existing_permission:
            error_code = 'PERMISSION_NOT_FOUND'
            message = 'Permission with that UUID not found'
            raise ServiceException(error_code=error_code, message=message)

        user_perms: list[Permission] = self.get_user_perms_list(user_id)
        perm_ids: list[str] = [perm.permission_id for perm in user_perms]
        if perm_id in perm_ids:
            return True
        else:
            return False
