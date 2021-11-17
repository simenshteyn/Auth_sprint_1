import textwrap

import pytest
from http import HTTPStatus

from tests.functional.utils.extract import extract_roles, extract_role, \
    extract_permission, extract_permissions, extract_tokens, extract_perm_check


def get_user_uuid(pg_curs, username: str, table_name: str = 'users',
                  scheme: str = 'app') -> str:
    """Get user uuid from username directly from database. """
    statement = textwrap.dedent(
        f'SELECT user_id FROM {scheme}.{table_name} WHERE user_login = %s ;'
    )
    pg_curs.execute(statement, (username,))
    return pg_curs.fetchone()[0]


def remove_user(pg_curs, user_id: str, table_name: str = 'users',
                scheme: str = 'app') -> None:
    """Remove user with given UUID from database. """
    statement = textwrap.dedent(
        f'DELETE FROM {scheme}.{table_name} WHERE user_id = %s ;'
    )
    pg_curs.execute(statement, (user_id,))


@pytest.mark.asyncio
async def test_role_endpoint_crud(make_post_request, make_get_request,
                                  make_patch_request, make_delete_request):
    """Test roles CRUD cycle: creation, read, update and deletion. """
    response = await make_post_request('role/',
                                       json={'role_name': 'test_role'})
    # Create new role
    role = await extract_role(response)
    assert response.status == HTTPStatus.OK
    assert role.role_name == 'test_role'
    role_uuid = role.uuid

    # Get list of roles with created one
    response = await make_get_request('role/')
    roles = await extract_roles(response)
    assert response.status == HTTPStatus.OK
    assert len(roles) > 0

    # Rename role by UUID
    response = await make_patch_request(f'role/{role_uuid}',
                                        json={'role_name': 'test_role_2'})
    role = await extract_role(response)
    assert response.status == HTTPStatus.OK
    assert role.role_name == 'test_role_2'

    # Remove role by UUID
    response = await make_delete_request(f'role/{role_uuid}')
    role = await extract_role(response)
    assert response.status == HTTPStatus.OK
    assert role.role_name == 'test_role_2'
    assert role.uuid == role_uuid


@pytest.mark.asyncio
async def test_role_permissions_assigment(
        make_post_request, make_get_request, make_delete_request):
    """Test permissions CRUD assigment: create, assign and remove process. """
    response = await make_post_request('role/',
                                       json={'role_name': 'testing_role'})
    # Create new role and save it's uuid
    created_role = await extract_role(response)
    assert response.status == HTTPStatus.OK
    assert created_role.role_name == 'testing_role'
    role_uuid = created_role.uuid

    # Create new permission and save it's uuid
    response = await make_post_request('permission/',
                                       json={'permission_name': 'testing_per'})
    created_permission = await extract_permission(response)
    assert response.status == HTTPStatus.OK
    assert created_permission.permission_name == 'testing_per'
    perm_uuid = created_permission.uuid

    # Assign created permission to created role
    response = await make_post_request(f'role/{role_uuid}/permissions',
                                       json={'permission_uuid': perm_uuid})
    assigned_permission = await extract_permission(response)
    assert response.status == HTTPStatus.OK
    assert assigned_permission.uuid == perm_uuid
    assert assigned_permission.permission_name == 'testing_per'

    # Get permissions for created role
    response = await make_get_request(f'role/{role_uuid}/permissions')
    permissions_list = await extract_permissions(response)
    assert response.status == HTTPStatus.OK
    assert len(permissions_list) == 1
    assert permissions_list[0].permission_name == 'testing_per'
    assert permissions_list[0].uuid == perm_uuid

    # Remove created permission from Role
    response = await make_delete_request(
        f'role/{role_uuid}/permissions/{perm_uuid}')
    removed_permission = await extract_permission(response)
    assert response.status == HTTPStatus.OK
    assert removed_permission.permission_name == 'testing_per'
    assert removed_permission.uuid == perm_uuid

    # Chek removed permission is excluded from role
    response = await make_get_request(f'role/{role_uuid}/permissions')
    permissions_list = await extract_permissions(response)
    assert response.status == HTTPStatus.OK
    assert len(permissions_list) == 0

    # Remove created role
    response = await make_delete_request(f'role/{role_uuid}')
    removed_role = await extract_role(response)
    assert response.status == HTTPStatus.OK
    assert removed_role.role_name == 'testing_role'
    assert removed_role.uuid == role_uuid

    # Remove created permission
    response = await make_delete_request(f'permission/{perm_uuid}')
    perm = await extract_permission(response)
    assert response.status == HTTPStatus.OK
    assert perm.uuid == perm_uuid


@pytest.mark.asyncio
async def test_user_role_assigment(make_post_request, make_get_request,
                                   make_delete_request, pg_curs):
    """Test full cycle of Role assigment to User: add, get, remove. """
    response = await make_post_request('user/signup',
                                       json={'username': 'some_test_user',
                                             'password': 'some_password',
                                             'email': 'some@email.com'})
    # Create new user and save it's uuid and tokens
    tokens = await extract_tokens(response)
    assert response.status == HTTPStatus.OK
    assert len(tokens.access_token) > 1
    assert len(tokens.refresh_token) > 1
    user_uuid = get_user_uuid(pg_curs, username='some_test_user')

    # Create new role and save it's uuid
    response = await make_post_request('role/',
                                       json={'role_name': 'testing_role'})
    created_role = await extract_role(response)
    assert response.status == HTTPStatus.OK
    assert created_role.role_name == 'testing_role'
    role_uuid = created_role.uuid

    # Create new permission and save it's uuid
    response = await make_post_request('permission/',
                                       json={'permission_name': 'testing_per'})
    created_permission = await extract_permission(response)
    assert response.status == HTTPStatus.OK
    assert created_permission.permission_name == 'testing_per'
    perm_uuid = created_permission.uuid

    # Assign created permission to created role
    response = await make_post_request(f'role/{role_uuid}/permissions',
                                       json={'permission_uuid': perm_uuid})
    assigned_permission = await extract_permission(response)
    assert response.status == HTTPStatus.OK
    assert assigned_permission.uuid == perm_uuid
    assert assigned_permission.permission_name == 'testing_per'

    # TODO Check if created User don't have permission by uuid till it assigned
    response = await make_get_request(f'user/{user_uuid}/pemissions/{perm_uuid}')
    perm_check = await extract_perm_check(response)
    assert response.status == HTTPStatus.OK
    assert not perm_check.is_permitted

    # Assign created role to created user
    response = await make_post_request(f'user/{user_uuid}/roles',
                                       json={'role_uuid': role_uuid})
    assigned_role = await extract_role(response)
    assert response.status == HTTPStatus.OK
    assert assigned_role.role_name == 'testing_role'
    assert assigned_role.uuid == role_uuid

    # Get assigned roles for created user
    response = await make_get_request(f'user/{user_uuid}/roles')
    assigned_roles = await extract_roles(response)
    assert response.status == HTTPStatus.OK
    assert len(assigned_roles) == 1
    assert assigned_roles[0].role_name == 'testing_role'

    # TODO Get permissions list for created user
    response = await make_get_request(f'user/{user_uuid}/permissions')
    user_perms = await extract_permissions(response)
    assert response.status == HTTPStatus.OK
    assert len(user_perms) == 1
    assert user_perms[0].permission_name == 'testing_per'

    # TODO Check if created User have permission by uuid
    response = await make_get_request(f'user/{user_uuid}/pemissions/{perm_uuid}')
    perm_check = await extract_perm_check(response)
    assert response.status == HTTPStatus.OK
    assert perm_check.is_permitted

    # Remove assigned role from created user
    response = await make_delete_request(f'user/{user_uuid}/roles/{role_uuid}')
    removed_role = await extract_role(response)
    assert response.status == HTTPStatus.OK
    assert removed_role.role_name == 'testing_role'
    assert removed_role.uuid == role_uuid

    # Check role is excluded from users role list
    response = await make_get_request(f'user/{user_uuid}/roles')
    user_roles = await extract_roles(response)
    assert response.status == HTTPStatus.OK
    assert len(user_roles) == 0

    # Remove created permission
    response = await make_delete_request(f'permission/{perm_uuid}')
    perm = await extract_permission(response)
    assert response.status == HTTPStatus.OK
    assert perm.uuid == perm_uuid

    # Remove created role
    response = await make_delete_request(f'role/{role_uuid}')
    removed_role = await extract_role(response)
    assert response.status == HTTPStatus.OK
    assert removed_role.role_name == 'testing_role'
    assert removed_role.uuid == role_uuid

    # Remove created user
    remove_user(pg_curs, user_uuid)
