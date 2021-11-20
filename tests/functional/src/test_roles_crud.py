import textwrap
from http import HTTPStatus

import pytest

from tests.functional.src.test_user import create_user, AuthTokenResponse
from tests.functional.utils.extract import (extract_perm_check,
                                            extract_permission,
                                            extract_permissions, extract_role,
                                            extract_roles, extract_tokens)


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


def create_role(pg_curs, role_name: str, table_name: str = 'roles',
                scheme: str = 'app') -> str:
    """Create role in database and return its UUID. """
    statement = textwrap.dedent(f'INSERT INTO {scheme}.{table_name} '
                                f'(role_name) VALUES (%s);')
    pg_curs.execute(statement, (role_name,))

    statement = textwrap.dedent(
        f'SELECT role_id FROM {scheme}.{table_name} WHERE role_name = %s ;'
    )
    pg_curs.execute(statement, (role_name,))
    return pg_curs.fetchone()[0]


def assign_role(pg_curs, owner_id: str, role_id: str,
                table_name: str = 'roles_owners', scheme: str = 'app'):
    """Assign role in database to user directly. """
    statement = textwrap.dedent(f'INSERT INTO {scheme}.{table_name} '
                                f'(owner_id, role_id) VALUES (%s, %s);')
    pg_curs.execute(statement, (owner_id, role_id))


def remove_role(pg_curs, role_id: str, table_name: str = 'roles',
                scheme: str = 'app') -> None:
    """Remove user with given UUID from database. """
    statement = textwrap.dedent(
        f'DELETE FROM {scheme}.{table_name} WHERE role_id = %s ;'
    )
    pg_curs.execute(statement, (role_id,))


def get_auth_headers(token: str):
    return {'Authorization': 'Bearer ' + token}


@pytest.mark.asyncio
async def test_role_endpoint_crud(make_post_request, make_get_request,
                                  make_patch_request, make_delete_request,
                                  pg_curs, redis_conn):
    """Test roles CRUD cycle: creation, read, update and deletion. """
    # Create superuser to work with roles and get tokens
    username = password = 'testsuperuser'
    email = username + '@yandex.com'
    valid_data = {
        'username': username,
        'password': password,
        'email': email
    }

    response, user = create_user(valid_data, pg_curs, redis_conn)
    tokens = AuthTokenResponse(**response.json())
    access_token = tokens.access_token
    su_user_uuid = user['user_id']
    assert response.status_code == 200
    assert user['user_login'] == username
    assert user['user_email'] == email
    assert len(access_token) > 5

    # Assign superuser role to superuser
    su_role_uuid = create_role(pg_curs, role_name='superadmin')
    assign_role(pg_curs, owner_id=su_user_uuid, role_id=su_role_uuid)

    # Create new role
    response = await make_post_request('role/',
                                       json={'role_name': 'test_role'},
                                       headers=get_auth_headers(access_token))
    role = await extract_role(response)
    assert response.status == HTTPStatus.OK
    assert role.role_name == 'test_role'
    role_uuid = role.uuid

    # Get list of roles with created one
    response = await make_get_request('role/',
                                      headers=get_auth_headers(access_token))
    roles = await extract_roles(response)
    assert response.status == HTTPStatus.OK
    assert len(roles) > 0

    # Rename role by UUID
    response = await make_patch_request(f'role/{role_uuid}',
                                        json={'role_name': 'test_role_2'},
                                        headers=get_auth_headers(access_token))
    role = await extract_role(response)
    assert response.status == HTTPStatus.OK
    assert role.role_name == 'test_role_2'

    # Remove role by UUID
    response = await make_delete_request(
        f'role/{role_uuid}',
        headers=get_auth_headers(access_token)
    )
    role = await extract_role(response)
    assert response.status == HTTPStatus.OK
    assert role.role_name == 'test_role_2'
    assert role.uuid == role_uuid

    # Remove superuser and superadmin role
    remove_user(pg_curs, user_id=su_user_uuid)
    remove_role(pg_curs, role_id=su_role_uuid)


@pytest.mark.asyncio
async def test_role_permissions_assigment(
        make_post_request, make_get_request, make_delete_request):
    """Test permissions CRUD assigment: create, assign and remove process. """
    response = await make_post_request('role/',
                                       json={'role_name': 'testing_r'})
    # Create new role and save it's uuid
    created_role = await extract_role(response)
    assert response.status == HTTPStatus.OK
    assert created_role.role_name == 'testing_r'
    role_uuid = created_role.uuid

    # Create new permission and save it's uuid
    response = await make_post_request('permission/',
                                       json={'permission_name': 'testing_p'})
    created_permission = await extract_permission(response)
    assert response.status == HTTPStatus.OK
    assert created_permission.permission_name == 'testing_p'
    perm_uuid = created_permission.uuid

    # Assign created permission to created role
    response = await make_post_request(f'role/{role_uuid}/permissions',
                                       json={'permission_uuid': perm_uuid})
    assigned_permission = await extract_permission(response)
    assert response.status == HTTPStatus.OK
    assert assigned_permission.uuid == perm_uuid
    assert assigned_permission.permission_name == 'testing_p'

    # Get permissions for created role
    response = await make_get_request(f'role/{role_uuid}/permissions')
    permissions_list = await extract_permissions(response)
    assert response.status == HTTPStatus.OK
    assert len(permissions_list) == 1
    assert permissions_list[0].permission_name == 'testing_p'
    assert permissions_list[0].uuid == perm_uuid

    # Remove created permission from Role
    response = await make_delete_request(
        f'role/{role_uuid}/permissions/{perm_uuid}')
    removed_permission = await extract_permission(response)
    assert response.status == HTTPStatus.OK
    assert removed_permission.permission_name == 'testing_p'
    assert removed_permission.uuid == perm_uuid

    # Check removed permission is excluded from role
    response = await make_get_request(f'role/{role_uuid}/permissions')
    permissions_list = await extract_permissions(response)
    assert response.status == HTTPStatus.OK
    assert len(permissions_list) == 0

    # Remove created role
    response = await make_delete_request(f'role/{role_uuid}')
    removed_role = await extract_role(response)
    assert response.status == HTTPStatus.OK
    assert removed_role.role_name == 'testing_r'
    assert removed_role.uuid == role_uuid

    # Remove created permission
    response = await make_delete_request(f'permission/{perm_uuid}')
    perm = await extract_permission(response)
    assert response.status == HTTPStatus.OK
    assert perm.uuid == perm_uuid


@pytest.mark.asyncio
async def test_user_role_assigment(make_post_request, make_get_request,
                                   make_delete_request, pg_curs, redis_client):
    """Test full cycle of Role assigment to User: add, get, check, remove. """
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

    # Check cache for that user and permission is empty
    cache = await redis_client.get(f'{user_uuid}:{perm_uuid}')
    assert not cache

    # Check if created User don't have permission by uuid till it assigned
    response = await make_get_request(
        f'user/{user_uuid}/permissions/{perm_uuid}')
    perm_check = await extract_perm_check(response)
    assert response.status == HTTPStatus.OK
    assert not perm_check.is_permitted

    # Check cache for that user and permission is false
    cache = await redis_client.get(f'{user_uuid}:{perm_uuid}')
    assert cache == 'denied'

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

    # Get permissions list for created user
    response = await make_get_request(f'user/{user_uuid}/permissions')
    user_perms = await extract_permissions(response)
    assert response.status == HTTPStatus.OK
    assert len(user_perms) == 1
    assert user_perms[0].permission_name == 'testing_per'

    # Check if created User have permission by uuid
    response = await make_get_request(
        f'user/{user_uuid}/permissions/{perm_uuid}')
    perm_check = await extract_perm_check(response)
    assert response.status == HTTPStatus.OK
    assert perm_check.is_permitted

    # Check user permission is cached
    cache = await redis_client.get(f'{user_uuid}:{perm_uuid}')
    assert cache == 'accepted'

    # Remove assigned role from created user
    response = await make_delete_request(f'user/{user_uuid}/roles/{role_uuid}')
    removed_role = await extract_role(response)
    assert response.status == HTTPStatus.OK
    assert removed_role.role_name == 'testing_role'
    assert removed_role.uuid == role_uuid

    # Check if created User lost permission by uuid after role removing
    response = await make_get_request(
        f'user/{user_uuid}/permissions/{perm_uuid}')
    perm_check = await extract_perm_check(response)
    assert response.status == HTTPStatus.OK
    assert not perm_check.is_permitted

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
