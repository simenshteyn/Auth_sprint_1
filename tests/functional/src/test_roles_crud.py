import pytest
from http import HTTPStatus

from tests.functional.utils.extract import extract_roles, extract_role, \
    extract_permission, extract_permissions


@pytest.mark.asyncio
async def test_role_endpoint_crud(make_post_request, make_get_request,
                                  make_patch_request, make_delete_request):
    response = await make_post_request('role/',
                                       json={'role_name': 'test_role'})
    role = await extract_role(response)
    assert response.status == HTTPStatus.OK
    assert role.role_name == 'test_role'
    role_uuid = role.uuid

    response = await make_get_request('role/')
    roles = await extract_roles(response)
    assert response.status == HTTPStatus.OK
    assert len(roles) > 0

    response = await make_patch_request(f'role/{role_uuid}',
                                        json={'role_name': 'test_role_2'})
    role = await extract_role(response)
    assert response.status == HTTPStatus.OK
    assert role.role_name == 'test_role_2'

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
