import pytest
from http import HTTPStatus

from tests.functional.utils.extract import extract_permission,\
    extract_permissions


@pytest.mark.asyncio
async def test_permission_endpoint_crud(make_post_request, make_get_request,
                                        make_patch_request,
                                        make_delete_request):
    """ Test CRUD cycle for Permission: create, read, update and delete."""
    response = await make_post_request('permission/',
                                       json={'permission_name': 'test_perm'})
    perm = await extract_permission(response)
    assert response.status == HTTPStatus.OK
    assert perm.permission_name == 'test_perm'
    perm_uuid = perm.uuid

    response = await make_get_request('permission/')
    perms = await extract_permissions(response)
    assert response.status == HTTPStatus.OK
    assert len(perms) > 0

    response = await make_patch_request(
        f'permission/{perm_uuid}',
        json={'permission_name': 'test_perm_2'}
    )
    perm = await extract_permission(response)
    assert response.status == HTTPStatus.OK
    assert perm.permission_name == 'test_perm_2'

    response = await make_delete_request(f'permission/{perm_uuid}')
    perm = await extract_permission(response)
    assert response.status == HTTPStatus.OK
    assert perm.permission_name == 'test_perm_2'
    assert perm.uuid == perm_uuid
