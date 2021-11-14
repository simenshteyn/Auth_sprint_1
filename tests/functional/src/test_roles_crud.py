import pytest
from http import HTTPStatus

from tests.functional.utils.extract import extract_roles, extract_role


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
