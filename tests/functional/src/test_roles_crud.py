import pytest
from http import HTTPStatus

from tests.functional.utils.extract import extract_roles


@pytest.mark.asyncio
async def test_get_list_of_all_roles(make_get_request):
    response = await make_get_request('role')
    roles = await extract_roles(response)
    assert response.status == HTTPStatus.OK
    assert len(roles) >= 0
