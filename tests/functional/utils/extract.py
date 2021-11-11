from tests.functional.utils.models import Role, HTTPResponse


async def extract_roles(response: HTTPResponse) -> list[Role]:
    return [Role.parse_obj(role) for role in response.body]
