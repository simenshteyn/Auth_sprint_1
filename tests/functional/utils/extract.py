from tests.functional.utils.models import Role, Permission, HTTPResponse, \
    UserTokens


async def extract_roles(response: HTTPResponse) -> list[Role]:
    return [Role.parse_obj(role) for role in response.body]


async def extract_role(response: HTTPResponse) -> Role:
    role = response.body
    return Role.parse_obj(role)


async def extract_permissions(response: HTTPResponse) -> list[Permission]:
    return [Permission.parse_obj(perm) for perm in response.body]


async def extract_permission(response: HTTPResponse) -> Permission:
    perm = response.body
    return Permission.parse_obj(perm)


async def extract_tokens(response: HTTPResponse) -> UserTokens:
    tokens = response.body
    return UserTokens.parse_obj(tokens)
