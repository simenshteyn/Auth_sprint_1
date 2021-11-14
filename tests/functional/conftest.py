import asyncio

import aiohttp
import psycopg2
import pytest
from psycopg2.extras import DictCursor
from redis import Redis

from tests.functional.settings import config
from tests.functional.utils.models import HTTPResponse

dsl = {'dbname': config.pg_dbname,
       'user': config.pg_user,
       'password': config.pg_pass,
       'host': config.pg_host,
       'port': config.pg_port}

redis_details = {
    'host': config.redis_host,
    'port': config.redis_port
}


@pytest.fixture(scope="session")
def event_loop(request):
    """Create an instance of the default event loop for each test case."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope='session')
def pg_conn():
    pg_conn = psycopg2.connect(**dsl, cursor_factory=DictCursor)
    yield pg_conn
    pg_conn.close()


@pytest.fixture
def pg_curs(pg_conn):
    pg_curs = pg_conn.cursor()
    yield pg_curs
    pg_curs.close()


@pytest.fixture(scope='session')
async def session():
    session = aiohttp.ClientSession()
    yield session
    await session.close()


@pytest.fixture(scope='session')
def make_get_request(session):
    async def inner(method: str, params: dict = None) -> HTTPResponse:
        params = params or {}
        url = '{protocol}://{host}:{port}/api/v{api_version}/{method}'.format(
            protocol=config.service_protocol,
            host=config.service_host,
            port=config.service_port,
            api_version=config.service_api_version,
            method=method
        )
        async with session.get(url, params=params) as response:
            return HTTPResponse(
                body=await response.json(),
                headers=response.headers,
                status=response.status,
            )

    return inner


@pytest.fixture
def redis_conn():
    r = Redis(redis_details['host'],
              redis_details['port']
              )
    yield r
    r.close()


@pytest.fixture(scope='session')
def make_post_request(session):
    async def inner(method: str, json: dict = None) -> HTTPResponse:
        json = json or {}
        url = '{protocol}://{host}:{port}/api/v{api_version}/{method}'.format(
            protocol=config.service_protocol,
            host=config.service_host,
            port=config.service_port,
            api_version=config.service_api_version,
            method=method
        )
        async with session.post(url, json=json) as response:
            return HTTPResponse(
                body=await response.json(),
                headers=response.headers,
                status=response.status,
            )

    return inner


@pytest.fixture(scope='session')
def make_patch_request(session):
    async def inner(method: str, json: dict = None) -> HTTPResponse:
        json = json or {}
        url = '{protocol}://{host}:{port}/api/v{api_version}/{method}'.format(
            protocol=config.service_protocol,
            host=config.service_host,
            port=config.service_port,
            api_version=config.service_api_version,
            method=method
        )
        async with session.patch(url, json=json) as response:
            return HTTPResponse(
                body=await response.json(),
                headers=response.headers,
                status=response.status,
            )

    return inner


@pytest.fixture(scope='session')
def make_delete_request(session):
    async def inner(method: str, params: dict = None) -> HTTPResponse:
        params = params or {}
        url = '{protocol}://{host}:{port}/api/v{api_version}/{method}'.format(
            protocol=config.service_protocol,
            host=config.service_host,
            port=config.service_port,
            api_version=config.service_api_version,
            method=method
        )
        async with session.delete(url, params=params) as response:
            return HTTPResponse(
                body=await response.json(),
                headers=response.headers,
                status=response.status,
            )

    return inner
