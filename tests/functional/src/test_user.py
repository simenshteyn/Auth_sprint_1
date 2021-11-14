import random
import string

import pytest
import requests
from psycopg2._psycopg import cursor, connection
from pydantic import BaseModel
from redis import Redis

from tests.functional.settings import config


def get_base_url(endpoint):
    return '{protocol}://{host}:{port}/api/v{api_version}/{endpoint}'.format(
        protocol=config.service_protocol,
        host=config.service_host,
        port=config.service_port,
        api_version=config.service_api_version,
        endpoint=endpoint
    )


def json_api_request(http_method, endpoint, json_data):
    response = requests.request(http_method,
                                get_base_url(endpoint),
                                json=json_data)

    try:
        response.json()
    except ValueError:
        pytest.fail("Non-json response from the endpoint")
        return

    return response


class CreateUserResponse(BaseModel):
    access_token: str
    refresh_token: str


def test_create_user(pg_conn: connection,
                     pg_curs: cursor,
                     redis_conn: Redis):
    username = password = "".join(random.choices(string.ascii_lowercase, k=10))
    email = username + "@yandex.com"

    valid_data = {
        "username": username, "password": password, "email": email
    }

    #
    # Field requirements satisfaction
    #
    for missing_field in ["username", "password", "email"]:
        partial_data = {k: valid_data[k]
                        for k in valid_data
                        if not k == missing_field}
        response = json_api_request("post", "user/signup", partial_data)
        response_json = response.json()
        expected_error_code = f"{missing_field.upper()}_MISSING"
        assert 400 <= response.status_code < 500, \
            f"Invalid response code when {missing_field} is missing"
        assert response_json["error_code"] == expected_error_code, \
            f"Invalid error_code when {missing_field} is missing"

    #
    # Successful creation of a user
    #
    response = json_api_request("post", "user/signup", valid_data)
    response_json = response.json()
    assert response.status_code == 200, \
        "Invalid response code when creating user"
    try:
        user_response = CreateUserResponse(**response_json)
    except ValueError as err:
        pytest.fail(err)
        return

    pg_curs: cursor
    query = "select user_id,user_login,user_email " \
            "from app.users where user_login=%s"
    pg_curs.execute(query, (valid_data['username'],))
    users = pg_curs.fetchall()
    assert len(users) == 1, \
        "Not a single record found after adding a user"
    user = users[0]
    assert user[1] == valid_data["username"], \
        "Wrong username after adding a user"
    assert user[2] == valid_data["email"], \
        "Wrong email after adding a user"

    #
    # access token is there
    #
    saved_access_token = redis_conn.get(name=user_response.access_token)
    assert saved_access_token.decode() == "", "Access token not found"

    #
    # Inability to create duplicated users
    #
    response = json_api_request("post", "user/signup", valid_data)
    response.json()
    assert response.status_code == 400, \
        "Non-error response code when creating a duplicated user"

    # TODO: use teardown of figure out if its possible to use transactions
    query = "delete from app.users where user_id=%s"
    pg_curs.execute(query, (user[0],))
    pg_conn.commit()
