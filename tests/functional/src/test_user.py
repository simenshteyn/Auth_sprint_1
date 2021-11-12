import random
import string

import pytest
import requests
from pydantic import BaseModel

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
    response = requests.request(http_method, get_base_url(endpoint), json=json_data)

    try:
        response.json()
    except ValueError:
        pytest.fail("Non-json response from the endpoint")
        return

    return response


class CreateUserResponse(BaseModel):
    access_token: str
    refresh_token: str


def test_create_user(pg_conn):
    username = password = "".join(random.choices(string.ascii_lowercase, k=10))
    email = username + "@yandex.com"

    valid_data = {
        "username": username, "password": password, "email": email
    }

    # Test field requirements
    for missing_field in ["username", "password", "email"]:
        partial_data = {k: valid_data[k] for k in valid_data if not k == missing_field}
        response = json_api_request("post", "user/signup", partial_data)
        response_json = response.json()
        expected_error_code = f"{missing_field.upper()}_MISSING"
        assert 400 <= response.status_code < 500, f"Invalid response code when {missing_field} is missing"
        assert response_json["error_code"] == expected_error_code, f"Invalid error_code when {missing_field} is missing"

    # Test successful creation of a user
    response = json_api_request("post", "user/signup", valid_data)
    response_json = response.json()
    assert response.status_code == 200, "Invalid response code when creating user"
    try:
        CreateUserResponse(**response_json)
    except ValueError as err:
        pytest.fail(err)

    with pg_conn.cursor() as curs:
        curs.execute(f"select * from app.users where user_login='{valid_data['username']}'")
        for record in curs:
            print(record)
