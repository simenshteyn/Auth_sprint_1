import random
import string

import pytest
import requests
from psycopg2._psycopg import cursor, connection
from pydantic import BaseModel, constr
from redis import Redis
from requests import Response

from tests.functional.settings import config


def dictfetchall(cursor):
    """Return all rows from a cursor as a dict"""
    columns = [col[0] for col in cursor.description]
    return [
        dict(zip(columns, row))
        for row in cursor.fetchall()
    ]


def get_base_url(endpoint):
    return '{protocol}://{host}:{port}/api/v{api_version}/{endpoint}'.format(
        protocol=config.service_protocol,
        host=config.service_host,
        port=config.service_port,
        api_version=config.service_api_version,
        endpoint=endpoint
    )


def json_api_request(http_method, endpoint, json_data) -> Response:
    response = requests.request(http_method,
                                get_base_url(endpoint),
                                json=json_data)
    try:
        response.json()
        return response
    except ValueError:
        pytest.fail("Non-json response from the endpoint: "
                    + response.text)


class AuthTokenResponse(BaseModel):
    """Represents the structure of successful auth response,
    validates presence and correct formatting of fields"""
    access_token: constr(min_length=1)
    refresh_token: constr(min_length=1)


@pytest.fixture(scope='session')
def valid_user():
    pass


def create_user(user_data: dict, pg_curs: cursor) -> tuple[Response, dict]:
    """Helper routine for user creation
    to be reused by multiple tests.
    Returns the api response and
    the resulting user representation in the database"""
    response = json_api_request("post", "user/signup", user_data)
    response_json = response.json()
    if not response.status_code == 200:
        return response, {}
    try:
        AuthTokenResponse(**response_json)
    except ValueError as err:
        pytest.fail(err)
        return

    query = "select user_id,user_login,user_email " \
            "from app.users where user_login=%s"
    pg_curs.execute(query, (user_data['username'],))
    users = dictfetchall(pg_curs)

    assert len(users), "User not found in the database after adding"
    assert len(users) == 1, \
        "Not a single record found after adding a user"
    return response, users[0]


class TestUser:
    def test_create_user(self, pg_conn: connection,
                         pg_curs: cursor,
                         redis_conn: Redis):
        username = password = "".join(
            random.choices(string.ascii_lowercase, k=10))
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
            # response = json_api_request("post", "user/signup", partial_data)
            response, _ = create_user(partial_data, pg_curs)
            assert 400 <= response.status_code < 500, \
                f"Invalid response code when {missing_field} is missing"

            response_json = response.json()
            expected_error_code = f"{missing_field.upper()}_MISSING"
            assert response_json["error_code"] == expected_error_code, \
                f"Invalid error_code when {missing_field} is missing"

        #
        # Successful creation of a user
        #
        create_response, user = create_user(valid_data, pg_curs)
        assert create_response.status_code == 200, \
            f"Invalid response code when creating user, " \
            f"response text: {response.text}"
        assert user["user_login"] == valid_data["username"], \
            "Wrong username after adding a user"
        assert user["user_email"] == valid_data["email"], \
            "Wrong email after adding a user"

        #
        # access token is there
        #
        token_response = AuthTokenResponse(**create_response.json())
        saved_access_token = redis_conn.get(name=token_response.access_token)
        assert saved_access_token.decode() == "", "Access token not found"

        #
        # Inability to create duplicated users
        #
        # response = json_api_request("post", "user/signup", valid_data)
        # response.json()
        _, duplicated_user = create_user(valid_data, pg_curs)
        assert response.status_code == 400, \
            "Non-error response code when creating a duplicated user"

        # TODO: use teardown of figure out if its possible to use t
        #  ransactions
        query = "delete from app.users where user_id=%s"
        pg_curs.execute(query, (user['user_id'],))
        pg_conn.commit()

    def test_login_user(self, pg_conn: connection,
                        pg_curs: cursor,
                        redis_conn: Redis):

        username = password = "".join(
            random.choices(string.ascii_lowercase, k=10))
        email = username + "@yandex.com"

        valid_data = {
            "username": username, "password": password, "email": email
        }

        response, user = create_user(valid_data, pg_curs)

        del valid_data["email"]
        response = json_api_request("post", "user/auth", valid_data)

        try:
            token_response = AuthTokenResponse(**response.json())
        except ValueError as err:
            pytest.fail(err)
            return

        query = ("select token_id, token_owner_id, token_value "
                 "from app.tokens where token_owner_id=%s and token_value=%s"
                 "")
        pg_curs.execute(query,
                        (user["user_id"], token_response.refresh_token,))
        access_tokens = dictfetchall(pg_curs)
        assert len(access_tokens) == 1, \
            "None or multiple refresh tokens found " \
            f"for logged in user: {len(access_tokens)}"

        db_token = access_tokens[0]['token_value']
        expected = token_response.refresh_token
        assert db_token == expected, "Refresh token in the DB is incorrect"

        #
        # access token is there
        #
        saved_access_token = redis_conn.get(name=token_response.access_token)
        assert saved_access_token.decode() == "", "Access token not found"

        # Can't login with a wrong password
        wrong_data = {**valid_data, "password": "123456"}
        response = json_api_request("post", "user/auth", wrong_data)
        assert response.status_code == 400, \
            "No error when using wrong password"
        assert response.json()['error_code'] == 'WRONG_PASSWORD'

        # Can't login with a wrong username
        wrong_data = {**valid_data, "username": "123456"}
        response = json_api_request("post", "user/auth", wrong_data)
        assert response.status_code == 400, \
            "No error when using wrong password"
        assert response.json()['error_code'] == 'USER_NOT_FOUND'

        # TODO: use teardown of figure out if its possible to use t
        #  ransactions
        query = "delete from app.users where user_id=%s"
        pg_curs.execute(query, (user['user_id'],))
        pg_conn.commit()
