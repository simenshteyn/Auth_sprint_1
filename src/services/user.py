import os

from db.pg import db
from models.auth_event import AuthEvent
from models.token import Token
from models.user import User

from werkzeug.security import generate_password_hash
from flask_jwt_extended import create_access_token

from utils import ServiceException
from db.redis_client import redis


def generate_tokens(user: User):
    """ Create new access and refresh tokens for the user"""
    user_data = {"user_id": user.user_id, }
    access_token = create_access_token(
        identity=user.user_id, additional_claims=user_data
    )
    refresh_token = create_access_token(
        identity=user.user_id, additional_claims=user_data
    )
    return access_token, refresh_token


class UserService:
    def create_user(self,
                    username: str,
                    password: str,
                    email: str,
                    user_info: dict):
        """ Check that a new user with these credentials can be added,
        if so, create the user and return its access and refresh tokens,
        otherwise, throw an exception telling what happened """

        existing_user: User = User.query.filter(
            (User.user_login == username) | (User.user_email == email)
        ).first()

        if existing_user:
            if existing_user.user_login == username:
                error_code = 'LOGIN_EXISTS'
                message = "this username is taken"
            else:
                error_code = 'EMAIL_EXISTS'
                message = "this email address is already used"
            raise ServiceException(error_code=error_code,
                                   message=message)

        password_hash = generate_password_hash(password)

        user = User(user_login=username,
                    user_password=password_hash,
                    user_email=email)
        db.session.add(user)
        db.session.commit()

        access_token, refresh_token = generate_tokens(user)
        self.commit_authentication(user,
                                   'signup',
                                   access_token,
                                   refresh_token,
                                   user_info)

        return access_token, refresh_token

    # TODO: see if this can be reused on login or disassemble it
    @staticmethod
    def commit_authentication(user: User,
                              event_type: str,
                              access_token: str,
                              refresh_token: str,
                              user_info: dict):
        """ Finalize successful authentication saving the details."""
        token = Token(token_owner_id=user.user_id, token_value=refresh_token)
        db.session.add(token)

        if event_type == 'login':
            auth_event = AuthEvent(auth_event_owner_id=user.user_id,
                                   auth_event_type=event_type,
                                   auth_event_fingerprint=str(user_info))
            db.session.add(auth_event)

        db.session.commit()
        redis.set(name=access_token,
                  value="",
                  ex=os.getenv('ACCESS_TOKEN_EXPIRATION'))
