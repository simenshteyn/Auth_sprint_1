import sys
from dataclasses import dataclass

from pydantic import ValidationError


@dataclass
class ServiceException(Exception):
    error_code: str
    message: str


# TODO: decide if it worth the effort
def make_service_exception(err: ValidationError):
    """ Transform and instance of pydantic.ValidationError
    into an instance of ServiceException"""
    first_error = err.errors().pop()
    error_field = first_error.get("loc")[0]
    error_reason = first_error.get("type").split(".")[-1]

    error_code = f"{error_field}_{error_reason}".upper()
    message = f"{error_field} is {error_reason}"

    return ServiceException(error_code, message)


def eprint(*args, **kwargs):
    """Print in server output"""
    print(*args, file=sys.stderr, **kwargs)
