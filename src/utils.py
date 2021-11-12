import os
import sys
from dataclasses import dataclass

from pydantic import BaseModel
from redis import Redis

redis = Redis(host=os.getenv('REDIS_HOST'), port=os.getenv('REDIS_PORT'))


@dataclass
class ServiceException(Exception):
    error_code: str
    message: str


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)
