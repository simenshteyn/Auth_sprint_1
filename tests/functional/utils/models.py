from dataclasses import dataclass

from multidict import CIMultiDictProxy
from pydantic import BaseModel


@dataclass
class HTTPResponse:
    body: dict
    headers: CIMultiDictProxy[str]
    status: int


class Role(BaseModel):
    uuid: str
    role_name: str


class Permission(BaseModel):
    uuid: str
    permission_name: str
