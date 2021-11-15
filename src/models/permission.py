from dataclasses import dataclass

from sqlalchemy import DefaultClause, text
from sqlalchemy.dialects.postgresql import UUID

from db.pg import db


@dataclass
class Permission(db.Model):
    __tablename__ = 'permissions'

    __table_args__ = {'schema': 'app'}

    permission_id: str = db.Column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=DefaultClause(text("gen_random_uuid()"))
    )
    permission_name: str = db.Column(db.String, unique=True, nullable=False)
